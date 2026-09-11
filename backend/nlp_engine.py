import json
import logging
import os
import re
import threading
from pathlib import Path

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# DistilBERT converted to ONNX for phishing-email classification. ONNX keeps
# the local-model approach while avoiding the large PyTorch runtime.
DEFAULT_MODEL_URL = "https://huggingface.co/securecommerce/phishing-email-detection-onnx/resolve/main/model.onnx?download=true"
DEFAULT_TOKENIZER_URL = "https://huggingface.co/securecommerce/phishing-email-detection-onnx/resolve/main/tokenizer.json?download=true"
DEFAULT_CONFIG_URL = "https://huggingface.co/securecommerce/phishing-email-detection-onnx/resolve/main/config.json?download=true"
MODEL_DIR = Path(os.getenv("PHISHGUARD_MODEL_DIR", "/tmp/phishguard-model"))

_session = None
_tokenizer = None
_labels: dict[int, str] = {0: "LEGITIMATE", 1: "PHISHING"}
_load_error: str | None = None
_load_lock = threading.Lock()
_inference_lock = threading.Lock()


def clean_email_text(body: str) -> str:
    """Normalize HTML/MIME email content before statistical classification."""
    soup = BeautifulSoup(body, "html.parser")
    for node in soup(["style", "script", "noscript", "template", "head"]):
        node.decompose()
    for node in soup.find_all(True):
        node.attrs.pop("style", None)
    cleaned = soup.get_text(" ")
    cleaned = re.sub(r"(?m)^\s*--[-_A-Za-z0-9.=]+\s*$", " ", cleaned)
    cleaned = re.sub(r"(?mi)^(?:content-(?:type|transfer-encoding|disposition)|mime-version):.*$", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:50_000]


def _download_file(url: str, destination: Path) -> None:
    import requests

    temporary = destination.with_suffix(destination.suffix + ".part")
    with requests.get(url, stream=True, timeout=(15, 180)) as response:
        response.raise_for_status()
        with temporary.open("wb") as output:
            for chunk in response.iter_content(chunk_size=1024 * 1024):
                if chunk:
                    output.write(chunk)
    temporary.replace(destination)


def _ensure_asset(url: str, destination: Path) -> Path:
    if destination.exists() and destination.stat().st_size > 0:
        return destination
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    _download_file(url, destination)
    return destination


def _load_classifier():
    global _session, _tokenizer, _labels, _load_error
    if _session is not None or _load_error is not None:
        return _session
    with _load_lock:
        if _session is not None or _load_error is not None:
            return _session
        try:
            import onnxruntime as ort
            from tokenizers import Tokenizer

            model_url = os.getenv("PHISHGUARD_ONNX_MODEL_URL", DEFAULT_MODEL_URL)
            tokenizer_url = os.getenv("PHISHGUARD_ONNX_TOKENIZER_URL", DEFAULT_TOKENIZER_URL)
            config_url = os.getenv("PHISHGUARD_ONNX_CONFIG_URL", DEFAULT_CONFIG_URL)
            model_path = _ensure_asset(model_url, MODEL_DIR / "model.onnx")
            tokenizer_path = _ensure_asset(tokenizer_url, MODEL_DIR / "tokenizer.json")
            config_path = _ensure_asset(config_url, MODEL_DIR / "config.json")

            config = json.loads(config_path.read_text(encoding="utf-8"))
            configured_labels = config.get("id2label", {})
            if configured_labels:
                _labels = {int(index): str(label) for index, label in configured_labels.items()}
            _tokenizer = Tokenizer.from_file(str(tokenizer_path))
            _tokenizer.enable_truncation(max_length=256)
            _tokenizer.enable_padding(length=256)
            options = ort.SessionOptions()
            options.intra_op_num_threads = max(1, int(os.getenv("PHISHGUARD_ORT_THREADS", "1")))
            options.inter_op_num_threads = 1
            options.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_BASIC
            _session = ort.InferenceSession(str(model_path), sess_options=options, providers=["CPUExecutionProvider"])
        except Exception as exc:
            _load_error = f"{type(exc).__name__}: {exc}"
            logger.exception("Could not load ONNX phishing classifier")
    return _session


def _is_phishing_label(label: str) -> bool:
    normalized = label.lower()
    return any(word in normalized for word in ("phish", "spam", "malicious", "label_1")) and not any(
        word in normalized for word in ("not_phish", "non-phish", "ham", "legitimate")
    )


def phishing_probability(text: str) -> tuple[int | None, str | None]:
    """Return a local ONNX phishing probability without concurrent inference."""
    enabled = os.getenv("PHISHGUARD_ENABLE_NLP", "1").strip().lower() in {"1", "true", "yes", "on"}
    if not enabled:
        return None, "Local classifier disabled; deterministic checks are active"
    session = _load_classifier()
    if session is None or _tokenizer is None:
        return None, _load_error or "Classifier is unavailable"
    try:
        import numpy as np

        with _inference_lock:
            encoded = _tokenizer.encode(clean_email_text(text)[:12_000])
            input_metas = {input_meta.name: input_meta for input_meta in session.get_inputs()}
            input_ids = np.asarray([encoded.ids], dtype=np.int64)
            attention = np.asarray([encoded.attention_mask], dtype=np.int64)
            model_inputs = {}
            for name in input_metas:
                lowered = name.lower()
                if "input_ids" in lowered:
                    model_inputs[name] = input_ids
                elif "attention_mask" in lowered:
                    model_inputs[name] = attention
                elif "token_type" in lowered or "segment" in lowered:
                    model_inputs[name] = np.zeros_like(input_ids)
            outputs = session.run(None, model_inputs)
            logits = np.asarray(outputs[0], dtype=np.float32)[0]
            logits -= np.max(logits)
            probabilities = np.exp(logits) / np.sum(np.exp(logits))
            phishing_indexes = [index for index, label in _labels.items() if index < len(probabilities) and _is_phishing_label(label)]
            if not phishing_indexes and len(probabilities) > 1:
                phishing_indexes = [1]
            return round(float(np.sum(probabilities[phishing_indexes])) * 100), None
    except Exception as exc:
        logger.exception("ONNX classifier inference failed")
        return None, f"{type(exc).__name__}: {exc}"

import logging
import os
import re
import threading

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Compact phishing-trained model suitable for small cloud instances. The
# previous full-size BERT checkpoint could exceed Render Free's memory limit
# once PyTorch, tokenization, and FastAPI were resident in the same process.
DEFAULT_MODEL = "lleratodev/720-bert-mini-phishing-fine-tune"
_classifier = None
_load_error: str | None = None
_lock = threading.Lock()


def clean_email_text(body: str) -> str:
    """Normalize HTML/MIME email content before statistical classification."""
    # CSS and script blocks can contain arbitrary token soup that resembles URLs.
    soup = BeautifulSoup(body, "html.parser")
    for node in soup(["style", "script", "noscript", "template", "head"]):
        node.decompose()
    # Remove style attributes before get_text() so inline CSS is never classified.
    for node in soup.find_all(True):
        node.attrs.pop("style", None)
    cleaned = soup.get_text(" ")
    # Remove multipart delimiters and MIME metadata/header lines while preserving message copy.
    cleaned = re.sub(r"(?m)^\s*--[-_A-Za-z0-9.=]+\s*$", " ", cleaned)
    cleaned = re.sub(r"(?mi)^(?:content-(?:type|transfer-encoding|disposition)|mime-version):.*$", " ", cleaned)
    cleaned = re.sub(r"\s+", " ", cleaned).strip()
    return cleaned[:50_000]


def _load_classifier():
    global _classifier, _load_error
    if _classifier is not None or _load_error is not None:
        return _classifier
    with _lock:
        if _classifier is not None or _load_error is not None:
            return _classifier
        try:
            # Keep the single-worker API predictable on constrained instances.
            # These settings are applied before the first inference thread is
            # created and can be overridden for larger deployments.
            import torch

            torch.set_num_threads(max(1, int(os.getenv("PHISHGUARD_TORCH_THREADS", "1"))))
            torch.set_num_interop_threads(1)
            from transformers import pipeline

            model_name = os.getenv("PHISHGUARD_MODEL", DEFAULT_MODEL)
            _classifier = pipeline(
                "text-classification",
                model=model_name,
                tokenizer=model_name,
                device=-1,
                truncation=True,
                top_k=None,
            )
        except Exception as exc:  # model/network failures must not take down the API
            _load_error = f"{type(exc).__name__}: {exc}"
            logger.exception("Could not load phishing classifier")
    return _classifier


def _is_phishing_label(label: str) -> bool:
    normalized = label.lower()
    return any(word in normalized for word in ("phish", "spam", "malicious", "label_1")) and not any(
        word in normalized for word in ("not_phish", "non-phish", "ham", "legitimate")
    )


def phishing_probability(text: str) -> tuple[int | None, str | None]:
    """Return (probability, error). A missing model yields None, never a fake score."""
    classifier = _load_classifier()
    if classifier is None:
        return None, _load_error or "Classifier is unavailable"
    try:
        output = classifier(clean_email_text(text)[:12_000])
        predictions = output[0] if output and isinstance(output[0], list) else output
        phishing_scores = [float(item["score"]) for item in predictions if _is_phishing_label(str(item["label"]))]
        if phishing_scores:
            return round(max(phishing_scores) * 100), None
        # For a two-class classifier with an explicit safe/legitimate winner.
        if len(predictions) == 1:
            item = predictions[0]
            label = str(item["label"]).lower()
            if any(word in label for word in ("safe", "legitimate", "ham", "label_0")):
                return round((1 - float(item["score"])) * 100), None
        logger.warning("Model labels were not recognized: %s", predictions)
        return None, "The configured model uses unrecognized class labels"
    except Exception as exc:
        logger.exception("Classifier inference failed")
        return None, f"{type(exc).__name__}: {exc}"

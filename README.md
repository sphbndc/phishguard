# PhishGuard

PhishGuard is a local-first email phishing analyzer. It combines a Hugging Face
text classifier with transparent security heuristics, email-authentication header
analysis, and safe URL unshortening. No paid API or hosted AI service is used.

## Prerequisites

- Python 3.10+
- Node.js 20+
- Internet access on first backend run to download the configured open-source
  model into the local Hugging Face cache and to query public DNS/redirects

## Run the backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\Scripts\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The local NLP signal uses a compact ONNX phishing-email model and runs one
inference at a time. Set `PHISHGUARD_ENABLE_NLP=0` to disable it if a host is
especially constrained; deterministic authentication, sender, language, and
URL checks remain active. The model and tokenizer are cached under
`PHISHGUARD_MODEL_DIR` (default `/tmp/phishguard-model`) and can be overridden
with `PHISHGUARD_ONNX_MODEL_URL`, `PHISHGUARD_ONNX_TOKENIZER_URL`, and
`PHISHGUARD_ONNX_CONFIG_URL`. Set `PHISHGUARD_ORT_THREADS` to tune CPU usage.

## Run the frontend locally

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. This is the local development version; it does not
replace the deployed site. The landing page is available at `/`, the scanner at
`/scanner`, and the standards and security knowledge base at `/tips`. Locally, the frontend uses
`http://localhost:8000` for the API by default; override it with
`NEXT_PUBLIC_API_URL` in `frontend/.env.local` when testing another backend.

The live frontend is available at:
https://phishguard-drab-five.vercel.app

## API endpoints

- `GET /` — service status and API documentation link
- `GET /api/health` — hosting-platform health check
- `POST /api/analyze` — analyze sender, email body, and optional raw headers
- `GET /docs` — interactive OpenAPI documentation

The scanner also supports light/dark themes, raw-header extraction guidance,
formatted clipboard reports, and branded PDF report downloads.

## Deploy with GitHub and Vercel

Live frontend: [https://phishguard-drab-five.vercel.app](https://phishguard-drab-five.vercel.app)

The Next.js client can be deployed directly from the public GitHub repository:

1. Sign in at [vercel.com](https://vercel.com) with GitHub and choose
   `sphbndc/phishguard`.
2. Set **Root Directory** to `frontend` (keep the detected Next.js preset).
3. Add `NEXT_PUBLIC_API_URL` as an environment variable containing the public
   URL of your running FastAPI backend, then deploy.

The FastAPI service should run separately on a Python host (for example,
Render's free tier) because the local PyTorch/Hugging Face model is not a good
fit for Vercel's short-lived serverless functions. Start it with:

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port $PORT
```

After deployment, add the backend's HTTPS URL to Vercel as
`NEXT_PUBLIC_API_URL` and redeploy the frontend. Configure the backend's
`PHISHGUARD_FRONTEND_ORIGIN` environment variable with the Vercel domain
`https://phishguard-drab-five.vercel.app` before production use. Multiple
comma-separated origins are supported for preview and production deployments.

## Important limitations

PhishGuard is a decision-support tool, not a guarantee that an email is safe.
SPF, DKIM, and DMARC are evaluated primarily from `Authentication-Results` and
related trace headers. Cryptographic DKIM verification is attempted only when
the supplied raw headers contain a DKIM signature and can be combined with the
body into a complete message. Do not click or reply to a suspicious message
solely because a scan reports a low score.

Email HTML and MIME wrappers are normalized with BeautifulSoup before heuristic
and local-model analysis. When all three authentication mechanisms explicitly
pass and align with the visible sender domain, the API applies a hard maximum
risk score of 12 (Safe).

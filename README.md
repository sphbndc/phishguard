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

The model is loaded lazily on the first scan. Set `PHISHGUARD_MODEL` to another
locally available Hugging Face sequence-classification model if desired. Set
`TRANSFORMERS_OFFLINE=1` to enforce cache-only operation.

## Run the frontend

```bash
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. The scanner is available at `/` and `/scanner`; the
standards and security knowledge base is at `/tips`. The frontend uses
`http://localhost:8000` by default;
override it with `NEXT_PUBLIC_API_URL` in `frontend/.env.local`.

## Important limitations

PhishGuard is a decision-support tool, not a guarantee that an email is safe.
SPF, DKIM, and DMARC are evaluated primarily from `Authentication-Results` and
related trace headers. Cryptographic DKIM verification is attempted only when
the supplied raw headers contain a DKIM signature and can be combined with the
body into a complete message. Do not click or reply to a suspicious message
solely because a scan reports a low score.

Email HTML is normalized with BeautifulSoup before heuristic and local-model
analysis. When all three authentication mechanisms explicitly pass and align
with the visible sender domain, the API applies a hard maximum risk score of 15.

# PhishGuard

PhishGuard is a free, open-source email security scanner. It checks sender identity, SPF/DKIM/DMARC authentication, message language, HTML content, and link destinations. Analysis runs locally on the deployed backend using deterministic security rules and an optional ONNX model; no paid AI API is required.

## Use the hosted app

Open the live scanner at **https://phishguard-drab-five.vercel.app**.

1. Enter the sender address.
2. Paste the email body as plain text or rich text.
3. Add raw headers when available for stronger authentication checks.
4. Select **Scan email for threat**.

Results include a risk score, explainable evidence, unshortened links, educational guidance, clipboard export, and a branded PDF download. Treat every result as advisory and verify high-impact requests independently.

## Run locally

### Requirements

- Python 3.10 or newer
- Node.js 20 or newer
- Internet access for the first model download and public DNS/link checks

### Backend

```bash
cd backend
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

The API is available at `http://localhost:8000`. Interactive API documentation is at `/docs`.

The ONNX classifier is enabled by default and performs one bounded inference at a time to protect memory. Set `PHISHGUARD_ENABLE_NLP=0` to run deterministic checks only. Model files are cached in `/tmp/phishguard-model` (or `PHISHGUARD_MODEL_DIR`). Advanced deployments can override the model URLs with `PHISHGUARD_ONNX_MODEL_URL`, `PHISHGUARD_ONNX_TOKENIZER_URL`, and `PHISHGUARD_ONNX_CONFIG_URL`.

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:3000`. The landing page is `/`, the scanner is `/scanner`, and the security standards guide is `/tips`.

To use a different API, create `frontend/.env.local`:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## API

- `GET /` - service status
- `GET /api/health` - health check
- `POST /api/analyze` - analyze `{ "sender": "...", "body": "...", "header": "..." }`
- `GET /docs` - OpenAPI documentation

## Deploy your own instance

The Next.js frontend can be deployed to Vercel with the project root set to `frontend`. Set `NEXT_PUBLIC_API_URL` to the public HTTPS URL of a separately hosted FastAPI backend. Deploy the backend on a Python host such as Render with:

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port $PORT
```

Configure the backend CORS variable `PHISHGUARD_FRONTEND_ORIGIN` with your Vercel domain. Keep both services on HTTPS in production.

## Security and privacy

- HTML, CSS, scripts, and MIME wrappers are cleaned before analysis.
- Link checks block private/reserved destinations and limit redirects.
- SPF, DKIM, and DMARC pass results are only trusted when domains align; critical malicious links remain decisive.
- Scan content is not stored by the application.
- A low score is not a guarantee of safety. Never disclose passwords, one-time codes, or payment details by email.

## License

This project is released under the MIT License. See [LICENSE](LICENSE) for details.

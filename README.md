# ScamSathi

ScamSathi is a full-stack scam-awareness and triage app for suspicious messages, URLs, and screenshots. It combines transparent heuristic checks with an optional locally trained text classifier. Risk scores are advisory, not proof that content is malicious or safe.

## Project layout

- `frontend/` — React + TypeScript + Vite UI, API client, Recharts analytics.
- `backend/` — FastAPI REST API, SQLite/SQLAlchemy persistence, analysis services, OCR and tests.
- `backend/ml/` — small development fixture and reproducible scikit-learn training script.
- `.env.example` — placeholder configuration only; never commit real secrets.
- `docker-compose.yml` — local container orchestration.

## Run locally on macOS

Prerequisites: Python 3.11+, Node.js 20+, npm. For OCR, install Tesseract separately (`brew install tesseract tesseract-lang` where available); manual text input remains a fallback.

### 1. Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m ml.train
uvicorn app.main:app --reload --port 8000
```

API docs: `http://localhost:8000/docs`; health: `http://localhost:8000/health`.

### 2. Frontend (new terminal)

```bash
cd frontend
npm install
npm run dev
```

Open `http://localhost:5173`. By default the UI connects to `http://localhost:8000/api/v1`. To change it, set `VITE_API_BASE_URL` before building.

### Local AI cyber safety assistant (optional)

The Assistant page uses Ollama on the same machine; ScamSathi does not call a paid AI API and does not download a model automatically. Install Ollama, then run:

```bash
ollama serve
ollama pull qwen2.5:3b
```

Keep the Ollama service running and start/restart the FastAPI backend. ScamSathi checks `http://127.0.0.1:11434/api/tags` and reports the configured runtime/model status. The model is configurable through `OLLAMA_BASE_URL`, `OLLAMA_MODEL`, and `OLLAMA_TIMEOUT_SECONDS` in the root `.env` (see `.env.example`). If Ollama or the model is absent, the page says so and does not return a scripted chatbot answer; scanner tools and the curated official reporting directory remain available. Reply quality and language coverage depend on the chosen model and have not been independently validated.

Conversation history is stored in the existing SQLite database with phone numbers, Aadhaar-like IDs, PANs, short numeric codes, and other recognized values redacted. Avoid sending secrets or personal data. The app has no user authentication and is intended for local development.

### 3. Tests and build

```bash
# backend terminal, from backend/ with venv activated
pytest -q

# frontend terminal, from frontend/
npm test
npm run build
```

## Training data

`backend/ml/dataset_fixture.csv` is a tiny synthetic development fixture only. To train on your own CSV with `text,label` columns:

```bash
cd backend
python -m ml.train --data /path/to/your_labeled_dataset.csv
```

Inspect dataset license, source, duplicates, label balance, and representativeness before using real data. The generated metrics are not a guarantee of real-world accuracy. The current training script uses a stratified train/test split and a simple majority baseline; it does not establish production readiness.

## Privacy and security notes

- Raw message retention is off by default; a SHA-256 digest and redacted preview are stored.
- The settings page can enable raw retention. The root `.env` is loaded by the backend; copy `.env.example` to `.env` if you need custom settings. This local demo has no user authentication, so do not expose it to the public internet or use it for multi-user data.
- URL analysis does not fetch the submitted URL. Local/private destinations are rejected.
- Screenshot upload validates PNG/JPEG/WEBP signatures and size. Images are handled in memory; OCR requires Tesseract, or users can paste extracted text manually.
- Google Safe Browsing v4 is optional. When `SAFE_BROWSING_API_KEY` is configured, URL scans query the provider; provider errors fall back to local heuristics. A clean/unknown response is not a safety guarantee.
- Retention days are saved as a setting; automated deletion of aged records is not yet implemented.
- Add authentication/authorization, rate limiting, CSRF/session protections as applicable, monitoring, production database migrations, stronger URL/DNS threat checks, provider integration and a reviewed labeled corpus before public deployment.

## Docker

```bash
docker compose up --build
```

Frontend: `http://localhost:8080`; backend docs: `http://localhost:8000/docs`.

## Known limitations

This repository is a functional development baseline, not a security certification or production guarantee. Do not treat a low score as a guarantee of safety. Verify suspicious messages with banks or official authorities independently. If money was lost to cyber fraud in India, call 1930 promptly and report at `https://cybercrime.gov.in/`.

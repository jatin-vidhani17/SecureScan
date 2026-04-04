# SecureScan

SecureScan is a beginner-friendly web application vulnerability scanner.

This starter version includes:
- React + Tailwind frontend
- Flask backend
- Secure URL validation with SSRF protections
- Basic security header checks and severity reporting

## Important Legal Note
Scan only systems that you own or have explicit written permission to test.

## Project Structure

- `frontend/` React + Tailwind UI
- `backend/` Flask API and scanner logic

## Local Setup

### 1. Backend

```bash
cd backend
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
copy .env.example .env
python app.py
```

Backend runs on `http://localhost:5000`.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend runs on `http://localhost:5173`.

## API Endpoint

### POST `/api/scan`
Request body:

```json
{
  "url": "https://example.com"
}
```

Returns:
- scan metadata
- HTTP status code
- findings list
- severity summary

## Security Controls Implemented

- Blocks localhost and private/internal IP ranges
- Restricts protocols to HTTP/HTTPS
- Rejects URL credentials
- Adds request timeout and redirect limit
- Rate limits scan endpoint
- Adds secure response headers on API responses

## Next Steps

- Add crawler depth control and page discovery
- Add cookie and TLS checks
- Persist scan history in SQLite
- Add GitHub Actions for `npm audit`, `pip-audit`, and `bandit`

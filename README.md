# SecureScan — OWASP Top 10 Web Vulnerability Scanner

SecureScan is an automated web application vulnerability scanner mapping directly to the **OWASP Top 10** guidelines. It features a modern, responsive security dashboard that visualises target vulnerability states, identifies the system's tech stack, and outputs framework-specific remediation code.

---

## Key Features

1. **Tech Stack Fingerprinting**: Passively identifies backend and frontend frameworks (e.g., Laravel, Django, Flask, Express, PHP, React, WordPress) using header patterns, cookies, and DOM markers.
2. **Framework-Aware Remediation**: Dynamically generates tailored vulnerability explanations, bulleted remediation steps, and copy-pasteable code patches customized to the target's specific stack (e.g., PDO bindings for PHP, ORM methods for Django, Helmet middleware for Express).
3. **OWASP Top 10 Mapping**: Performs 10 distinct automated test checks covering broken access control, cryptographic failures, injection flaws, supply chain risks, insecure designs, and exception handling.
4. **Asynchronous Multi-threaded Scanning**: Runs crawler and detectors in a background thread to prevent UI freezing. Results are polled by the React dashboard in real-time.
5. **Interactive Dashboard**: Premium dark-mode interface built with React, Tailwind CSS, and Recharts (featuring radar charts, donut graphs, live log terminal, and an interactive code-viewer with a click-to-copy utility).

---

## Project Folder Structure

```text
SecureScan/
├── frontend/                   # React.js SPA Dashboard
│   ├── src/
│   │   ├── App.jsx             # Main dashboard shell & polling logic
│   │   ├── api.js              # Axios backend REST API methods
│   │   └── components/
│   │       ├── OWASPTable.jsx  # Interactive OWASP table with Copy-Code utility
│   │       ├── Charts.jsx      # Radar, Donut, and Pass/Fail visual charts
│   │       └── ...
│   └── package.json
└── backend/                    # Flask REST API Server
    ├── app.py                  # API routes controller
    ├── database.py             # SQLite helper methods & schema setup
    ├── crawler/
    │   └── crawler.py          # BFS web crawler module
    ├── core/
    │   ├── engine.py           # Master scan thread pipeline orchestrator
    │   ├── owasp_tests.py      # 10 OWASP Top 10 test functions
    │   ├── recommendations.py  # Framework-specific reasons/tips registry
    │   └── scoring.py          # Scoring and grading logic (0-100 / A-F)
    ├── detectors/
    │   ├── sqli.py             # Active SQL injection testing
    │   ├── xss.py              # Active reflected XSS testing
    │   └── sensitive_data.py   # RegEx-based secret key scanning
    └── requirements.txt
```

---

## Local Installation

### 1. Backend API (Flask)
```bash
cd backend
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt
copy .env.example .env
python app.py
```
*API runs on `http://localhost:5000`*

### 2. Frontend Dashboard (React + Vite)
```bash
cd frontend
npm install
npm run dev
```
*Dashboard runs on `http://localhost:5173`*

---

## Key API Endpoint Payload Examples

### GET `/api/scan/results?url=http://example.com`
Returns full structured results including score, grade, tech stack, and enriched OWASP outcomes:
```json
{
  "target": "http://example.com",
  "score": 85,
  "grade": "B",
  "tech_stack": "laravel",
  "owasp_results": [
    {
      "owasp_id": "A05",
      "owasp_name": "Injection",
      "status": "fail",
      "severity": "High",
      "description": "SQL Injection vulnerability discovered.",
      "recommendation": "Use parameterized queries/ORMs.",
      "reason": "Using raw query statements like whereRaw() with string interpolation...",
      "tips": [
        "Always use standard Eloquent query builder methods which bind parameters automatically.",
        "Make sure all variables inside Blade templates use {{ $variable }} to auto-escape HTML."
      ],
      "code_snippet": "// Safe SQL Eloquent query:\n$user = User::where('name', $request->name)->get();",
      "findings": [...]
    }
  ]
}
```

---

## Legal Disclaimer
This software is intended strictly for educational purposes and authorized security auditing. **Do not scan target systems without explicit written consent.**

---

*Assisted and developed in collaboration with Antigravity, an AI coding assistant designed by Google DeepMind.*


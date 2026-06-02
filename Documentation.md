# SecureScan — Web Application Vulnerability Scanner

## IGNOU MCA Project Documentation

**Project Title:** SecureScan — An Automated Web Application Vulnerability Scanner Based on OWASP Top 10  
**Student Name:** Jatin Vidhani  
**Programme:** M.S.c IS (Master in Science of Information Security)  
**University:** Indira Gandhi National Open University (IGNOU)

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Objectives](#2-objectives)
3. [Literature Review](#3-literature-review)
4. [Methodology](#4-methodology)
5. [System Architecture](#5-system-architecture)
6. [Implementation](#6-implementation)
7. [OWASP Top 10 — Test Implementation Details](#7-owasp-top-10--test-implementation-details)
8. [Case Study](#8-case-study)
9. [Observations and Analysis](#9-observations-and-analysis)
10. [Conclusion](#10-conclusion)
11. [Future Scope](#11-future-scope)
12. [Bibliography](#12-bibliography)
13. [Appendices](#13-appendices)
14. [Glossary](#14-glossary)

---

## 1. Introduction

### 1.1 Background

Web applications are the backbone of modern digital infrastructure, serving everything from e-commerce platforms to government portals. With this ubiquity comes an ever-growing attack surface. According to the OWASP Foundation, web application vulnerabilities remain the most exploited attack vector, with injection flaws, broken access control, and security misconfigurations leading the list of critical risks.

Traditional vulnerability assessment often requires expensive commercial tools or deep manual expertise. Small businesses, educational institutions, and independent developers frequently lack access to these resources, leaving their applications exposed to known attack patterns.

### 1.2 Problem Statement

Despite the availability of security standards like the OWASP Top 10, many web applications continue to ship with preventable vulnerabilities. There exists a gap between awareness of security best practices and the practical tools available for automated assessment. This project addresses that gap by building an accessible, open-source vulnerability scanner that maps directly to the OWASP Top 10 framework.

### 1.3 About SecureScan

**SecureScan** is a full-stack web application vulnerability scanner developed as an academic project. It combines:

- A **Python/Flask backend** that performs automated crawling and vulnerability detection
- A **React.js frontend** that provides a modern cybersecurity dashboard for visualising results
- An **SQLite database** for persistent storage of scan results and logs
- A **scoring engine** that rates target websites on a 0–100 scale with A–F letter grades

The scanner evaluates websites against all 10 categories of the OWASP Top 10 (2025), providing actionable recommendations for each identified vulnerability.

### 1.4 Scope

SecureScan is designed for educational and authorised security testing purposes. It performs:

- Automated web crawling (breadth-first, configurable depth)
- 10 distinct OWASP-mapped security tests
- Error-based SQL injection detection
- Reflected cross-site scripting (XSS) detection
- Sensitive data exposure scanning
- Security header analysis
- Authentication weakness checks
- Supply chain and integrity verification

The tool is **not** intended for unauthorized testing and includes safeguards against scanning private networks.

---

## 2. Objectives

The primary objectives of this project are:

1. **Design and implement** a modular web vulnerability scanner that maps to the OWASP Top 10 security framework
2. **Automate** the detection of common web vulnerabilities including SQL Injection, XSS, security misconfigurations, and sensitive data exposure
3. **Develop a scoring system** that quantifies the security posture of a target website on a 0–100 scale with corresponding letter grades (A–F)
4. **Build an interactive dashboard** using React.js that visualises scan results through charts, tables, and detailed finding cards
5. **Generate exportable reports** (JSON/Text) containing structured vulnerability data, OWASP categorisation, and remediation recommendations
6. **Demonstrate practical application** of cybersecurity concepts through a real-world case study using an intentionally vulnerable web application

---

## 3. Literature Review

### 3.1 OWASP Top 10

The Open Web Application Security Project (OWASP) is a nonprofit foundation dedicated to improving software security. Their flagship document, the OWASP Top 10, is the most widely recognised standard for web application security awareness. The 2025 edition identifies these critical risk categories:

| ID  | Category | Description |
|-----|----------|-------------|
| A01 | Broken Access Control | Failures in enforcing user permissions and access restrictions |
| A02 | Security Misconfiguration | Missing security headers, default credentials, verbose errors |
| A03 | Software Supply Chain Failures | Use of outdated or vulnerable third-party components |
| A04 | Cryptographic Failures | Absence of encryption, exposed sensitive data |
| A05 | Injection | SQL injection, XSS, command injection via unsanitised input |
| A06 | Insecure Design | Architectural flaws, verbose error pages, missing threat modelling |
| A07 | Authentication Failures | Weak authentication mechanisms, missing CSRF protection |
| A08 | Software & Data Integrity Failures | Missing integrity checks on external resources (SRI) |
| A09 | Security Logging & Alerting Failures | Insufficient logging, missing correlation headers |
| A10 | Mishandling of Exceptional Conditions | Unhandled errors, exposed stack traces |

### 3.2 Existing Vulnerability Scanners

Several commercial and open-source tools exist in this space:

- **OWASP ZAP (Zed Attack Proxy):** A comprehensive open-source scanner with active and passive scanning modes. Complex to configure for beginners.
- **Burp Suite:** Industry-standard commercial tool for web security testing. Requires a paid license for full features.
- **Nikto:** A command-line web server scanner focused on server misconfigurations. No GUI interface.
- **Acunetix:** Enterprise-grade automated scanner. Expensive licensing model.

SecureScan differentiates itself by providing a **lightweight, educational tool** with a modern web-based dashboard that makes vulnerability scanning accessible to students and small-scale developers.

### 3.3 Technologies Used

| Layer | Technology | Purpose |
|-------|-----------|---------|
| Backend | Python 3.12 | Core scanning logic |
| Web Framework | Flask 3.0 | REST API server |
| Frontend | React 18 | Dashboard UI |
| Styling | Tailwind CSS 3.4 | Responsive design |
| Charts | Recharts | Data visualization |
| Database | SQLite | Persistent storage |
| HTTP Client | Requests | Web crawling & testing |
| HTML Parsing | BeautifulSoup 4 | DOM analysis |

---

## 4. Methodology

### 4.1 Development Approach

SecureScan follows an **incremental development methodology**:

1. **Phase 1 — Core Engine:** Built the web crawler and basic vulnerability detectors
2. **Phase 2 — Database & API:** Added SQLite persistence and Flask REST endpoints
3. **Phase 3 — Frontend Dashboard:** Developed the React.js visualisation layer
4. **Phase 4 — OWASP Integration:** Mapped all detections to OWASP Top 10 categories
5. **Phase 5 — Scoring & Reporting:** Implemented the scoring engine and export features

### 4.2 Scanning Methodology

SecureScan's scanning pipeline follows a five-stage process:

```
┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
│ TECH STACK   │───▶│   CRAWLING   │───▶│   FETCHING   │───▶│   TESTING    │───▶│   SCORING    │
│ DETECTION    │    │              │    │              │    │              │    │              │
│ Headers +    │    │ BFS spider   │    │ HTTP GET all │    │ 10 OWASP     │    │ 0-100 score  │
│ HTML markers │    │ Discover     │    │ discovered   │    │ security     │    │ A-F grade    │
│              │    │ all pages    │    │ URLs + store │    │ tests        │    │ Pass/Fail    │
└──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘    └──────────────┘
```

**Stage 0 — Tech Stack Detection:** The scanner fingerprints the target using HTTP headers, cookies, and HTML markers (e.g., WordPress, Django, Spring Boot, React). The detected stack is stored with the scan and used to tune framework-specific detectors.

**Stage 1 — Crawling:** A breadth-first spider discovers all reachable pages within the target domain up to a configurable depth (default: 2). Only pages with `text/html` content type are followed.

**Stage 2 — Fetching:** All discovered URLs are fetched concurrently (5 threads) and their full HTTP responses (headers + body) are stored in memory for analysis.

**Stage 3 — Testing:** Each of the 10 OWASP tests is executed against the collected response data. Tests that require active probing (e.g., SQL injection) make additional HTTP requests with crafted payloads.

**Stage 4 — Scoring:** Results from all 10 tests are fed into the scoring engine, which calculates a weighted score based on test pass/fail status and severity levels.

### 4.3 Scoring Algorithm

Each OWASP test is worth **10 points** (total: 100). Deductions are weighted by severity:

| Severity | Points Deducted |
|----------|----------------|
| High     | 10 (full)      |
| Medium   | 7              |
| Low      | 4              |

**Grade Boundaries:**

| Score Range | Grade |
|-------------|-------|
| 90–100      | A     |
| 80–89       | B     |
| 70–79       | C     |
| 60–69       | D     |
| < 60        | F     |

---

## 5. System Architecture

### 5.1 High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    React.js Frontend                     │
│  ┌───────────┐ ┌──────────┐ ┌─────────┐ ┌───────────┐  │
│  │ Dashboard │ │  Charts  │ │ OWASP   │ │  Report   │  │
│  │ ScoreCard │ │ Radar    │ │ Table   │ │  Export   │  │
│  │ ScanForm  │ │ Bar/Pie  │ │         │ │  JSON/TXT │  │
│  └───────────┘ └──────────┘ └─────────┘ └───────────┘  │
└───────────────────────┬─────────────────────────────────┘
                        │ HTTP REST API
                        ▼
┌─────────────────────────────────────────────────────────┐
│                   Flask Backend (Python)                  │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────────┐ │
│  │  REST API  │ │  Scanner   │ │   OWASP Test Suite   │ │
│  │  /api/*    │ │  Engine    │ │   10 test functions   │ │
│  └────────────┘ └────────────┘ └──────────────────────┘ │
│  ┌────────────┐ ┌────────────┐ ┌──────────────────────┐ │
│  │  Crawler   │ │ Detectors  │ │   Scoring Engine     │ │
│  │  BFS       │ │ SQLi/XSS/  │ │   0-100 / A-F        │ │
│  │  Spider    │ │ Tech-aware │ │                      │ │
│  └────────────┘ └────────────┘ └──────────────────────┘ │
└───────────────────────┬─────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────────┐
│              SQLite Database (securescan.db)              │
│  ┌──────┐ ┌──────────────┐ ┌───────────────┐ ┌──────┐  │
│  │scans │ │scan_results  │ │vulnerabilities│ │ logs │  │
│  │score │ │owasp_id      │ │type, url      │ │      │  │
│  │grade │ │status        │ │severity       │ │      │  │
│  └──────┘ └──────────────┘ └───────────────┘ └──────┘  │
└─────────────────────────────────────────────────────────┘
```

### 5.2 Database Schema

**scans** — Master scan records with scoring data:
- `id`, `target_url`, `status`, `score`, `grade`, `tests_passed`, `tests_total`, `tech_stack`, `tech_stack_confidence`, `tech_stack_details`, `started_at`, `completed_at`

**scan_results** — Individual OWASP test outcomes:
-  `id`, `scan_id`, `owasp_id`, `owasp_name`, `status`, `severity`, `description`, `recommendation`, `findings_json`

**vulnerabilities** — Raw vulnerability findings:
- `id`, `scan_id`, `type`, `url`, `parameter`, `payload`, `severity`, `description`, `owasp_category`

**pages** — Crawled URLs per scan:
- `id`, `scan_id`, `url`

**logs** — Real-time scan engine logs:
- `id`, `scan_id`, `message`, `timestamp`

### 5.3 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/health` | Health check |
| POST | `/api/scan/start` | Start a new scan (async) |
| GET | `/api/scan/status?url=` | Poll scan status + score |
| GET | `/api/scan/results?url=` | Full results with OWASP data |
| GET | `/api/scan/report?url=` | Structured report for export |
| GET | `/api/scan/logs?url=` | Real-time scan logs |

---

## 6. Implementation

### 6.1 Project Structure

```
SecureScan/
├── backend/
│   ├── app.py                  # Flask API server
│   ├── database.py             # SQLite schema + helpers
│   ├── scanner.py              # Security header checks
│   ├── security.py             # URL validation + SSRF protection
│   ├── core/
│   │   ├── engine.py           # Main scan orchestrator
│   │   ├── owasp_tests.py      # 10 OWASP test functions
│   │   ├── scoring.py          # Score calculation engine
│   │   └── techstack.py        # Tech stack fingerprinting
│   ├── crawler/
│   │   └── crawler.py          # BFS web crawler
│   ├── detectors/
│   │   ├── sqli.py             # SQL injection detector
│   │   ├── xss.py              # XSS detector
│   │   └── sensitive_data.py   # Sensitive data scanner
│   └── reports/
│       └── report.py           # Report generation (JSON/Text)
├── frontend/
│   ├── src/
│   │   ├── App.jsx             # Main dashboard component
│   │   ├── api.js              # Axios API client
│   │   ├── index.css           # Global styles
│   │   ├── main.jsx            # React entry point
│   │   └── components/
│   │       ├── ScoreCard.jsx   # Score / Grade / Tests Passed
│   │       ├── Charts.jsx      # Bar, Radar, Donut charts
│   │       ├── OWASPTable.jsx  # Interactive OWASP results table
│   │       ├── VulnerabilityList.jsx  # Detailed findings
│   │       ├── ScanLogs.jsx    # Terminal-style log viewer
│   │       └── ReportExport.jsx # Export buttons
│   ├── index.html
│   ├── tailwind.config.js
│   └── package.json
├── sample_scan_output.json     # Sample results for demo
├── Documentation.md            # This file
└── README.md
```

### 6.2 Web Crawler (crawler.py)

The crawler uses a **breadth-first search (BFS)** algorithm to discover pages within the target domain:

```python
class Crawler:
    def __init__(self, target_url, max_depth=3):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited = set()
        self.to_visit = [(target_url, 0)]
        self.base_domain = urlparse(target_url).netloc
```

**Key design decisions:**
- **Domain restriction:** Only follows links within the same domain (`netloc` matching)
- **Depth limiting:** Configurable `max_depth` prevents infinite crawling
- **Fragment stripping:** URL fragments (`#`) are removed to avoid duplicate entries
- **Content filtering:** Only processes `text/html` responses
- **Rate limiting:** 1.2-second delay between requests to avoid overwhelming targets

### 6.3 SQL Injection Detector (sqli.py)

The SQL injection detector uses **error-based detection**. It injects payloads into URL query parameters and analyzes the response for database error signatures:

```python
# Payloads include: single quotes, double quotes, OR-based tautologies,
# comment sequences (--), and UNION-based injection attempts
self.payloads = ["'", '"', "' OR '1'='1", "' OR 1=1 --", "' UNION SELECT NULL--"]

# Error signatures cover MySQL, PostgreSQL, SQLite, Oracle, and MSSQL
self.error_signatures = [
    "you have an error in your sql syntax",  # MySQL
    "pg_query",                                # PostgreSQL
    "sqlite3.operationalerror",               # SQLite
    "ora-01756",                              # Oracle
    "unclosed quotation mark",                # MSSQL
]
```

**Detection flow:**
1. Parse URL to extract query parameters
2. For each parameter, inject each payload (appended to original value)
3. Reconstruct URL and send HTTP GET request
4. Check response body (lowercased) for any matching error signature
5. If matched → report as SQL Injection vulnerability (High severity)

### 6.4 XSS Detector (xss.py)

The XSS detector checks for **reflected cross-site scripting** by injecting a unique marker payload and checking if it appears un-sanitised in the response:

```python
self.payload = "<script>alert('XSS_TEST_MARKER')</script>"
```

If the exact payload string is found in the response HTML, it indicates the application is reflecting user input without proper encoding — a confirmed reflected XSS vulnerability.

### 6.5 Sensitive Data Detector (sensitive_data.py)

This detector uses regular expressions to identify exposed sensitive information in HTTP responses:

- **Email addresses:** Standard email pattern matching
- **Indian phone numbers:** 10-digit numbers starting with 6-9
- **Stripe API keys:** `sk_(live|test)_` followed by 24 alphanumeric characters
- **AWS Access Keys:** Pattern matching `AKIA` prefix + 16 uppercase alphanumeric characters

### 6.6 Scoring Engine (scoring.py)

The scoring engine normalises OWASP test results into a single numeric score:

```python
# Each test starts at 10 points
# Deductions based on severity: High=-10, Medium=-7, Low=-4
for result in owasp_results:
    if result["status"] == "pass":
        points = 10
    else:
        deduction = SEVERITY_DEDUCTION[result["severity"]]
        points = max(0, 10 - deduction)
    total_score += points

# Normalize to 0-100
score = round((total_score / max_possible) * 100)
```

---

## 7. OWASP Top 10 — Test Implementation Details

### A01: Broken Access Control

**What it checks:**
- Probes common admin paths (`/admin`, `/phpmyadmin`, `/.git`, `/server-status`, etc.)
- Detects directory listing (Apache `Index of /` pattern)
- Checks if sensitive paths return HTTP 200 without authentication

**How it works:** The test constructs a list of known sensitive paths and sends HTTP GET requests to each. If any path returns a 200 status code with content suggesting an admin panel or directory listing, it's flagged as a failure.

### A02: Security Misconfiguration

**What it checks:** Presence of 6 critical security headers:
- Content-Security-Policy (High)
- Strict-Transport-Security (Medium)
- X-Content-Type-Options (Medium)
- X-Frame-Options (Medium)
- Referrer-Policy (Low)
- Permissions-Policy (Low)

**How it works:** Fetches the target URL and inspects response headers. Each missing header is logged as a finding with its associated severity level.

### A03: Software Supply Chain Failures

**What it checks:** Outdated JavaScript library references in page source:
- jQuery 1.x / 2.x
- Bootstrap 3.x
- AngularJS 1.x
- React 15.x

**How it works:** Scans the HTML body of all crawled pages using regex patterns that match library version strings (e.g., `jquery-1.12.4.min.js`).

### A04: Cryptographic Failures

**What it checks:**
- Whether the target is served over plain HTTP (no TLS)
- Mixed content on HTTPS pages (HTTP resources on HTTPS page)
- Sensitive data exposure (reuses the `SensitiveDataDetector`)

### A05: Injection

**What it checks:**
- SQL Injection (reuses `SQLInjectionDetector`)
- Cross-Site Scripting / XSS (reuses `XSSDetector`)

This is the most active test — it sends crafted payloads to query parameters across all discovered URLs.

### A06: Insecure Design

**What it checks:** Verbose error pages and stack traces exposed to users. Matches patterns like:
- `Traceback (most recent call last)` (Python)
- `PHP Warning / Notice / Fatal`
- `Stack Trace:` (generic)
- `ASP.NET_SessionId` (ASP.NET leaks)

### A07: Authentication Failures

**What it checks:**
- Login forms (pages with password fields) without CSRF tokens
- Login forms that submit over plain HTTP instead of HTTPS

**How it works:** Scans all crawled page responses for password input fields. When found, checks for the presence of common CSRF token field names (`csrf`, `_token`, `csrfmiddlewaretoken`, etc.) and verifies form action URLs use HTTPS.

### A08: Software & Data Integrity Failures

**What it checks:** External `<script>` tags loaded from CDNs without Subresource Integrity (SRI) attributes.

**How it works:** Parses HTML to find all `<script src="...">` tags pointing to external URLs. For each, checks whether the tag includes an `integrity=` attribute.

### A09: Security Logging & Alerting Failures

**What it checks:**
- Presence of request correlation headers (`X-Request-Id`, `X-Correlation-Id`)
- Verbose `Server` header revealing version information

### A10: Mishandling of Exceptional Conditions

**What it checks:**
- Probes a non-existent URL path and checks if the server returns 500 (instead of clean 404)
- Checks for debug information in error responses
- Scans crawled pages for HTTP 5xx status codes

---

## 8. Case Study

### 8.1 Target: Acunetix Test PHP Website

**URL:** `http://testphp.vulnweb.com`  
**Description:** An intentionally vulnerable web application maintained by Acunetix for testing vulnerability scanners. It contains known SQL injection, XSS, and other security flaws.

### 8.2 Scan Configuration

| Parameter | Value |
|-----------|-------|
| Crawl Depth | 2 |
| Concurrent Workers | 5 |
| Request Timeout | 15 seconds |
| User-Agent | SecureScan/1.0 |

### 8.3 Expected Results

Based on the known vulnerabilities in testphp.vulnweb.com:

| OWASP Test | Expected Outcome |
|------------|------------------|
| A01: Broken Access Control | FAIL — Directory listing and admin paths accessible |
| A02: Security Misconfiguration | FAIL — Missing CSP, HSTS, and other headers |
| A03: Supply Chain | PASS — No outdated library signatures detected |
| A04: Cryptographic Failures | FAIL — Served over HTTP, sensitive data exposed |
| A05: Injection | FAIL — SQL injection in `listproducts.php?cat=`, XSS in search |
| A06: Insecure Design | FAIL — PHP error messages exposed |
| A07: Authentication Failures | FAIL — Login form without CSRF protection |
| A08: Integrity Failures | PASS — No external CDN scripts without SRI |
| A09: Logging Failures | Varies — Depends on server configuration |
| A10: Exception Handling | PASS/FAIL — Depends on error page configuration |

### 8.4 Sample Score Calculation

With 4 tests passing and 6 failing (mostly High severity):

```
Passed: 4 tests × 10 points = 40 points
Failed (High): 5 tests × 0 points = 0 points
Failed (Medium): 1 test × 3 points = 3 points
Total: 43/100 → Grade: F
```

This accurately reflects the poor security posture of an intentionally vulnerable application.

---

## 9. Observations and Analysis

### 9.1 Detection Accuracy

- **SQL Injection:** The error-based approach successfully detects injection on pages with query parameters that interact with databases. It correctly identified the `cat` parameter vulnerability on `listproducts.php`.
- **XSS:** The reflected XSS detector reliably identifies cases where user input is echoed without sanitisation.
- **Security Headers:** Header checking is deterministic and produces zero false positives.
- **Sensitive Data:** Regex-based detection works well for structured data (emails, phone numbers, API keys) but may miss obfuscated or encrypted sensitive information.

### 9.2 Performance Characteristics

| Metric | Typical Value |
|--------|---------------|
| Crawl speed | ~1 page/1.5 seconds (rate-limited) |
| Full scan (depth=2) | 2–5 minutes depending on site size |
| Concurrent workers | 5 threads |
| Memory usage | < 100 MB for typical scans |

### 9.3 Limitations

1. **Error-based SQLi only:** Does not detect blind or time-based SQL injection
2. **Reflected XSS only:** Does not detect stored or DOM-based XSS
3. **No authentication support:** Cannot scan pages behind login
4. **GET parameters only:** Does not test POST form data
5. **Single-page apps:** Limited ability to crawl JavaScript-rendered content
6. **False positives:** Generic error patterns (e.g., "internal server error") may occasionally trigger false detections

---

## 10. Conclusion

SecureScan successfully demonstrates the practical implementation of an automated web vulnerability scanner aligned with the OWASP Top 10 framework. The project achieves its objectives of:

- ✅ Detecting real-world vulnerabilities (SQLi, XSS, misconfigurations) through automated scanning
- ✅ Mapping all findings to the OWASP Top 10 categorisation system
- ✅ Providing quantitative security scoring (0–100 scale with A–F grades)
- ✅ Delivering results through an interactive, visually professional dashboard
- ✅ Generating exportable reports with actionable recommendations

The tool validated its effectiveness using the Acunetix testphp.vulnweb.com intentionally vulnerable application, correctly identifying SQL injection, XSS, missing security headers, and other vulnerabilities.

While SecureScan is not intended to replace enterprise-grade tools like Burp Suite or OWASP ZAP, it serves as an effective educational tool and a practical starting point for organisations beginning their security assessment journey.

---

## 11. Future Scope

1. **Blind SQL Injection Detection:** Implement time-based and boolean-based blind injection techniques
2. **Stored & DOM XSS:** Extend XSS detection to cover persistent and DOM-based variants
3. **POST Parameter Testing:** Analyse and fuzz HTML form submissions
4. **Authenticated Scanning:** Support login cookie / session-based scanning of protected pages
5. **JavaScript Rendering:** Integrate a headless browser (Puppeteer/Playwright) for SPA scanning
6. **Scheduled Scans:** Add a job queue for recurring automated assessments
7. **PDF Report Generation:** Generate formatted PDF reports using WeasyPrint or ReportLab
8. **CI/CD Integration:** Provide a CLI interface for integration into deployment pipelines
9. **CVE Database Integration:** Cross-reference detected library versions with the NVD/CVE database
10. **Multi-User Support:** Add authentication and role-based access to the dashboard

---

## 12. Bibliography

1. OWASP Foundation. (2025). *OWASP Top 10 Web Application Security Risks.* https://owasp.org/www-project-top-ten/
2. OWASP Foundation. (2023). *OWASP Testing Guide v5.* https://owasp.org/www-project-web-security-testing-guide/
3. Stuttard, D., & Pinto, M. (2011). *The Web Application Hacker's Handbook.* 2nd Edition, Wiley.
4. Zalewski, M. (2012). *The Tangled Web: A Guide to Securing Modern Web Applications.* No Starch Press.
5. Flask Documentation. https://flask.palletsprojects.com/
6. React Documentation. https://react.dev/
7. Mozilla Developer Network. (2024). *HTTP Headers — Security.* https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers
8. SQLite Documentation. https://www.sqlite.org/docs.html
9. BeautifulSoup Documentation. https://www.crummy.com/software/BeautifulSoup/bs4/doc/
10. Recharts Documentation. https://recharts.org/
11. Acunetix. *Acunetix Web Vulnerability Scanner Test Sites.* http://testphp.vulnweb.com/
12. NIST. *National Vulnerability Database (NVD).* https://nvd.nist.gov/
13. CWE/SANS. *Top 25 Most Dangerous Software Weaknesses.* https://cwe.mitre.org/top25/

---

## 13. Appendices

### Appendix A: Installation & Setup

**Prerequisites:**
- Python 3.10+
- Node.js 18+
- npm 9+

**Backend Setup:**
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate        # Windows
pip install -r requirements.txt
python app.py                  # Starts on http://localhost:5000
```

**Frontend Setup:**
```bash
cd frontend
npm install
npm run dev                    # Starts on http://localhost:5173
```

### Appendix B: Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| PORT | 5000 | Backend server port |
| FRONTEND_ORIGIN | http://localhost:5173 | CORS allowed origin |

### Appendix C: Sample API Request/Response

**Start Scan:**
```http
POST /api/scan/start
Content-Type: application/json

{ "url": "http://testphp.vulnweb.com" }
```

**Response:**
```json
{
  "message": "Scan started",
  "target": "http://testphp.vulnweb.com"
}
```

**Get Results (after completion):**
```http
GET /api/scan/results?url=http://testphp.vulnweb.com
```

See `sample_scan_output.json` for the complete response structure.

### Appendix D: Dependencies

**Python (backend/requirements.txt):**
- Flask 3.0.3
- Flask-Cors 4.0.1
- requests 2.32.3
- python-dotenv 1.0.1
- beautifulsoup4 4.12.3

**JavaScript (frontend/package.json):**
- react 18.3.1
- axios 1.8.2
- recharts (latest)
- tailwindcss 3.4.16
- vite 5.4.10

---

## 14. Glossary

| Term | Definition |
|------|------------|
| **BFS** | Breadth-First Search — algorithm used for web crawling |
| **CORS** | Cross-Origin Resource Sharing — HTTP mechanism for cross-domain requests |
| **CSRF** | Cross-Site Request Forgery — attack that tricks users into submitting malicious requests |
| **CSP** | Content Security Policy — HTTP header that restricts resource loading |
| **CVE** | Common Vulnerabilities and Exposures — standardised vulnerability identifiers |
| **DOM** | Document Object Model — tree representation of HTML/XML documents |
| **HSTS** | HTTP Strict Transport Security — header enforcing HTTPS connections |
| **OWASP** | Open Web Application Security Project — nonprofit security foundation |
| **REST** | Representational State Transfer — architectural style for web APIs |
| **SPA** | Single Page Application — web app that loads a single HTML page |
| **SQL** | Structured Query Language — language for database operations |
| **SQLi** | SQL Injection — attack that inserts malicious SQL via user input |
| **SRI** | Subresource Integrity — browser feature to verify CDN resource integrity |
| **SSRF** | Server-Side Request Forgery — attack that makes server send requests to internal resources |
| **TLS/SSL** | Transport Layer Security / Secure Sockets Layer — encryption protocols |
| **XSS** | Cross-Site Scripting — attack that injects client-side scripts into web pages |

---

*Document generated for SecureScan v2.0 — IGNOU MCA Project*

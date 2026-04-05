"""
OWASP Top 10 (2025) Test Framework for SecureScan.

Each test function receives crawled page data and returns a structured result dict.
The 10 tests map to the OWASP Top 10 categories (A01–A10).
Existing detectors (sqli, xss, sensitive_data) are integrated into the relevant tests.
"""

import re
import requests
import urllib.parse
from typing import List, Dict, Any, Optional

# Import existing detectors — these are reused, not rewritten
from detectors.sqli import SQLInjectionDetector
from detectors.xss import XSSDetector
from detectors.sensitive_data import SensitiveDataDetector


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fetch_page(url: str, timeout: int = 15) -> Optional[requests.Response]:
    """Safely fetch a URL and return the Response object, or None on failure."""
    try:
        return requests.get(
            url, timeout=timeout,
            headers={"User-Agent": "SecureScan/1.0"},
            allow_redirects=True
        )
    except requests.RequestException:
        return None


def _make_result(
    owasp_id: str,
    owasp_name: str,
    status: str,
    severity: str,
    description: str,
    recommendation: str,
    findings: Optional[List[Dict]] = None
) -> Dict[str, Any]:
    """Build a standardised OWASP test result dict."""
    return {
        "owasp_id": owasp_id,
        "owasp_name": owasp_name,
        "status": status,              # "pass" or "fail"
        "severity": severity,          # "Low", "Medium", "High"
        "description": description,
        "recommendation": recommendation,
        "findings": findings or []
    }


# ---------------------------------------------------------------------------
# A01 — Broken Access Control
# ---------------------------------------------------------------------------

# Common admin / sensitive paths to probe
_SENSITIVE_PATHS = [
    "/admin", "/admin/", "/administrator", "/.env", "/config",
    "/phpmyadmin", "/wp-admin", "/cpanel", "/server-status",
    "/debug", "/.git", "/.git/config"
]

def test_a01_broken_access_control(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A01 — Broken Access Control
    Check for:
      1. Directory listing enabled (look for 'Index of /' pattern)
      2. Accessible admin / sensitive paths without authentication
    """
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Check sensitive paths
    for path in _SENSITIVE_PATHS:
        probe_url = origin + path
        if log:
            log(f"[A01] Probing {probe_url}")
        resp = _fetch_page(probe_url, timeout=10)
        if resp and resp.status_code == 200:
            body_lower = resp.text.lower()
            # Directory listing?
            if "index of" in body_lower and "<pre>" in body_lower:
                findings.append({
                    "issue": "Directory listing enabled",
                    "url": probe_url,
                    "evidence": "Response contains 'Index of' pattern"
                })
            # Admin panels accessible
            if any(kw in body_lower for kw in ["login", "dashboard", "control panel", "admin"]):
                findings.append({
                    "issue": f"Sensitive path accessible: {path}",
                    "url": probe_url,
                    "evidence": f"HTTP 200 returned for {path}"
                })

    # Check for directory listing on crawled pages
    for url, resp in responses.items():
        if resp and "index of" in resp.text.lower():
            findings.append({
                "issue": "Directory listing detected",
                "url": url,
                "evidence": "Page contains 'Index of' pattern"
            })

    if findings:
        return _make_result(
            "A01", "Broken Access Control", "fail", "High",
            f"Found {len(findings)} access control issue(s): exposed admin paths or directory listings.",
            "Restrict access to admin paths with authentication. Disable directory listing in server config.",
            findings
        )
    return _make_result(
        "A01", "Broken Access Control", "pass", "Low",
        "No exposed admin paths or directory listings detected.",
        "Continue monitoring and enforcing access controls."
    )


# ---------------------------------------------------------------------------
# A02 — Security Misconfiguration
# ---------------------------------------------------------------------------

_REQUIRED_HEADERS = {
    "Content-Security-Policy": "High",
    "Strict-Transport-Security": "Medium",
    "X-Content-Type-Options": "Medium",
    "X-Frame-Options": "Medium",
    "Referrer-Policy": "Low",
    "Permissions-Policy": "Low",
}

def test_a02_security_misconfiguration(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A02 — Security Misconfiguration
    Check the target's main page for missing security headers.
    Reuses logic from the existing scanner.py module.
    """
    findings = []
    resp = responses.get(base_url) or _fetch_page(base_url)

    if resp is None:
        return _make_result(
            "A02", "Security Misconfiguration", "fail", "Medium",
            "Could not fetch the target URL to check security headers.",
            "Ensure the target URL is reachable.",
        )

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    for header, severity in _REQUIRED_HEADERS.items():
        if header.lower() not in headers_lower:
            findings.append({
                "issue": f"Missing header: {header}",
                "severity": severity,
                "evidence": "Header not found in HTTP response"
            })

    # Check X-Content-Type-Options value
    xcto = headers_lower.get("x-content-type-options", "")
    if xcto and xcto.lower() != "nosniff":
        findings.append({
            "issue": "Weak X-Content-Type-Options",
            "severity": "Medium",
            "evidence": f"Current value: {xcto}"
        })

    if findings:
        worst = "High" if any(f.get("severity") == "High" for f in findings) else "Medium"
        return _make_result(
            "A02", "Security Misconfiguration", "fail", worst,
            f"{len(findings)} missing or misconfigured security header(s) detected.",
            "Configure your web server to send all recommended security headers (CSP, HSTS, X-Frame-Options, etc.).",
            findings
        )
    return _make_result(
        "A02", "Security Misconfiguration", "pass", "Low",
        "All recommended security headers are present.",
        "Continue monitoring header configuration on deployments."
    )


# ---------------------------------------------------------------------------
# A03 — Software Supply Chain Failures
# ---------------------------------------------------------------------------

# Known outdated JS library signatures (version patterns in the source)
_OUTDATED_LIBS = [
    (r"jquery[/-]v?(1\.\d+)", "jQuery 1.x", "Upgrade to jQuery 3.x+"),
    (r"jquery[/-]v?(2\.\d+)", "jQuery 2.x", "Upgrade to jQuery 3.x+"),
    (r"bootstrap[/-]v?(3\.\d+)", "Bootstrap 3.x", "Upgrade to Bootstrap 5.x+"),
    (r"angular[/-]v?(1\.\d+)", "AngularJS 1.x", "Migrate to Angular 14+"),
    (r"react[/-]v?(15\.\d+)", "React 15.x", "Upgrade to React 18+"),
]

def test_a03_supply_chain(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A03 — Software Supply Chain Failures
    Scan HTML pages for references to outdated JavaScript libraries.
    """
    findings = []

    for url, resp in responses.items():
        if resp is None:
            continue
        body = resp.text.lower()
        for pattern, lib_name, fix in _OUTDATED_LIBS:
            match = re.search(pattern, body)
            if match:
                findings.append({
                    "issue": f"Outdated library detected: {lib_name} (v{match.group(1)})",
                    "url": url,
                    "recommendation": fix
                })

    if findings:
        return _make_result(
            "A03", "Software Supply Chain Failures", "fail", "Medium",
            f"Found {len(findings)} outdated library reference(s) that may contain known vulnerabilities.",
            "Update all client-side libraries to their latest stable versions.",
            findings
        )
    return _make_result(
        "A03", "Software Supply Chain Failures", "pass", "Low",
        "No known outdated JavaScript libraries detected in page sources.",
        "Regularly audit third-party dependencies for known CVEs."
    )


# ---------------------------------------------------------------------------
# A04 — Cryptographic Failures
# ---------------------------------------------------------------------------

def test_a04_cryptographic_failures(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A04 — Cryptographic Failures
    Check for:
      1. Site served over plain HTTP (no HTTPS)
      2. Mixed content (HTTPS page loading HTTP resources)
      3. Sensitive data exposure (via existing SensitiveDataDetector)
    """
    findings = []

    # Check if the base URL uses HTTPS
    if base_url.startswith("http://"):
        findings.append({
            "issue": "Site served over plain HTTP",
            "url": base_url,
            "evidence": "No TLS/SSL encryption — data transmitted in cleartext"
        })

    # Check for mixed content on HTTPS pages
    for url, resp in responses.items():
        if resp is None:
            continue
        if url.startswith("https://"):
            # Look for http:// resource references in the HTML
            http_refs = re.findall(r'(?:src|href|action)=["\']http://', resp.text, re.IGNORECASE)
            if http_refs:
                findings.append({
                    "issue": "Mixed content detected",
                    "url": url,
                    "evidence": f"{len(http_refs)} HTTP resource(s) loaded on HTTPS page"
                })

    # Run existing sensitive data detector on all URLs
    detector = SensitiveDataDetector()
    for url in urls:
        result = detector.scan_url(url)
        if result:
            findings.append({
                "issue": "Sensitive data exposed in response",
                "url": url,
                "evidence": result.get("details", result.get("payload", ""))
            })

    if findings:
        return _make_result(
            "A04", "Cryptographic Failures", "fail", "High",
            f"Found {len(findings)} cryptographic / data-exposure issue(s).",
            "Use HTTPS everywhere. Remove sensitive data from HTML responses. Avoid mixed content.",
            findings
        )
    return _make_result(
        "A04", "Cryptographic Failures", "pass", "Low",
        "No cryptographic weaknesses or sensitive data exposure detected.",
        "Continue enforcing HTTPS and scan regularly for data leaks."
    )


# ---------------------------------------------------------------------------
# A05 — Injection
# ---------------------------------------------------------------------------

def test_a05_injection(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A05 — Injection (SQL Injection + XSS)
    Uses the existing SQLInjectionDetector and XSSDetector.
    """
    findings = []

    sqli_detector = SQLInjectionDetector()
    xss_detector = XSSDetector()

    # Limit to testing a maximum of 15 URLs for injection to speed up scanning
    test_urls = urls[:15]
    if log and len(urls) > 15:
        log(f"[A05] Found {len(urls)} URLs but limiting injection tests to 15 to prevent timeouts.")

    for url in test_urls:
        if log:
            log(f"[A05] Testing injection on {url}")

        sqli_result = sqli_detector.scan_url(url)
        if sqli_result:
            findings.append({
                "issue": "SQL Injection detected",
                "url": sqli_result.get("url", url),
                "parameter": sqli_result.get("parameter", ""),
                "payload": sqli_result.get("payload", ""),
                "sub_type": "SQL Injection"
            })

        xss_result = xss_detector.scan_url(url)
        if xss_result:
            findings.append({
                "issue": "Cross-Site Scripting (XSS) detected",
                "url": xss_result.get("url", url),
                "parameter": xss_result.get("parameter", ""),
                "payload": xss_result.get("payload", ""),
                "sub_type": "XSS"
            })

    if findings:
        return _make_result(
            "A05", "Injection", "fail", "High",
            f"Found {len(findings)} injection vulnerability/ies (SQLi / XSS).",
            "Use parameterized queries for SQL. Sanitise and encode all user input before rendering in HTML.",
            findings
        )
    return _make_result(
        "A05", "Injection", "pass", "Low",
        "No SQL injection or XSS vulnerabilities detected.",
        "Continue using parameterized queries and output encoding."
    )


# ---------------------------------------------------------------------------
# A06 — Insecure Design
# ---------------------------------------------------------------------------

_ERROR_PATTERNS = [
    r"traceback \(most recent call last\)",
    r"stack trace:",
    r"fatal error",
    r"exception in thread",
    r"<b>warning</b>:",
    r"php (warning|notice|fatal)",
    r"asp\.net_sessionid",
    r"on line \d+",
]

def test_a06_insecure_design(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A06 — Insecure Design
    Check for verbose error pages and application stack traces exposed to users.
    """
    findings = []

    for url, resp in responses.items():
        if resp is None:
            continue
        body_lower = resp.text.lower()
        for pattern in _ERROR_PATTERNS:
            if re.search(pattern, body_lower):
                findings.append({
                    "issue": "Verbose error / stack trace exposed",
                    "url": url,
                    "evidence": f"Pattern matched: {pattern}"
                })
                break  # One finding per URL is enough

    if findings:
        return _make_result(
            "A06", "Insecure Design", "fail", "Medium",
            f"Found {len(findings)} page(s) exposing verbose error messages or stack traces.",
            "Configure custom error pages. Never expose stack traces or debug info in production.",
            findings
        )
    return _make_result(
        "A06", "Insecure Design", "pass", "Low",
        "No verbose error pages or stack traces detected.",
        "Ensure custom error handling is configured for all environments."
    )


# ---------------------------------------------------------------------------
# A07 — Authentication Failures
# ---------------------------------------------------------------------------

def test_a07_authentication_failures(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A07 — Authentication Failures
    Check for:
      1. Login forms without CSRF tokens
      2. Login forms submitting over HTTP (not HTTPS)
    """
    findings = []

    for url, resp in responses.items():
        if resp is None:
            continue
        body_lower = resp.text.lower()
        # Detect if the page has a login form
        has_password_field = 'type="password"' in body_lower or "type='password'" in body_lower
        if not has_password_field:
            continue

        # Check for CSRF token
        has_csrf = any(tok in body_lower for tok in [
            "csrf", "_token", "csrfmiddlewaretoken",
            "authenticity_token", "__requestverificationtoken"
        ])
        if not has_csrf:
            findings.append({
                "issue": "Login form without CSRF protection",
                "url": url,
                "evidence": "Password field found but no CSRF token detected in the form"
            })

        # Check if form action is HTTP
        form_actions = re.findall(r'action=["\']([^"\']*)["\']', resp.text, re.IGNORECASE)
        for action in form_actions:
            if action.startswith("http://"):
                findings.append({
                    "issue": "Login form submits over plain HTTP",
                    "url": url,
                    "evidence": f"Form action: {action}"
                })

    if findings:
        return _make_result(
            "A07", "Authentication Failures", "fail", "High",
            f"Found {len(findings)} authentication-related issue(s).",
            "Add CSRF tokens to all forms. Ensure login forms submit over HTTPS.",
            findings
        )
    return _make_result(
        "A07", "Authentication Failures", "pass", "Low",
        "No authentication weaknesses detected (CSRF tokens present, HTTPS used).",
        "Enforce multi-factor authentication and strong password policies."
    )


# ---------------------------------------------------------------------------
# A08 — Software & Data Integrity Failures
# ---------------------------------------------------------------------------

def test_a08_integrity_failures(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A08 — Software & Data Integrity Failures
    Check for external scripts loaded without Subresource Integrity (SRI) attributes.
    """
    findings = []

    for url, resp in responses.items():
        if resp is None:
            continue
        # Find all <script src="..."> tags
        scripts = re.findall(
            r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>',
            resp.text, re.IGNORECASE
        )
        for src in scripts:
            # Only check external scripts (CDN)
            if src.startswith("http://") or src.startswith("https://") or src.startswith("//"):
                # Check if the tag has integrity attribute
                # Re-search the specific tag to check for integrity
                tag_pattern = re.escape(src)
                tag_match = re.search(
                    rf'<script[^>]*src=["\']' + tag_pattern + r'["\'][^>]*>',
                    resp.text, re.IGNORECASE
                )
                if tag_match and "integrity=" not in tag_match.group(0).lower():
                    findings.append({
                        "issue": "External script without SRI",
                        "url": url,
                        "evidence": f"Script: {src} loaded without integrity attribute"
                    })

    if findings:
        return _make_result(
            "A08", "Software & Data Integrity Failures", "fail", "Medium",
            f"Found {len(findings)} external script(s) loaded without Subresource Integrity (SRI).",
            "Add integrity and crossorigin attributes to all external <script> tags.",
            findings
        )
    return _make_result(
        "A08", "Software & Data Integrity Failures", "pass", "Low",
        "All external scripts include SRI attributes, or no external scripts detected.",
        "Continue using SRI for all CDN-hosted resources."
    )


# ---------------------------------------------------------------------------
# A09 — Security Logging & Alerting Failures
# ---------------------------------------------------------------------------

def test_a09_logging_failures(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A09 — Security Logging & Alerting Failures
    Check for:
      1. Missing X-Request-Id or similar correlation headers (indicates no request logging)
      2. Server header reveals too much version info
    """
    findings = []
    resp = responses.get(base_url) or _fetch_page(base_url)

    if resp is None:
        return _make_result(
            "A09", "Security Logging & Alerting Failures", "fail", "Medium",
            "Could not fetch target URL to assess logging configuration.",
            "Ensure server is reachable and properly configured."
        )

    headers_lower = {k.lower(): v for k, v in resp.headers.items()}

    # Check for request correlation headers
    has_correlation = any(h in headers_lower for h in [
        "x-request-id", "x-correlation-id", "x-trace-id"
    ])
    if not has_correlation:
        findings.append({
            "issue": "No request correlation header found",
            "evidence": "Missing X-Request-Id / X-Correlation-Id — may indicate insufficient request logging"
        })

    # Check if Server header is too verbose
    server = headers_lower.get("server", "")
    if server and re.search(r'\d+\.\d+', server):
        findings.append({
            "issue": "Verbose Server header",
            "evidence": f"Server: {server} — reveals version information"
        })

    if findings:
        return _make_result(
            "A09", "Security Logging & Alerting Failures", "fail", "Low",
            f"Found {len(findings)} logging/alerting concern(s).",
            "Implement request correlation IDs. Remove version info from Server header. Set up centralized logging.",
            findings
        )
    return _make_result(
        "A09", "Security Logging & Alerting Failures", "pass", "Low",
        "Logging and alerting configuration appears adequate.",
        "Ensure logs are monitored and alerts are configured for anomalies."
    )


# ---------------------------------------------------------------------------
# A10 — Mishandling of Exceptional Conditions
# ---------------------------------------------------------------------------

def test_a10_exception_handling(base_url: str, urls: List[str], responses: Dict[str, requests.Response], log=None) -> Dict:
    """
    A10 — Mishandling of Exceptional Conditions
    Probe for unhandled errors by:
      1. Requesting non-existent paths (expect clean 404, not a crash)
      2. Checking for 500 status codes among crawled pages
      3. Looking for debug mode indicators
    """
    findings = []
    parsed = urllib.parse.urlparse(base_url)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    # Probe a random non-existent path
    probe_url = origin + "/securescan_test_404_nonexistent_abc123"
    resp = _fetch_page(probe_url, timeout=10)
    if resp:
        if resp.status_code == 500:
            findings.append({
                "issue": "Server returns 500 for missing page",
                "url": probe_url,
                "evidence": "Expected 404 but got 500 — unhandled exception"
            })
        body_lower = resp.text.lower()
        if any(kw in body_lower for kw in ["traceback", "stack trace", "debug", "exception"]):
            findings.append({
                "issue": "Error page reveals debug information",
                "url": probe_url,
                "evidence": "Error response contains debug/traceback content"
            })

    # Check crawled pages for 500 errors
    for url, r in responses.items():
        if r and r.status_code >= 500:
            findings.append({
                "issue": "Server error (HTTP 5xx) detected",
                "url": url,
                "evidence": f"Status code: {r.status_code}"
            })

    if findings:
        return _make_result(
            "A10", "Mishandling of Exceptional Conditions", "fail", "Medium",
            f"Found {len(findings)} exception-handling issue(s).",
            "Implement custom error pages for all HTTP error codes. Never expose stack traces in production.",
            findings
        )
    return _make_result(
        "A10", "Mishandling of Exceptional Conditions", "pass", "Low",
        "Error handling appears properly configured — no debug info leaked.",
        "Regularly test error handling paths and keep custom error pages updated."
    )


# ---------------------------------------------------------------------------
# Master runner — executes all 10 OWASP tests
# ---------------------------------------------------------------------------

ALL_TESTS = [
    test_a01_broken_access_control,
    test_a02_security_misconfiguration,
    test_a03_supply_chain,
    test_a04_cryptographic_failures,
    test_a05_injection,
    test_a06_insecure_design,
    test_a07_authentication_failures,
    test_a08_integrity_failures,
    test_a09_logging_failures,
    test_a10_exception_handling,
]

def run_all_owasp_tests(
    base_url: str,
    urls: List[str],
    responses: Dict[str, requests.Response],
    log=None
) -> List[Dict[str, Any]]:
    """Execute every OWASP test and return the list of results."""
    results = []
    for test_fn in ALL_TESTS:
        test_name = test_fn.__name__
        if log:
            log(f"Running OWASP test: {test_name}")
        try:
            result = test_fn(base_url, urls, responses, log=log)
            results.append(result)
            status_icon = "✓" if result["status"] == "pass" else "✗"
            if log:
                log(f"  {status_icon} {result['owasp_id']}: {result['owasp_name']} — {result['status'].upper()}")
        except Exception as exc:
            if log:
                log(f"  ⚠ {test_name} raised an exception: {exc}")
            results.append(_make_result(
                test_name.split("_")[1].upper() if "_" in test_name else "???",
                test_name,
                "fail", "Medium",
                f"Test failed due to an internal error: {exc}",
                "Review the test implementation and retry.",
            ))
    return results

"""
SecurityHeaderDetector — Detects missing or weak security headers.
Maps to OWASP A02 (Cryptographic Failures) with reduced false positives.

Note: Only reports CRITICAL missing headers (CSP, HSTS, X-Content-Type-Options).
Skips low-impact headers like Referrer-Policy and Permissions-Policy to reduce noise.
"""

import requests
from typing import Optional, Dict, List
from .base import BaseDetector


class SecurityHeaderDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="Security Headers Detector", owasp_category="A02")
        
        # Only critical headers - omit low-impact ones to reduce false positives
        self.critical_headers = {
            "Content-Security-Policy": "High",
            "Strict-Transport-Security": "High",
            "X-Content-Type-Options": "High",
        }
        
        self.recommended_headers = {
            "X-Frame-Options": "Medium",
        }

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scans HTTP headers for security issues with high confidence."""
        try:
            res = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            headers = res.headers
            normalized = {k.lower(): v for k, v in headers.items()}

            # Check for missing CRITICAL headers only
            missing_critical = []
            for header, severity in self.critical_headers.items():
                if header.lower() not in normalized:
                    missing_critical.append(header)

            # Only report if multiple critical headers are missing
            # (Single missing header is common and often intentional)
            if len(missing_critical) >= 2:
                return self._make_finding(
                    vuln_type="Missing Critical Security Headers",
                    severity="High",
                    description=f"Multiple critical security headers are missing",
                    evidence=f"Missing: {', '.join(missing_critical)}",
                    url=url
                )

            # Check for weak values
            xcto = normalized.get("x-content-type-options", "")
            if xcto and xcto.lower() != "nosniff":
                return self._make_finding(
                    vuln_type="Weak X-Content-Type-Options",
                    severity="Medium",
                    description="X-Content-Type-Options should be 'nosniff'",
                    evidence=f"Current: {xcto}",
                    url=url
                )

            # Check CSP if present - is it too permissive?
            csp = normalized.get("content-security-policy", "")
            if csp and ("*" in csp or "'unsafe-inline'" in csp):
                return self._make_finding(
                    vuln_type="Weak Content Security Policy",
                    severity="Medium",
                    description="CSP is too permissive (contains * or 'unsafe-inline')",
                    evidence=f"Policy: {csp[:100]}...",
                    url=url
                )

            return None

        except requests.RequestException:
            return None

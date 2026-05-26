"""
CORSDetector — Detects misconfigured CORS policies.
Maps to OWASP A01 (Broken Access Control).
"""

import requests
from typing import Optional, Dict
from .base import BaseDetector


class CORSDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="CORS Misconfiguration Detector", owasp_category="A01")

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scans for misconfigured CORS policies."""
        try:
            # Send a request with an arbitrary Origin header
            headers = {
                'User-Agent': 'Mozilla/5.0',
                'Origin': 'http://malicious-attacker.com'
            }
            res = requests.get(url, timeout=15, headers=headers)
            response_headers = {k.lower(): v for k, v in res.headers.items()}

            # Check for overly permissive CORS headers
            acao = response_headers.get('access-control-allow-origin', '')
            
            if acao:
                # ACAO = "*" allows any origin
                if acao == '*':
                    return self._make_finding(
                        vuln_type="Misconfigured CORS Policy",
                        severity="Medium",
                        description="CORS allows requests from any origin (Access-Control-Allow-Origin: *)",
                        evidence=f"Access-Control-Allow-Origin: {acao}",
                        url=url
                    )
                # ACAO echoes the Origin header (could allow attacker's origin)
                elif acao == 'http://malicious-attacker.com':
                    return self._make_finding(
                        vuln_type="Overly Permissive CORS Policy",
                        severity="Medium",
                        description="CORS policy echoes the request origin without validation",
                        evidence=f"Server echoed attacker origin: {acao}",
                        url=url
                    )

            # Check for credentials in CORS
            acac = response_headers.get('access-control-allow-credentials', '')
            if acac and acac.lower() == 'true' and acao == '*':
                return self._make_finding(
                    vuln_type="CORS with Credentials Vulnerability",
                    severity="High",
                    description="CORS allows credentials with wildcard origin",
                    evidence="Access-Control-Allow-Credentials: true with Access-Control-Allow-Origin: *",
                    url=url
                )

            return None

        except requests.RequestException:
            return None

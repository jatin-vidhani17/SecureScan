"""
AuthenticationDetector — Detects weak authentication mechanisms and session issues.
Maps to OWASP A05 (Broken Authentication) and A07 (Identification and Authentication Failures).
"""

import requests
import re
from typing import Optional, Dict
from .base import BaseDetector


class AuthenticationDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="Authentication Detector", owasp_category="A05")

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scans for weak authentication mechanisms."""
        try:
            res = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            headers = {k.lower(): v for k, v in res.headers.items()}
            body = res.text.lower()

            # Check 1: Missing HTTP-only flag on cookies
            set_cookie = headers.get('set-cookie', '')
            if set_cookie:
                if 'httponly' not in set_cookie.lower():
                    return self._make_finding(
                        vuln_type="Weak Cookie Configuration",
                        severity="Medium",
                        description="Cookie missing HttpOnly flag - vulnerable to XSS attacks",
                        evidence=f"Set-Cookie header: {set_cookie[:50]}... (no HttpOnly)",
                        url=url
                    )
                
                # Check for missing Secure flag (if HTTPS URL)
                if 'secure' not in set_cookie.lower() and url.startswith('https'):
                    return self._make_finding(
                        vuln_type="Weak Cookie Configuration",
                        severity="Medium",
                        description="HTTPS cookie missing Secure flag",
                        evidence=f"Set-Cookie header: {set_cookie[:50]}... (no Secure)",
                        url=url
                    )

            # Check 2: Look for password reset tokens or sensitive auth tokens in HTML
            token_patterns = [
                r'reset[_\-]?token\s*=\s*["\']?[\w\-]{10,}',
                r'csrf[_\-]?token\s*=\s*["\']?[\w\-]{10,}',
                r'auth[_\-]?token\s*=\s*["\']?[\w\-]{10,}'
            ]
            
            for pattern in token_patterns:
                if re.search(pattern, body, re.IGNORECASE):
                    return self._make_finding(
                        vuln_type="Sensitive Token Exposure",
                        severity="High",
                        description="Authentication tokens found in HTML response",
                        evidence=f"Auth token pattern detected in response",
                        url=url
                    )

            # Check 3: Look for default credentials hints
            default_creds = ['admin/admin', 'test/test', 'default credentials', 'username: admin']
            for cred in default_creds:
                if cred in body:
                    return self._make_finding(
                        vuln_type="Weak Default Credentials",
                        severity="High",
                        description="Indication of default credentials in application",
                        evidence=f"Found: {cred}",
                        url=url
                    )

            return None

        except requests.RequestException:
            return None

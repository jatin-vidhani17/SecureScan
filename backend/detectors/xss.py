import requests
import urllib.parse
from typing import Optional, Dict
from .base import BaseDetector


class XSSDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="XSS Detector", owasp_category="A07")
        self.payload = "<script>alert('XSS_TEST_MARKER')</script>"

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scans a single URL with query parameters for Reflected XSS."""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if not query_params:
            return None

        for param_name, _ in query_params.items():
            test_params = query_params.copy()
            test_params[param_name] = [self.payload]
            
            test_query = urllib.parse.urlencode(test_params, doseq=True)
            test_url = urllib.parse.urlunparse(parsed_url._replace(query=test_query))
            
            try:
                res = requests.get(test_url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
                # If the payload is reflected directly in the HTML without sanitization,
                # it's likely vulnerable to XSS.
                if self.payload in res.text:
                    return self._make_finding(
                        vuln_type="Cross-Site Scripting (XSS)",
                        severity="High",
                        description="User input is reflected in response without proper sanitization",
                        evidence=f"Payload detected in response: {self.payload}",
                        payload=self.payload,
                        parameter=param_name,
                        url=url
                    )
            except requests.RequestException:
                pass

        return None

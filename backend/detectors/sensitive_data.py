import requests
import re
from typing import Optional, Dict

class SensitiveDataDetector:
    def __init__(self):
        # Regular expressions for sensitive data patterns
        self.patterns = {
            "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Indian Phone Number": r"\b[6-9]\d{9}\b",
            "Stripe API Key": r"sk_(live|test)_[0-9a-zA-Z]{24}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}"
        }

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scans a URL's response body for exposed sensitive data."""
        try:
            res = requests.get(url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
            # Avoid scanning huge binaries or non-text files
            if 'text' not in res.headers.get('Content-Type', ''):
                return None

            body = res.text

            for data_type, pattern in self.patterns.items():
                matches = re.finditer(pattern, body)
                exposed_items = []
                for match in matches:
                    exposed_items.append(match.group(0))

                if exposed_items:
                    # Remove duplicates
                    exposed_items = list(set(exposed_items))
                    return {
                        "type": "Sensitive Data Exposure",
                        "url": url,
                        "parameter": "Response Body",
                        "payload": f"Found: {data_type}",
                        "severity": "Medium",
                        "details": f"Exposed data: {', '.join(exposed_items[:3])}" # Show max 3 for brevity
                    }
        except requests.RequestException:
            pass

        return None

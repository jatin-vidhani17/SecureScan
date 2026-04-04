import requests
import urllib.parse
from typing import Optional, Dict

class SQLInjectionDetector:
    def __init__(self):
        self.payloads = [
            "'",
            "\"",
            "' OR '1'='1",
            "1 OR 1=1"
        ]
        self.error_signatures = [
            "mysql error",
            "syntax error",
            "sql error",
            "warning mysql",
            "unclosed quotation mark after the character string"
        ]

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scans a single URL with query parameters for SQL Injection."""
        parsed_url = urllib.parse.urlparse(url)
        query_params = urllib.parse.parse_qs(parsed_url.query)

        if not query_params:
            return None # No parameters to test

        for param_name, _ in query_params.items():
            for payload in self.payloads:
                # Create a modified query testing this parameter
                test_params = query_params.copy()
                # Inject payload (we'll just append it to the first value for simplicity)
                original_value = test_params[param_name][0]
                test_params[param_name] = [original_value + payload]
                
                # Reconstruct URL
                test_query = urllib.parse.urlencode(test_params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed_url._replace(query=test_query))
                
                try:
                    res = requests.get(test_url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
                    body = res.text.lower()
                    
                    # Check for SQL errors in the response body
                    for signature in self.error_signatures:
                        if signature in body:
                            return {
                                "type": "SQL Injection",
                                "url": url,
                                "parameter": param_name,
                                "payload": payload,
                                "severity": "High"
                            }
                except requests.RequestException:
                    pass

        return None

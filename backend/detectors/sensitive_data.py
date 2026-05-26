"""
SensitiveDataDetector — Finds exposed sensitive data in responses.
Maps to OWASP A08 (Integrity Failures) and A04 (Cryptographic Failures).

Improved: Only reports when data is in actual response body (not robots.txt or sitemap).
Filters false positives from minified JavaScript containing random strings.
"""

import requests
import re
from typing import Optional, Dict
from .base import BaseDetector


class SensitiveDataDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="Sensitive Data Detector", owasp_category="A08")
        
        # Regex patterns for sensitive data
        self.patterns = {
            "Email Address": r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}",
            "Indian Phone Number": r"\b[6-9]\d{9}\b",
            "Stripe API Key": r"sk_(live|test)_[0-9a-zA-Z]{24}",
            "AWS Access Key": r"AKIA[0-9A-Z]{16}",
            "Private Key": r"-----BEGIN (RSA|DSA|EC) PRIVATE KEY-----",
            "Password in URL": r"([?&](password|pwd|passwd)=[\w]+)"
        }
        
        # URLs to skip (known false positives)
        self.skip_paths = ["/robots.txt", "/sitemap.xml", ".json"]

    def _is_likely_false_positive(self, content_type: str, body: str) -> bool:
        """
        Filter obvious false positives:
        - Minified JS/CSS with random strings
        - JSON responses with IDs
        - Sitemap/robots.txt files
        """
        # Skip non-text content
        if 'text' not in content_type.lower():
            return True
        
        # Skip if body is too large (likely bundle)
        if len(body) > 1000000:
            return True
        
        # Skip if looks like minified JS (one huge line)
        if body.count('\n') < 5 and len(body) > 50000:
            return True
        
        return False

    def _has_context(self, match_text: str, context: str, match_pos: int) -> bool:
        """
        Check if match has surrounding context that suggests it's real data.
        E.g., "password=value" is real, but "sk_xyzabc123" alone in minified code is noise.
        """
        # For emails, they're usually real if found
        if "@" in match_text:
            return True
        
        # For API keys, check surroundings
        before = context[max(0, match_pos - 50):match_pos]
        after = context[match_pos + len(match_text):match_pos + len(match_text) + 50]
        
        # Real API keys have context like variable names, json keys, etc
        context_words = (before + after).lower()
        if any(word in context_words for word in ["key", "secret", "token", "api", "auth"]):
            return True
        
        return False

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scans for exposed sensitive data with false positive filtering."""
        try:
            # Skip certain paths known to generate false positives
            if any(skip in url for skip in self.skip_paths):
                return None
            
            res = requests.get(
                url, 
                timeout=15, 
                headers={'User-Agent': 'Mozilla/5.0'},
                allow_redirects=True
            )
            
            content_type = res.headers.get('Content-Type', '')
            
            # Skip non-text or huge files
            if self._is_likely_false_positive(content_type, res.text):
                return None

            body = res.text

            # Scan for sensitive patterns
            for data_type, pattern in self.patterns.items():
                matches = list(re.finditer(pattern, body))
                
                if matches:
                    # Filter to only high-confidence matches
                    confident_matches = []
                    for match in matches[:5]:  # Check first 5 matches
                        match_text = match.group(0)
                        if self._has_context(match_text, body, match.start()):
                            confident_matches.append(match_text)
                    
                    if confident_matches:
                        return self._make_finding(
                            vuln_type="Sensitive Data Exposure",
                            severity="High",
                            description=f"Sensitive {data_type} exposed in page response",
                            evidence=f"Found {data_type}: {', '.join(confident_matches[:2])}",
                            parameter="Response Body",
                            url=url
                        )
        
        except requests.RequestException:
            pass

        return None

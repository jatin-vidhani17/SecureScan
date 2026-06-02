"""
Tech stack detection for SecureScan.
Detects common frameworks/platforms based on headers, cookies, and HTML markers.
"""

from typing import Dict, List, Optional
import re
import requests


class TechStackDetector:
    def __init__(self, timeout: int = 10):
        self.timeout = timeout

    def _fetch(self, url: str) -> Optional[requests.Response]:
        try:
            return requests.get(
                url,
                timeout=self.timeout,
                headers={"User-Agent": "SecureScan/1.0"},
                allow_redirects=True,
            )
        except requests.RequestException:
            return None

    def detect(self, base_url: str) -> Dict:
        resp = self._fetch(base_url)
        if resp is None:
            return {
                "primary": "unknown",
                "confidence": 0.0,
                "technologies": [],
                "details": {"error": "Unable to fetch target URL"},
            }

        headers = {k.lower(): v for k, v in resp.headers.items()}
        server = resp.headers.get("Server", "")
        powered_by = resp.headers.get("X-Powered-By", "")
        cookies = resp.headers.get("Set-Cookie", "")
        body = resp.text
        body_lower = body.lower()

        meta_generator = None
        match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', body, re.IGNORECASE)
        if match:
            meta_generator = match.group(1)

        technologies: List[Dict] = []

        def add_tech(slug: str, name: str, confidence: float, evidence: str):
            technologies.append({
                "name": name,
                "slug": slug,
                "confidence": confidence,
                "evidence": evidence,
            })

        # WordPress
        if "wp-content" in body_lower or "wp-includes" in body_lower or (meta_generator and "wordpress" in meta_generator.lower()):
            add_tech("wordpress", "WordPress", 0.95, "WP content markers or generator tag found")

        # Joomla
        if "joomla" in body_lower or (meta_generator and "joomla" in meta_generator.lower()) or "option=com_" in body_lower:
            add_tech("joomla", "Joomla", 0.85, "Joomla generator or option=com_ marker found")

        # Drupal
        if "drupal" in body_lower or (meta_generator and "drupal" in meta_generator.lower()) or "drupal-settings-json" in body_lower:
            add_tech("drupal", "Drupal", 0.85, "Drupal generator or settings marker found")

        # Laravel
        if "laravel_session" in cookies.lower() or "laravel" in powered_by.lower():
            add_tech("laravel", "Laravel", 0.85, "Laravel session cookie or X-Powered-By detected")

        # Django
        if "csrftoken" in cookies.lower() or "csrfmiddlewaretoken" in body_lower:
            add_tech("django", "Django", 0.85, "CSRF token/cookie markers detected")

        # Flask
        if "werkzeug" in server.lower() or "flask" in powered_by.lower():
            add_tech("flask", "Flask", 0.8, "Werkzeug/Flask headers detected")

        # ASP.NET
        if "asp.net" in powered_by.lower() or "asp.net" in server.lower() or "asp.net_sessionid" in cookies.lower():
            add_tech("asp_net", "ASP.NET", 0.9, "ASP.NET headers/cookies detected")

        # Java/JSP
        if "jsessionid" in cookies.lower() or ".jsp" in body_lower:
            add_tech("java", "Java/JSP", 0.8, "JSESSIONID cookie or .jsp markers detected")
        if "spring" in body_lower or "spring" in powered_by.lower() or "x-application-context" in headers:
            add_tech("spring_boot", "Spring Boot", 0.85, "Spring markers or x-application-context header detected")

        # Node.js/Express
        if "express" in powered_by.lower():
            add_tech("express", "Express.js", 0.9, "X-Powered-By: Express detected")
        if "express" in server.lower() or "node" in server.lower():
            add_tech("nodejs", "Node.js", 0.8, "Node/Express server headers detected")

        # PHP
        if "phpsessid" in cookies.lower() or "php" in server.lower():
            add_tech("php", "PHP", 0.7, "PHPSESSID cookie or PHP server header detected")

        # React
        if "data-reactroot" in body_lower or "<div id=\"root\">" in body_lower:
            add_tech("react", "React", 0.8, "React root markers detected")

        # Vue
        if "data-v-" in body_lower or "__vue" in body_lower:
            add_tech("vue", "Vue.js", 0.8, "Vue markers detected")

        # Angular
        if "ng-version" in body_lower or "ng-app" in body_lower:
            add_tech("angular", "Angular", 0.8, "Angular markers detected")

        # Select primary tech by highest confidence
        primary = "unknown"
        confidence = 0.0
        for tech in technologies:
            if tech["confidence"] > confidence:
                primary = tech["slug"]
                confidence = tech["confidence"]

        return {
            "primary": primary,
            "confidence": confidence,
            "technologies": technologies,
            "details": {
                "server": server,
                "powered_by": powered_by,
                "cookies": cookies[:200],
                "meta_generator": meta_generator,
            },
        }

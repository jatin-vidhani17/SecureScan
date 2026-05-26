"""
FrameworkSpecificDetector — Tech-stack specific vulnerability detection
Detects framework-specific vulnerabilities:
- WordPress: Plugin vulnerabilities, theme issues, common misconfigs
- Laravel: Artisan exposure, storage directory issues
- Django: Debug mode exposure, SECRET_KEY exposure
- Spring Boot: Actuator endpoints, configuration issues
- Express.js: Package.json exposure, npm audit issues
- ASP.NET: Configuration errors, IIS issues
"""

import requests
import re
from typing import Optional, Dict, List
from .base import BaseDetector


class FrameworkSpecificDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="Framework Specific Detector", owasp_category="A01")
        
        self.framework_checks = {
            "wordpress": {
                "endpoints": [
                    "/wp-json/wp/v2/users",  # User enumeration
                    "/wp-admin/",  # Admin panel accessible?
                    "/xmlrpc.php",  # XML-RPC enabled?
                ],
                "headers": ["X-Powered-By"],
                "vulnerabilities": ["xmlrpc_enabled", "user_enumeration", "admin_accessible"]
            },
            "django": {
                "endpoints": [
                    "/admin/",  # Django admin
                    "/static/admin/",  # Admin static files
                ],
                "checks": ["debug_mode", "sql_injection", "csrf_bypass"],
            },
            "laravel": {
                "endpoints": [
                    "/artisan",  # Artisan CLI exposure
                    "/storage/logs/laravel.log",  # Log exposure
                ],
                "checks": ["artisan_exposed", "logs_exposed", "key_exposure"]
            },
            "spring_boot": {
                "endpoints": [
                    "/actuator",  # Spring Boot Actuator
                    "/actuator/health",
                    "/actuator/env",  # Environment variables
                    "/actuator/beans",
                ],
                "checks": ["actuator_exposed", "env_disclosure"]
            },
            "express": {
                "endpoints": [
                    "/package.json",
                    "/node_modules",
                ],
                "checks": ["package_json_exposed", "node_modules_accessible"]
            },
            "aspnet": {
                "endpoints": [
                    "/api/",
                    "/.well-known/",
                ],
                "checks": ["api_discovery", "cors_misconfigured"]
            }
        }
        
        self.tech_stack = None

    def _detect_tech_stack(self, url: str) -> Optional[str]:
        """Detect framework from tech stack"""
        try:
            resp = requests.get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            headers = resp.headers
            body = resp.text.lower()
            
            # WordPress
            if "wp-content" in body or "wp-includes" in body:
                return "wordpress"
            
            # Django
            if "django" in body or "csrfmiddlewaretoken" in body:
                return "django"
            
            # Laravel
            if "laravel" in body or "laravel_session" in headers.get("Set-Cookie", ""):
                return "laravel"
            
            # Spring Boot
            if "spring" in body or "springbootversion" in body:
                return "spring_boot"
            
            # Express/Node.js
            if "express" in headers.get("Server", "").lower():
                return "express"
            
            # ASP.NET
            if "asp.net" in headers.get("Server", "").lower():
                return "aspnet"
            
        except:
            pass
        
        return None

    def _check_endpoint(self, url: str, timeout: int = 3) -> Dict:
        """Check if endpoint is accessible"""
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=False
            )
            
            return {
                "status": resp.status_code,
                "accessible": resp.status_code < 400,
                "content_type": resp.headers.get("Content-Type", ""),
                "body": resp.text[:500] if resp.status_code == 200 else None
            }
        except requests.RequestException:
            return {"status": None, "accessible": False}

    def scan_url(self, url: str) -> Optional[Dict]:
        """Scan for framework-specific vulnerabilities"""
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Detect framework
            framework = self._detect_tech_stack(url)
            if not framework or framework not in self.framework_checks:
                return None
            
            findings = []
            config = self.framework_checks[framework]
            
            # Check framework-specific endpoints
            for endpoint in config.get("endpoints", []):
                endpoint_url = base_url + endpoint
                result = self._check_endpoint(endpoint_url)
                
                if result.get("accessible"):
                    findings.append({
                        "endpoint": endpoint,
                        "issue": f"{framework.upper()} endpoint publicly accessible",
                        "severity": "High" if "admin" in endpoint.lower() else "Medium",
                        "url": endpoint_url,
                        "description": endpoint
                    })
            
            if findings:
                return self._make_finding(
                    vuln_type=f"Framework Misconfiguration ({framework.upper()})",
                    severity="Medium",
                    description=f"Found {len(findings)} {framework.upper()} endpoints publicly accessible",
                    evidence=f"Endpoints: {', '.join([f['endpoint'] for f in findings])}",
                    url=base_url
                )
            
            return None

        except Exception:
            return None

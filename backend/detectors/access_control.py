"""
AccessControlDetector — Tech-stack aware broken access control detection.
Maps to OWASP A01 with intelligent detection for:
- WordPress (wp-config.php, theme/plugin files)
- PHP (config.php, database files, Laravel/Symfony configs)
- JSP/Java (web.xml, Spring Boot properties, JNDI configs)
- Python/Django (settings.py, requirements.txt, env files)
- Node.js (package.json, .env, config files)
- React/Vue/Angular SPAs (skip, user routes are legitimate)

Each platform has tech-specific vulnerable paths and validation.
"""

import requests
import re
from typing import Optional, Dict, List
from .base import BaseDetector


class AccessControlDetector(BaseDetector):
    def __init__(self):
        super().__init__(name="Access Control Detector", owasp_category="A01")
        self.tech_stack = None
        
        # Tech-stack specific vulnerable paths
        self.tech_paths = {
            "wordpress": {
                "paths": ["/wp-config.php", "/wp-config.php.bak", "/wp-config.php.swp"],
                "patterns": [r"define\s*\(\s*['\"]DB_", r"WORDPRESS_CONFIG"],
                "severity": "High"
            },
            "joomla": {
                "paths": ["/configuration.php", "/administrator/", "/administrator/index.php"],
                "patterns": [r"\$dbtype", r"\$dbuser", r"\$password"],
                "severity": "High"
            },
            "drupal": {
                "paths": ["/sites/default/settings.php", "/user/login", "/core/install.php"],
                "patterns": [r"\$databases", r"\$settings", r"drupal"],
                "severity": "High"
            },
            "php": {
                "paths": ["/config.php", "/config/database.php", "/includes/config.php", 
                         "/config/config.php", "/api/config.php"],
                "patterns": [r"\$_?[A-Z_]+(HOST|USER|PASS|DB)", r"mysql_connect|mysqli", 
                            r"PDO\s*\("],
                "severity": "High"
            },
            "laravel": {
                "paths": ["/.env", "/.env.local", "/storage/logs/laravel.log"],
                "patterns": [r"APP_KEY=", r"DB_PASSWORD=", r"MAIL_PASSWORD="],
                "severity": "Critical"
            },
            "django": {
                "paths": ["/settings.py", "/wsgi.py", "/requirements.txt"],
                "patterns": [r"SECRET_KEY\s*=", r"DATABASES\s*=", r"DEBUG\s*="],
                "severity": "High"
            },
            "flask": {
                "paths": ["/config.py", "/instance/config.py", "/requirements.txt"],
                "patterns": [r"SECRET_KEY\s*=", r"SQLALCHEMY_DATABASE_URI", r"DEBUG\s*="],
                "severity": "High"
            },
            "java": {
                "paths": ["/WEB-INF/web.xml", "/META-INF/MANIFEST.MF", 
                         "/application.properties", "/application.yml"],
                "patterns": [r"<servlet|<filter|spring\.jndi|java\.naming"],
                "severity": "High"
            },
            "nodejs": {
                "paths": ["/.env", "/package.json", "/config.js", "/config/default.json"],
                "patterns": [r"apiKey|secretKey|password|token", r"\"main\"|\"scripts\""],
                "severity": "High"
            },
            "asp_net": {
                "paths": ["/web.config", "/appsettings.json", "/web.config.bak"],
                "patterns": [r"<connectionStrings|<appSettings|machineKey"],
                "severity": "High"
            },
        }

    def _detect_tech_stack(self, response_sample: requests.Response) -> Dict[str, str]:
        """
        Detect target technology stack from headers, content, and requests.
        Returns: {"stack": "wordpress|php|django|java|nodejs|aspnet|react", ...}
        """
        headers = response_sample.headers
        body = response_sample.text.lower()
        
        result = {"stack": "unknown", "confidence": 0, "details": {}}
        
        # WordPress detection
        if "wp-content" in body or "wp-includes" in body or "WordPress" in response_sample.text:
            result["stack"] = "wordpress"
            result["confidence"] = 0.9
            return result
        
        # Django detection
        if "django" in body or "csrfmiddlewaretoken" in body:
            result["stack"] = "django"
            result["confidence"] = 0.9
            return result
        
        # Laravel detection
        if "laravel" in body or "laravel_session" in headers.get("Set-Cookie", ""):
            result["stack"] = "php"  # PHP with Laravel
            result["confidence"] = 0.85
            result["details"]["framework"] = "laravel"
            return result
        
        # React/Vue/Angular SPA detection
        if "<div id=\"root\">" in response_sample.text or "<div id=\"app\">" in response_sample.text:
            result["stack"] = "react"
            result["confidence"] = 0.95
            return result
        
        if "vue" in body or "__vue" in body:
            result["stack"] = "vue"
            result["confidence"] = 0.85
            return result
        
        if "angular" in body or "ng-app" in body:
            result["stack"] = "angular"
            result["confidence"] = 0.85
            return result
        
        # Java/JSP detection
        if ".jsp" in body or "jsessionid" in headers.get("Set-Cookie", ""):
            result["stack"] = "java"
            result["confidence"] = 0.9
            return result
        
        if "spring" in body or "springbootversion" in body:
            result["stack"] = "java"
            result["details"]["framework"] = "spring_boot"
            result["confidence"] = 0.9
            return result
        
        # Python detection (non-Django)
        if "python" in headers.get("Server", "").lower():
            result["stack"] = "python"
            result["confidence"] = 0.8
            return result
        
        # ASP.NET detection
        if "asp.net" in headers.get("Server", "").lower() or ".aspx" in body:
            result["stack"] = "asp_net"
            result["confidence"] = 0.9
            return result
        
        # Node.js/Express detection
        if "express" in headers.get("Server", "").lower() or "node" in headers.get("Server", "").lower():
            result["stack"] = "nodejs"
            result["confidence"] = 0.9
            return result
        
        # Generic PHP detection
        if "php" in headers.get("Server", "").lower() or ".php" in body or "php" in body[:200]:
            result["stack"] = "php"
            result["confidence"] = 0.7
            return result
        
        return result

    def _check_file_exists(self, url: str, timeout: int = 3) -> Optional[Dict]:
        """Check if file exists and return response details"""
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                headers={"User-Agent": "Mozilla/5.0"},
                allow_redirects=False
            )
            
            if resp.status_code == 200:
                return {
                    "status": 200,
                    "content_length": len(resp.text),
                    "content": resp.text,
                    "content_type": resp.headers.get("Content-Type", "")
                }
            elif resp.status_code in [301, 302, 307]:
                return {
                    "status": resp.status_code,
                    "location": resp.headers.get("Location")
                }
            elif resp.status_code == 403:
                return {"status": 403}
            
        except requests.RequestException:
            pass
        
        return None

    def _validate_finding(self, file_path: str, response_content: str, patterns: List[str]) -> bool:
        """Validate that response contains actual vulnerable content (not false positive)"""
        if not response_content or len(response_content) < 10:
            return False
        
        # Check if any pattern matches
        for pattern in patterns:
            if re.search(pattern, response_content, re.IGNORECASE):
                return True
        
        return False

    def scan_url(self, url: str) -> Optional[Dict]:
        """
        Scan for broken access control using tech-stack aware detection.
        """
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            
            # Detect tech stack
            if self.tech_stack is None:
                context_stack = (self.context.get("tech_stack") or {}) if hasattr(self, "context") else {}
                stack_hint = context_stack.get("primary")
                if stack_hint and stack_hint != "unknown":
                    stack_map = {"express": "nodejs"}
                    self.tech_stack = {
                        "stack": stack_map.get(stack_hint, stack_hint),
                        "confidence": context_stack.get("confidence", 0.0)
                    }
                else:
                    try:
                        sample_resp = requests.get(url, timeout=5)
                        self.tech_stack = self._detect_tech_stack(sample_resp)
                    except requests.RequestException:
                        self.tech_stack = {"stack": "unknown"}
            
            tech_stack = self.tech_stack.get("stack", "unknown")
            
            # Skip SPA sites - user routes are legitimate
            if tech_stack in ["react", "vue", "angular"]:
                return None
            
            findings = []
            
            # Get tech-specific paths to test
            if tech_stack in self.tech_paths:
                tech_config = self.tech_paths[tech_stack]
                paths = tech_config["paths"]
                patterns = tech_config["patterns"]
                
                # Test each path
                for path in paths:
                    probe_url = base_url + path
                    response = self._check_file_exists(probe_url)
                    
                    if response and response.get("status") == 200:
                        # Validate it's actual sensitive content
                        if self._validate_finding(path, response.get("content", ""), patterns):
                            findings.append({
                                "path": path,
                                "url": probe_url,
                                "type": f"Exposed {tech_stack.upper()} Configuration",
                                "content_snippet": response.get("content", "")[:200]
                            })
            
            # Universal checks (all tech stacks)
            # Check for directory listing
            try:
                resp = requests.get(
                    base_url + "/",
                    timeout=3,
                    headers={"User-Agent": "Mozilla/5.0"}
                )
                body_lower = resp.text.lower()
                
                if "index of" in body_lower and ("<pre>" in body_lower or "<table>" in body_lower):
                    findings.append({
                        "path": "/",
                        "type": "Directory Listing Enabled",
                        "url": base_url + "/"
                    })
            except:
                pass
            
            # Report findings if any
            if findings:
                return self._make_finding(
                    vuln_type="Broken Access Control",
                    severity="High",
                    description=f"Found {len(findings)} exposed file(s) - {tech_stack.upper()} stack",
                    evidence=f"Tech: {tech_stack} | Files: {', '.join([f['path'] for f in findings])}",
                    url=base_url
                )
            
            return None

        except Exception:
            return None

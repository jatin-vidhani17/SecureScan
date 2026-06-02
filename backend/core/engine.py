"""
SecureScan Engine — Orchestrates the full scan pipeline:
  1. Tech stack detection
  2. Crawl target website
  3. Collect HTTP responses for all discovered URLs
  4. Run all vulnerability detectors
  5. Run 10 OWASP Top 10 tests against collected data
  6. Calculate security score and grade
  7. Persist everything to the database
"""

import concurrent.futures
import json
import requests
from typing import List, Dict, Any

from crawler.crawler import Crawler
from core.owasp_tests import run_all_owasp_tests
from core.scoring import calculate_score
from core.techstack import TechStackDetector

from detectors.access_control import AccessControlDetector
from detectors.sqli import SQLInjectionDetector
from detectors.xss import XSSDetector
from detectors.sensitive_data import SensitiveDataDetector
from detectors.security_headers import SecurityHeaderDetector
from detectors.cors import CORSDetector
from detectors.authentication import AuthenticationDetector
from detectors.framework_specific import FrameworkSpecificDetector

from database import (
    create_scan, complete_scan, save_pages,
    save_vulnerabilities, save_owasp_results,
    update_scan_score, save_log, update_scan_tech_stack
)

# Global scan tracking for cancellation support
RUNNING_SCANS = {}


class ScannerEngine:
    def __init__(self, target_url: str, max_depth: int = 2):
        self.target_url = target_url
        self.max_depth = max_depth
        self.crawler = Crawler(target_url, max_depth=self.max_depth)
        self.tech_stack_info: Dict[str, Any] = {}
        self.cancel_requested = False
        self.scan_id = None
        
        # Initialize all detectors
        self.detectors = [
            AccessControlDetector(),      # Tech-stack aware: WordPress, PHP, Django, Java, Node.js, ASP.NET, React
            FrameworkSpecificDetector(),  # Framework-specific vulnerabilities
            SQLInjectionDetector(),
            XSSDetector(),
            SensitiveDataDetector(),
            SecurityHeaderDetector(),     # Only critical headers
            CORSDetector(),
            AuthenticationDetector()
        ]

    def _fetch_responses(self, urls: List[str], log=None) -> Dict[str, requests.Response]:
        """Fetch HTTP responses for all crawled URLs (used by OWASP tests)."""
        responses = {}

        def fetch_one(url):
            try:
                resp = requests.get(
                    url, timeout=15,
                    headers={"User-Agent": "SecureScan/1.0"},
                    allow_redirects=True
                )
                return url, resp
            except requests.RequestException:
                return url, None

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            futures = {executor.submit(fetch_one, url): url for url in urls}
            for future in concurrent.futures.as_completed(futures):
                url, resp = future.result()
                responses[url] = resp

        if log:
            log(f"Fetched responses for {len(responses)} URLs.")
        return responses

    def _run_detectors(self, urls: List[str], log=None) -> List[Dict[str, Any]]:
        """Run all vulnerability detectors on each URL."""
        detector_findings = []

        engine_log = log or (lambda msg: print(msg))
        engine_log("=" * 50)
        engine_log("Running Vulnerability Detectors...")
        engine_log("=" * 50)

        for detector in self.detectors:
            if self.cancel_requested:
                engine_log("Scan cancelled - stopping detectors")
                break
            engine_log(f"\n[Detector] Running {detector.name}...")
            findings_count = 0
            
            for url in urls:
                if self.cancel_requested:
                    engine_log("Scan cancelled - stopping detector")
                    break
                try:
                    finding = detector.scan_url(url)
                    if finding:
                        detector_findings.append(finding)
                        findings_count += 1
                        engine_log(f"  ✓ Found: {finding['type']} in {url}")
                except Exception as e:
                    engine_log(f"  ✗ Error scanning {url}: {str(e)}")

            engine_log(f"  {detector.name} completed - {findings_count} findings")

        engine_log(f"\nTotal findings from detectors: {len(detector_findings)}")
        return detector_findings

    def run(self) -> Dict[str, Any]:
        self.scan_id = create_scan(self.target_url)
        RUNNING_SCANS[self.target_url] = self

        def engine_log(msg):
            print(msg)
            save_log(self.scan_id, msg)

        try:
            engine_log(f"--- Starting Scan for {self.target_url} ---")

            # ── Step 0: Detect tech stack ──
            if self.cancel_requested:
                raise Exception("Scan cancelled by user")
            engine_log("Detecting target tech stack...")
            tech_detector = TechStackDetector()
            try:
                self.tech_stack_info = tech_detector.detect(self.target_url)
                update_scan_tech_stack(
                    self.scan_id,
                    self.tech_stack_info.get("primary", "unknown"),
                    self.tech_stack_info.get("confidence", 0.0),
                    json.dumps(self.tech_stack_info)
                )
                engine_log(
                    f"Tech stack detected: {self.tech_stack_info.get('primary', 'unknown')} "
                    f"(confidence {self.tech_stack_info.get('confidence', 0.0):.2f})"
                )
            except Exception as exc:
                engine_log(f"Tech stack detection failed: {exc}")
                self.tech_stack_info = {"primary": "unknown", "confidence": 0.0, "technologies": []}

            # Attach log callback to crawler
            self.crawler.log_callback = engine_log
            self.crawler.cancel_requested = self

            # ── Step 1: Crawling ──
            if self.cancel_requested:
                raise Exception("Scan cancelled by user")
            engine_log("Initializing Crawler...")
            discovered_urls = self.crawler.crawl()
            save_pages(self.scan_id, discovered_urls)
            engine_log(f"Discovered {len(discovered_urls)} URLs to scan.")

            # ── Step 2: Fetch all responses ──
            if self.cancel_requested:
                raise Exception("Scan cancelled by user")
            engine_log("Fetching HTTP responses for analysis...")
            responses = self._fetch_responses(discovered_urls, log=engine_log)

            # ── Step 3: Run all vulnerability detectors ──
            if self.cancel_requested:
                raise Exception("Scan cancelled by user")
            for detector in self.detectors:
                if hasattr(detector, "set_context"):
                    detector.set_context({"tech_stack": self.tech_stack_info})
            detector_findings = self._run_detectors(discovered_urls, log=engine_log)

            # ── Step 4: Run OWASP Top 10 Tests ──
            if self.cancel_requested:
                raise Exception("Scan cancelled by user")
            engine_log("=" * 50)
            engine_log("Running OWASP Top 10 Security Tests...")
            engine_log("=" * 50)
            owasp_results = run_all_owasp_tests(
                self.target_url, discovered_urls, responses, log=engine_log
            )

            # ── Step 5: Calculate Score ──
            engine_log("Calculating security score...")
            score_data = calculate_score(owasp_results)
            engine_log(f"  Score: {score_data['score']}/100")
            engine_log(f"  Grade: {score_data['grade']}")
            engine_log(f"  Tests Passed: {score_data['tests_passed']}/{score_data['tests_total']}")

            # ── Step 6: Collect raw vulnerabilities (merge detector findings + OWASP findings) ──
            all_vulnerabilities = []
            
            # Add detector findings
            for finding in detector_findings:
                all_vulnerabilities.append({
                    "type": finding.get("type", "Unknown"),
                    "url": finding.get("url", self.target_url),
                    "parameter": finding.get("parameter", ""),
                    "payload": finding.get("payload", ""),
                    "severity": finding.get("severity", "Medium"),
                    "details": finding.get("evidence", finding.get("description", "")),
                    "owasp_category": finding.get("owasp_category", "")
                })
            
            # Add OWASP findings
            for result in owasp_results:
                if result["status"] == "fail":
                    for finding in result.get("findings", []):
                        all_vulnerabilities.append({
                            "type": finding.get("issue", result["owasp_name"]),
                            "url": finding.get("url", self.target_url),
                            "parameter": finding.get("parameter", ""),
                            "payload": finding.get("payload", finding.get("evidence", "")),
                            "severity": result.get("severity", "Medium"),
                            "details": finding.get("evidence", ""),
                            "owasp_category": result["owasp_id"]
                        })

            # ── Step 7: Save everything ──
            engine_log("Saving OWASP results and vulnerabilities...")
            save_owasp_results(self.scan_id, owasp_results)
            save_vulnerabilities(self.scan_id, all_vulnerabilities)
            update_scan_score(
                self.scan_id,
                score_data["score"],
                score_data["grade"],
                score_data["tests_passed"],
                score_data["tests_total"]
            )
            complete_scan(self.scan_id)

            engine_log(f"--- Scan Completed. Found {len(all_vulnerabilities)} issues across {score_data['tests_total']} OWASP tests! ---")

            return {
                "target": self.target_url,
                "scanned_urls_count": len(discovered_urls),
                "score": score_data["score"],
                "grade": score_data["grade"],
                "tests_passed": score_data["tests_passed"],
                "tests_total": score_data["tests_total"],
                "tech_stack": self.tech_stack_info.get("primary", "unknown"),
                "tech_stack_details": self.tech_stack_info,
                "owasp_results": owasp_results,
                "vulnerabilities": all_vulnerabilities
            }
        except Exception as e:
            engine_log(f"Scan error: {str(e)}")
            if "cancelled" in str(e).lower():
                from database import cancel_scan
                cancel_scan(self.scan_id)
                engine_log("Scan cancelled and saved to database.")
            else:
                from database import mark_scan_error
                mark_scan_error(self.scan_id, str(e))
            raise
        finally:
            if self.target_url in RUNNING_SCANS:
                del RUNNING_SCANS[self.target_url]

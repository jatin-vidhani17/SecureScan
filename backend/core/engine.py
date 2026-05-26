"""
SecureScan Engine — Orchestrates the full scan pipeline:
  1. Crawl target website
  2. Collect HTTP responses for all discovered URLs
  3. Run all vulnerability detectors
  4. Run 10 OWASP Top 10 tests against collected data
  5. Calculate security score and grade
  6. Persist everything to the database
"""

import concurrent.futures
import requests
from typing import List, Dict, Any

from crawler.crawler import Crawler
from core.owasp_tests import run_all_owasp_tests
from core.scoring import calculate_score

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
    update_scan_score, save_log
)


class ScannerEngine:
    def __init__(self, target_url: str, max_depth: int = 2):
        self.target_url = target_url
        self.max_depth = max_depth
        self.crawler = Crawler(target_url, max_depth=self.max_depth)
        
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
            engine_log(f"\n[Detector] Running {detector.name}...")
            findings_count = 0
            
            for url in urls:
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
        scan_id = create_scan(self.target_url)

        def engine_log(msg):
            print(msg)
            save_log(scan_id, msg)

        engine_log(f"--- Starting Scan for {self.target_url} ---")

        # Attach log callback to crawler
        self.crawler.log_callback = engine_log

        # ── Step 1: Crawling ──
        engine_log("Initializing Crawler...")
        discovered_urls = self.crawler.crawl()
        save_pages(scan_id, discovered_urls)
        engine_log(f"Discovered {len(discovered_urls)} URLs to scan.")

        # ── Step 2: Fetch all responses ──
        engine_log("Fetching HTTP responses for analysis...")
        responses = self._fetch_responses(discovered_urls, log=engine_log)

        # ── Step 3: Run all vulnerability detectors ──
        detector_findings = self._run_detectors(discovered_urls, log=engine_log)

        # ── Step 4: Run OWASP Top 10 Tests ──
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
        save_owasp_results(scan_id, owasp_results)
        save_vulnerabilities(scan_id, all_vulnerabilities)
        update_scan_score(
            scan_id,
            score_data["score"],
            score_data["grade"],
            score_data["tests_passed"],
            score_data["tests_total"]
        )
        complete_scan(scan_id)

        engine_log(f"--- Scan Completed. Found {len(all_vulnerabilities)} issues across {score_data['tests_total']} OWASP tests! ---")

        return {
            "target": self.target_url,
            "scanned_urls_count": len(discovered_urls),
            "score": score_data["score"],
            "grade": score_data["grade"],
            "tests_passed": score_data["tests_passed"],
            "tests_total": score_data["tests_total"],
            "owasp_results": owasp_results,
            "vulnerabilities": all_vulnerabilities
        }

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
            engine_log(f"\n[Detector] Running {detector.name}...")
            findings_count = 0
            
            for url in urls:
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
        scan_id = create_scan(self.target_url)

        def engine_log(msg):
            print(msg)
            save_log(scan_id, msg)

        engine_log(f"--- Starting Scan for {self.target_url} ---")

        # Attach log callback to crawler
        self.crawler.log_callback = engine_log

        # ── Step 1: Crawling ──
        engine_log("Initializing Crawler...")
        discovered_urls = self.crawler.crawl()
        save_pages(scan_id, discovered_urls)
        engine_log(f"Discovered {len(discovered_urls)} URLs to scan.")

        # ── Step 2: Fetch all responses ──
        engine_log("Fetching HTTP responses for analysis...")
        responses = self._fetch_responses(discovered_urls, log=engine_log)

        # ── Step 3: Run all vulnerability detectors ──
        detector_findings = self._run_detectors(discovered_urls, log=engine_log)

        # ── Step 4: Run OWASP Top 10 Tests ──
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
        save_owasp_results(scan_id, owasp_results)
        save_vulnerabilities(scan_id, all_vulnerabilities)
        update_scan_score(
            scan_id,
            score_data["score"],
            score_data["grade"],
            score_data["tests_passed"],
            score_data["tests_total"]
        )
        complete_scan(scan_id)

        engine_log(f"--- Scan Completed. Found {len(all_vulnerabilities)} issues across {score_data['tests_total']} OWASP tests! ---")

        return {
            "target": self.target_url,
            "scanned_urls_count": len(discovered_urls),
            "score": score_data["score"],
            "grade": score_data["grade"],
            "tests_passed": score_data["tests_passed"],
            "tests_total": score_data["tests_total"],
            "owasp_results": owasp_results,
            "vulnerabilities": all_vulnerabilities
        }

import concurrent.futures
from typing import List, Dict, Any

from crawler.crawler import Crawler
from detectors.sqli import SQLInjectionDetector
from detectors.xss import XSSDetector
from detectors.sensitive_data import SensitiveDataDetector

from database import create_scan, complete_scan, save_pages, save_vulnerabilities

class ScannerEngine:
    def __init__(self, target_url: str, max_depth: int = 2):
        self.target_url = target_url
        self.max_depth = max_depth
        self.crawler = Crawler(target_url, max_depth=self.max_depth)
        
        self.sqli_detector = SQLInjectionDetector()
        self.xss_detector = XSSDetector()
        self.sensitive_data_detector = SensitiveDataDetector()

    def _scan_single_url(self, url: str) -> List[Dict[str, Any]]:
        url_findings = []
        
        # 1. SQL Injection 
        sqli_result = self.sqli_detector.scan_url(url)
        if sqli_result:
            url_findings.append(sqli_result)

        # 2. XSS
        xss_result = self.xss_detector.scan_url(url)
        if xss_result:
            url_findings.append(xss_result)

        # 3. Sensitive Data
        sensitive_data_result = self.sensitive_data_detector.scan_url(url)
        if sensitive_data_result:
            url_findings.append(sensitive_data_result)
            
        return url_findings

    def run(self) -> Dict[str, Any]:
        print(f"--- Starting Scan for {self.target_url} ---")
        scan_id = create_scan(self.target_url)

        # Step 1: Crawling
        discovered_urls = self.crawler.crawl()
        save_pages(scan_id, discovered_urls)
        print(f"Discovered {len(discovered_urls)} URLs to scan.")

        # Step 2: Running Detectors Concurrently
        all_vulnerabilities = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            future_to_url = {executor.submit(self._scan_single_url, url): url for url in discovered_urls}
            
            for future in concurrent.futures.as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    findings = future.result()
                    all_vulnerabilities.extend(findings)
                except Exception as exc:
                    print(f'{url} generated an exception: {exc}')

        # Step 3: Save and complete
        save_vulnerabilities(scan_id, all_vulnerabilities)
        complete_scan(scan_id)

        print(f"--- Scan Completed ---")
        return {
            "target": self.target_url,
            "scanned_urls_count": len(discovered_urls),
            "vulnerabilities": all_vulnerabilities
        }

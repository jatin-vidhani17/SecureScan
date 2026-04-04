import sys
import logging
logging.basicConfig(level=logging.DEBUG)

sys.path.append("backend")
from crawler.crawler import Crawler
from detectors.sqli import SQLInjectionDetector

print("Starting deep crawler debug...")
crawler = Crawler("http://testphp.vulnweb.com", max_depth=1)
links = crawler.crawl()
print(f"Found {len(links)} links. Sample: {links[:5]}")

detector = SQLInjectionDetector()
vulns = []
for link in links:
    v = detector.scan_url(link)
    if v:
        vulns.append(v)

print(f"Found {len(vulns)} SQLi vulnerabilities:", vulns)

import sys
sys.path.append("backend")
from crawler.crawler import Crawler

print("Starting crawler test...")
crawler = Crawler("http://testphp.vulnweb.com", max_depth=1)
links = crawler.crawl()
print("Found links:", len(links))
for link in links:
    print(link)

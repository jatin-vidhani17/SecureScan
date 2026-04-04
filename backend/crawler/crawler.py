import urllib.parse
import requests
from bs4 import BeautifulSoup
from typing import Set, List

class Crawler:
    def __init__(self, target_url: str, max_depth: int = 3, log_callback=None):
        self.target_url = target_url
        self.max_depth = max_depth
        self.visited: Set[str] = set()
        self.to_visit: List[tuple[str, int]] = [(target_url, 0)]
        self.base_domain = urllib.parse.urlparse(target_url).netloc
        self.log_callback = log_callback

    def log(self, msg: str):
        print(msg)
        if self.log_callback:
            self.log_callback(msg)

    def crawl(self) -> List[str]:
        """Crawls the target site and returns a list of discovered URLs within the same domain."""
        self.log(f"Starting crawl for {self.target_url} up to depth {self.max_depth}")
        while self.to_visit:
            current_url, current_depth = self.to_visit.pop(0)

            if current_depth > self.max_depth:
                continue

            if current_url in self.visited:
                continue

            self.visited.add(current_url)

            try:
                response = requests.get(current_url, timeout=15, headers={'User-Agent': 'Mozilla/5.0'})
                if 'text/html' not in response.headers.get('Content-Type', ''):
                    continue

                soup = BeautifulSoup(response.text, 'html.parser')
                self.log(f"[{current_depth}] Crawled_OK: {current_url}")

                for tag in soup.find_all('a', href=True):
                    href = tag.get('href')
                    next_url = urllib.parse.urljoin(current_url, href)
                    
                    # Stay within the same domain
                    parsed_next = urllib.parse.urlparse(next_url)
                    if parsed_next.netloc == self.base_domain:
                        # Strip fragments
                        next_url = next_url.split('#')[0]
                        if next_url not in self.visited:
                            self.to_visit.append((next_url, current_depth + 1))
            except requests.RequestException as e:
                self.log(f"Failed to fetch {current_url}: {e}")

        return list(self.visited)

if __name__ == "__main__":
    # Test the crawler
    crawler = Crawler("http://testphp.vulnweb.com", max_depth=1)
    links = crawler.crawl()
    print(f"Found {len(links)} links.")

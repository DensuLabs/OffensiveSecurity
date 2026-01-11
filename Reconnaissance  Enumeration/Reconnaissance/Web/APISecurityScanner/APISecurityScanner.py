import httpx
import asyncio
import json
import logging
import urllib.parse
from datetime import datetime
from typing import List, Dict, Any

# Setup structured logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class APISecurityScanner:
    def __init__(self, base_url: str, headers: Dict = None):
        self.base_url = base_url.rstrip('/')
        self.headers = headers or {}
        self.found_vulnerabilities = []

    async def _make_request(self, method: str, endpoint: str, **kwargs) -> httpx.Response:
        """Centralized async request handler."""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        async with httpx.AsyncClient(headers=self.headers, timeout=10.0) as client:
            try:
                return await client.request(method, url, **kwargs)
            except httpx.RequestError as e:
                logger.error(f"Request failed for {url}: {e}")
                return None

    def _log_vuln(self, v_type: str, desc: str, endpoint: str, severity: str = "Medium"):
        """Standardized vulnerability logging."""
        vuln = {
            'timestamp': datetime.now().isoformat(),
            'type': v_type,
            'severity': severity,
            'description': desc,
            'endpoint': endpoint
        }
        self.found_vulnerabilities.append(vuln)
        logger.warning(f"[!] {v_type} detected at {endpoint}")

    # --- Test Modules ---

    async def test_auth_bypass(self, endpoint: str):
        """Checks if sensitive endpoints are exposed without tokens."""
        # Test 1: No Auth
        resp = await self._make_request("GET", endpoint, headers={})
        if resp and resp.status_code == 200:
            self._log_vuln("Broken Authentication", "Endpoint accessible without credentials", endpoint, "High")

    async def test_idor(self, endpoint: str):
        """Tests for Insecure Direct Object References (IDOR)."""
        # 
        parts = endpoint.split('/')
        for i, part in enumerate(parts):
            if part.isdigit() or len(part) > 30: # Check for digits or potential UUIDs
                for test_id in ['0', '1', '999', '-1']:
                    test_path = '/'.join(parts[:i] + [test_id] + parts[i+1:])
                    resp = await self._make_request("GET", test_path)
                    if resp and resp.status_code == 200:
                        self._log_vuln("IDOR", f"Access granted using ID: {test_id}", test_path, "High")

    async def test_rate_limiting(self, endpoint: str):
        """Tests if the API enforces rate limits."""
        # 
        tasks = [self._make_request("GET", endpoint) for _ in range(20)]
        responses = await asyncio.gather(*tasks)
        
        status_codes = [r.status_code for r in responses if r]
        if 429 not in status_codes:
            self._log_vuln("Missing Rate Limit", "API does not throttle rapid requests", endpoint, "Low")

    async def run_scan(self, endpoints: List[str]):
        """Runs the full suite of tests concurrently."""
        logger.info(f"[*] Starting async scan on {self.base_url}")
        
        tasks = []
        for ep in endpoints:
            tasks.append(self.test_auth_bypass(ep))
            tasks.append(self.test_idor(ep))
            tasks.append(self.test_rate_limiting(ep))
            # Add other tests here...

        await asyncio.gather(*tasks)
        return self.generate_report()

    def generate_report(self):
        report = {
            'target': self.base_url,
            'scan_summary': {
                'total_found': len(self.found_vulnerabilities),
                'date': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            },
            'findings': self.found_vulnerabilities
        }
        return json.dumps(report, indent=4)
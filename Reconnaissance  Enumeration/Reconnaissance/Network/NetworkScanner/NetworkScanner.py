import nmap
import logging
from typing import List, Dict, Optional

# Configure basic logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

class NetworkScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan_host(self, host: str, ports: str = "1-1000") -> Optional[Dict]:
        """Scan a single host for open ports and return raw results."""
        try:
            return self.nm.scan(host, ports)
        except Exception as e:
            logging.error(f"Error scanning {host}: {e}")
            return None

    def scan_network(self, network: str) -> List[str]:
        """Perform a ping sweep to discover active hosts on a network."""
        try:
            self.nm.scan(hosts=network, arguments='-sn')
            # Use list comprehension for cleaner host extraction
            return [h for h in self.nm.all_hosts() if self.nm[h].state() == 'up']
        except Exception as e:
            logging.error(f"Error scanning network {network}: {e}")
            return []

    def service_detection(self, host: str, ports: str = "1-1000") -> Dict[int, Dict]:
        """Detect services on open TCP ports for a specific host."""
        try:
            self.nm.scan(host, ports, arguments='-sV')
            
            if host not in self.nm.all_hosts():
                logging.warning(f"Host {host} appears to be down or unreachable.")
                return {}

            # Safely navigate the nested dictionary
            tcp_data = self.nm[host].get('tcp', {})
    
            return {
                port: {
                    'state': info.get('state'),
                    'name': info.get('name'),
                    'version': info.get('version', 'unknown'),
                }
                for port, info in tcp_data.items()
            }

        except Exception as e:
            logging.error(f"Error during service detection on {host}: {e}")
            return {}
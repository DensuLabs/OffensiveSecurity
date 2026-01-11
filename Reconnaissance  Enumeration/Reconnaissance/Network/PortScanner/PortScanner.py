import socket
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

# Setup logging for better control over output
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

class PortScanner:
    def __init__(self, target_host: str):
        self.target_host = target_host
        self.open_ports = []
        self._lock = Lock()

    def _is_host_up(self) -> bool:
        """Internal check to ensure host is resolvable before scanning."""
        try:
            socket.gethostbyname(self.target_host)
            return True
        except socket.gaierror:
            logger.error(f"[-] Hostname {self.target_host} could not be resolved.")
            return False

    def scan_port(self, port: int, timeout: float = 1.0):
        """Attempts to connect to a specific port."""
        try:
            # Using 'with' ensures the socket is closed automatically
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                result = sock.connect_ex((self.target_host, port))
                if result == 0:
                    with self._lock:
                        self.open_ports.append(port)
                    logger.info(f"[+] Port {port:5}: Open")
        except Exception as e:
            logger.debug(f"Error scanning port {port}: {e}")

    def run(self, start_port: int, end_port: int, max_threads: int = 100):
        """Execution wrapper for multi-threaded scanning."""
        if not self._is_host_up():
            return

        logger.info(f"Starting scan on {self.target_host}...")
        start_time = datetime.now()

        # ThreadPoolExecutor handles the worker pool and task queue efficiently
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            ports = range(start_port, end_port + 1)
            executor.map(self.scan_port, ports)

        duration = datetime.now() - start_time
        logger.info("-" * 30)
        logger.info(f"Scan completed in: {duration}")
        logger.info(f"Open ports: {sorted(self.open_ports)}")
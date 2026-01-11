import hashlib
import secrets
import hmac
import logging
from typing import Dict, Optional

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SecureHashing:
    # PBKDF2 Constants - High iterations to slow down brute force
    ITERATIONS = 210_000 
    HASH_ALGO = 'sha256'
    SALT_SIZE = 32

    @staticmethod
    def hash_password(password: str) -> Dict[str, bytes]:
        """Hash password with a cryptographically secure random salt."""
        # secrets.token_bytes is preferred over get_random_bytes for standard library use
        salt = secrets.token_bytes(SecureHashing.SALT_SIZE)
        
        pwdhash = hashlib.pbkdf2_hmac(
            SecureHashing.HASH_ALGO,
            password.encode('utf-8'),
            salt,
            SecureHashing.ITERATIONS
        )
        
        return {
            'hash': pwdhash,
            'salt': salt,
            'iterations': SecureHashing.ITERATIONS
        }

    @staticmethod
    def verify_password(password: str, stored_hash: bytes, stored_salt: bytes) -> bool:
        """Verify password using constant-time comparison."""
        new_hash = hashlib.pbkdf2_hmac(
            SecureHashing.HASH_ALGO,
            password.encode('utf-8'),
            stored_salt,
            SecureHashing.ITERATIONS
        )
        
        # USE THIS instead of == to prevent timing attacks
        return hmac.compare_digest(new_hash, stored_hash)

    @staticmethod
    def file_hash(filename: str, algorithm: str = 'sha256') -> Optional[str]:
        """Calculate hash of a file using buffered reading for memory efficiency."""
        # Only allow specific safe algorithms
        if algorithm not in hashlib.algorithms_guaranteed:
            raise ValueError(f"Algorithm {algorithm} is not guaranteed safe.")

        hash_obj = hashlib.new(algorithm)
        try:
            with open(filename, 'rb') as f:
                # 64KB chunks are generally more efficient for modern disk I/O
                for chunk in iter(lambda: f.read(65536), b""):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except FileNotFoundError:
            logger.error(f"File not found: {filename}")
            return None
from Crypto.PublicKey import RSA
from Crypto.Signature import pss
from Crypto.Hash import SHA256
import base64
from typing import Dict, Optional

class DigitalSignature:
    def __init__(self):
        self.private_key: Optional[RSA.RsaKey] = None
        self.public_key: Optional[RSA.RsaKey] = None

    def generate_keys(self, key_size: int = 2048) -> Dict[str, str]:
        """Generate RSA key pair and return as PEM strings."""
        key = RSA.generate(key_size)
        self.private_key = key
        self.public_key = key.publickey()
        
        return {
            'private_key': self.private_key.export_key().decode('utf-8'),
            'public_key': self.public_key.export_key().decode('utf-8')
        }

    def load_keys(self, private_pem: str = None, public_pem: str = None) -> None:
        """Load RSA keys from PEM strings."""
        try:
            if private_pem:
                self.private_key = RSA.import_key(private_pem)
                # Automatically extract public key if only private is provided
                if not public_pem:
                    self.public_key = self.private_key.publickey()
            if public_pem:
                self.public_key = RSA.import_key(public_pem)
        except (ValueError, IndexError, TypeError) as e:
            raise ValueError(f"Invalid key format: {e}")

    def sign_message(self, message: str) -> str:
        """Sign a message using the private key and RSA-PSS padding."""
        if not self.private_key:
            raise RuntimeError("Private key is required for signing.")

        # Hash the message
        msg_hash = SHA256.new(message.encode('utf-8'))
        
        # Create signature using PSS (Modern standard)
        signature = pss.new(self.private_key).sign(msg_hash)
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message: str, b64_signature: str) -> bool:
        """Verify an RSA-PSS signature using the public key."""
        if not self.public_key:
            raise RuntimeError("Public key is required for verification.")

        try:
            msg_hash = SHA256.new(message.encode('utf-8'))
            signature_bytes = base64.b64decode(b64_signature)
            
            # PSS verification
            verifier = pss.new(self.public_key)
            verifier.verify(msg_hash, signature_bytes)
            return True
        except (ValueError, TypeError):
            # ValueError: signature is invalid
            # TypeError: key is not public or message is not a hash object
            return False
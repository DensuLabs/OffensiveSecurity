from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import base64

class AESCrypto:
    # Industry standards for high-security derivation
    KDF_ITERATIONS = 210_000
    KEY_SIZE = 32  # AES-256
    SALT_SIZE = 16
    NONCE_SIZE = 12 # Standard for GCM

    def __init__(self, password: str):
        self.password = password.encode('utf-8')

    def _derive_key(self, salt: bytes) -> bytes:
        """Derive a 256-bit key using PBKDF2."""
        return PBKDF2(
            self.password, 
            salt, 
            dkLen=self.KEY_SIZE, 
            count=self.KDF_ITERATIONS, 
            hmac_hash_module=SHA256
        )

    def encrypt(self, plaintext: str) -> str:
        """Encrypts using AES-256-GCM with built-in authentication."""
        salt = get_random_bytes(self.SALT_SIZE)
        nonce = get_random_bytes(self.NONCE_SIZE)
        
        key = self._derive_key(salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        
        # GCM doesn't require manual padding
        ciphertext, tag = cipher.encrypt_and_digest(plaintext.encode('utf-8'))
        
        # Combine everything: salt + nonce + tag + ciphertext
        # Order: [16b salt][12b nonce][16b tag][...ciphertext...]
        combined = salt + nonce + tag + ciphertext
        return base64.b64encode(combined).decode('utf-8')

    def decrypt(self, b64_data: str) -> str:   
        """Decrypts and verifies data integrity."""
        try:
            raw_data = base64.b64decode(b64_data)
            # Extract components based on fixed sizes
            s_ptr = self.SALT_SIZE
            n_ptr = s_ptr + self.NONCE_SIZE
            t_ptr = n_ptr + 16 # Tag is always 16 bytes for AES-GCM
            salt = raw_data[:s_ptr]
            nonce = raw_data[s_ptr:n_ptr]
            tag = raw_data[n_ptr:t_ptr]
            ciphertext = raw_data[t_ptr:]
            key = self._derive_key(salt)
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            # verify() happens during decrypt()
            decrypted_bytes = cipher.decrypt_and_verify(ciphertext, tag)
            return decrypted_bytes.decode('utf-8')
        
        except (ValueError, KeyError) as e:
            # KeyError is raised if the tag (MAC) check fails
            raise Exception("Decryption failed: Integrity check failed or incorrect password.") from e
        except Exception as e:
            raise Exception(f"Technical error during decryption: {e}") from e
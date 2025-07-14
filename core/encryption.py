from cryptography.fernet import Fernet
import hashlib
from core import db_manager
import base64

# --- Fernet Key Handling ---
def generate_key():
    return Fernet.generate_key()

def get_fernet(key):
    return Fernet(key)

def encrypt_password(fernet, password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(fernet, encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

def derive_fernet_key_from_password(password: str) -> bytes:
    """Derives a Fernet-compatible key from a plain-text password."""
    raw_key = hashlib.sha256(password.encode()).digest()
    return base64.urlsafe_b64encode(raw_key)

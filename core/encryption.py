from cryptography.fernet import Fernet
import hashlib
from core import db_manager

# --- Fernet Key Handling ---
def generate_key():
    return Fernet.generate_key()

def get_fernet(key):
    return Fernet(key)

def encrypt_password(fernet, password):
    return fernet.encrypt(password.encode()).decode()

def decrypt_password(fernet, encrypted_password):
    return fernet.decrypt(encrypted_password.encode()).decode()

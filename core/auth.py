from core import db_manager
import os
import hashlib
import base64

def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return base64.b64encode(salt + key).decode()

def verify_password(password, stored_hash):
    raw = base64.b64decode(stored_hash.encode())
    salt = raw[:16]
    key = raw[16:]
    new_key = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
    return new_key == key

def is_master_set():
    result = db_manager.get_setting("master_password")
    return result is not None

def save_master(password):
    hashed = hash_password(password)
    db_manager.set_setting("master_password", hashed)

def load_master():
    return db_manager.get_setting("master_password")

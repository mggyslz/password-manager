# config.py
from pathlib import Path
from cryptography.fernet import Fernet

# 🔁 Use a local `.config` folder in your project directory
config_dir = Path(__file__).resolve().parent / ".config"
config_dir.mkdir(exist_ok=True)

KEY_FILE = config_dir / "secret.key"
DB_FILE = config_dir / "passwords.db"

def save_key(key):
    with open(KEY_FILE, "wb") as f:
        f.write(key)

def load_key():
    with open(KEY_FILE, "rb") as f:
        return f.read()

def get_or_create_key():
    if not KEY_FILE.exists():
        key = Fernet.generate_key()
        save_key(key)
    return load_key()

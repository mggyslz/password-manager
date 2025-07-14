import sqlite3
from config import DB_FILE

def connect():
    return sqlite3.connect(DB_FILE)

def init_db():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                password TEXT NOT NULL,
                category TEXT DEFAULT ''
            )
        """)
        try:
            conn.execute("ALTER TABLE passwords ADD COLUMN category TEXT DEFAULT ''")
        except sqlite3.OperationalError:
            pass
        init_settings_table()
        conn.commit()

def init_settings_table():
    with connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        conn.commit()

def add_entry(site, username, encrypted_password, category=""):
    with connect() as conn:
        conn.execute('''
            INSERT INTO passwords (site, username, password, category)
            VALUES (?, ?, ?, ?)
        ''', (site, username, encrypted_password, category))
        conn.commit()

def get_all_entries():
    with connect() as conn:
        cur = conn.execute('SELECT id, site, username, password, category FROM passwords')
        return cur.fetchall()

def update_entry_by_id(entry_id, new_encrypted_password):
    with connect() as conn:
        conn.execute('''
            UPDATE passwords
            SET password = ?
            WHERE id = ?
        ''', (new_encrypted_password, entry_id))
        conn.commit()

def update_full_entry(entry_id, site, username, encrypted_password):
    with connect() as conn:
        conn.execute('''
            UPDATE passwords
            SET site = ?, username = ?, password = ?
            WHERE id = ?
        ''', (site, username, encrypted_password, entry_id))
        conn.commit()

def delete_entry_by_id(entry_id):
    with connect() as conn:
        conn.execute('DELETE FROM passwords WHERE id = ?', (entry_id,))
        conn.commit()

def set_setting(key, value):
    with connect() as conn:
        conn.execute('REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
        conn.commit()

def get_setting(key):
    with connect() as conn:
        cur = conn.execute('SELECT value FROM settings WHERE key = ?', (key,))
        row = cur.fetchone()
        return row[0] if row else None

def get_all_entries_raw():
    with connect() as conn:
        cur = conn.execute('SELECT site, username, password, category FROM passwords')
        return cur.fetchall()


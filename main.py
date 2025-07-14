# main.py
import tkinter as tk
from tkinter import messagebox
from gui.main_ui import PasswordManagerApp
from gui.login_ui import LoginWindow
from core import auth, db_manager

db_manager.init_db()

def show_login():
    login_root = tk.Tk()
    login = LoginWindow(login_root)
    login_root.mainloop()
    return login.result

def prompt_master_password():
    if not auth.is_master_set():
        # First time setup
        from tkinter import simpledialog
        while True:
            pw1 = simpledialog.askstring("Set Master Password", "Enter master password:", show='*')
            pw2 = simpledialog.askstring("Confirm Password", "Confirm master password:", show='*')
            if not pw1:
                messagebox.showerror("Error", "Password cannot be empty.")
            elif pw1 != pw2:
                messagebox.showerror("Mismatch", "Passwords do not match.")
            else:
                auth.save_master(pw1)
                messagebox.showinfo("Success", "Master password set.")
                return True
    else:
        return show_login()

if __name__ == "__main__":
    if prompt_master_password():
        root = tk.Tk()
        app = PasswordManagerApp(root)
        root.mainloop()
    else:
        messagebox.showinfo("Access Denied", "Too many failed attempts or login cancelled.")

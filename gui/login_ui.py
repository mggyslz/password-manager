# gui/login_ui.py
import tkinter as tk
from tkinter import messagebox
from core import auth

class LoginWindow:
    def __init__(self, master):
        self.master = master
        self.master.title("Unlock Password Manager")
        self.master.geometry("350x200")
        self.master.resizable(False, False)

        self.result = False  # Will be True if login successful

        self.build_ui()

    def build_ui(self):
        tk.Label(self.master, text="Enter Master Password", font=("Segoe UI", 12, "bold")).pack(pady=(20, 10))

        self.pw_entry = tk.Entry(self.master, show="*", width=30, font=("Segoe UI", 10))
        self.pw_entry.pack(pady=(0, 10))
        self.pw_entry.focus()

        login_btn = tk.Button(self.master, text="Login", width=12, command=self.attempt_login)
        login_btn.pack(pady=5)

        # Optional links
        link_frame = tk.Frame(self.master)
        link_frame.pack(pady=10)


    def attempt_login(self):
        entered_pw = self.pw_entry.get()
        stored_hash = auth.load_master()
        if auth.verify_password(entered_pw, stored_hash):
            self.result = True
            self.master.destroy()
        else:
            messagebox.showerror("Access Denied", "Incorrect master password.")
            self.pw_entry.delete(0, tk.END)

    def change_password(self):
        old_pw = tk.simpledialog.askstring("Current Password", "Enter current master password:", show="*")
        stored_hash = auth.load_master()
        if not old_pw or not auth.verify_password(old_pw, stored_hash):
            messagebox.showerror("Error", "Incorrect current password.")
            return

        new_pw = tk.simpledialog.askstring("New Password", "Enter new password:", show="*")
        confirm_pw = tk.simpledialog.askstring("Confirm Password", "Confirm new password:", show="*")
        if new_pw != confirm_pw or not new_pw:
            messagebox.showerror("Error", "Passwords do not match or are empty.")
            return

        auth.save_master(new_pw)
        messagebox.showinfo("Success", "Master password changed.")

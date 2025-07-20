import tkinter as tk
from tkinter import messagebox, ttk, filedialog, simpledialog
from core import db_manager, encryption, auth
from core.auth import hash_password
import config
import time
import threading
from pynput import keyboard
import json
import hashlib
import base64
import pyperclip

# ======== PASSWORD MANAGER CLASS ========
class PasswordManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("700x700")
        self.root.resizable(False, False)

        db_manager.init_db()
        key = config.get_or_create_key()
        self.fernet = encryption.get_fernet(key)

        self.build_ui()
        self.refresh_list()
        threading.Thread(target=self.listen_for_hotkey, daemon=True).start()

        self.idle_timeout = 120  # Idle time in seconds
        self.last_activity = time.time()

        # Bind all key and mouse events to reset timer
        self.root.bind_all("<Any-KeyPress>", self.reset_idle_timer)
        self.root.bind_all("<Any-Button>", self.reset_idle_timer)

        # Start idle checking loop
        self.check_idle()

# ======== UI BUILD ========
    def build_ui(self):
        label_font = ("Segoe UI", 10, "bold")
        entry_font = ("Segoe UI", 10)

        # Input Frame
        input_frame = tk.Frame(self.root, padx=10, pady=10)
        input_frame.pack(fill="x")

        tk.Label(input_frame, text="Site:", font=label_font).grid(row=0, column=0, sticky="e", padx=5, pady=5)
        tk.Label(input_frame, text="Username:", font=label_font).grid(row=1, column=0, sticky="e", padx=5, pady=5)
        tk.Label(input_frame, text="Password:", font=label_font).grid(row=2, column=0, sticky="e", padx=5, pady=5)

        self.site_entry = tk.Entry(input_frame, font=entry_font, width=40)
        self.username_entry = tk.Entry(input_frame, font=entry_font, width=40)
        self.password_entry = tk.Entry(input_frame, font=entry_font, width=40)

        tk.Label(input_frame, text="Category:", font=label_font).grid(row=3, column=0, sticky="e", padx=5, pady=5)
        self.category_entry = ttk.Combobox(input_frame, values=["", "Work", "Personal", "Finance", "Social", "Email", "School", "Other"], state="readonly", width=37)
        self.category_entry.grid(row=3, column=1, pady=5)


        self.site_entry.grid(row=0, column=1, pady=5)
        self.username_entry.grid(row=1, column=1, pady=5)
        self.password_entry.grid(row=2, column=1, pady=5)

        self.strength_label = tk.Label(input_frame, text="", font=("Segoe UI", 9, "italic"))
        self.strength_label.grid(row=4, column=1, sticky="w", padx=5, pady=(0, 2))

        self.password_entry.bind("<KeyRelease>", self.check_password_strength)


        # Generate Password Button
        tk.Button(input_frame, text="Generate Password", width=20, command=self.handle_generate_password)\
            .grid(row=5, column=1, sticky="w", padx=5, pady=(0, 10))

        
        # Buttons
        button_frame = tk.Frame(self.root, pady=10)
        button_frame.pack(fill="x")
        settings_frame = tk.Frame(self.root, pady=5)
        settings_frame.pack()

        tk.Button(button_frame, text="Add", width=10, command=self.add_entry).pack(side="left", padx=15)
        tk.Button(button_frame, text="Update", width=10, command=self.update_entry).pack(side="left", padx=15)
        tk.Button(button_frame, text="Delete", width=10, command=self.delete_entry).pack(side="left", padx=15)
        tk.Button(settings_frame, text="Export Vault", width=25, command=self.export_vault).pack(pady=2)
        tk.Button(settings_frame, text="Import Vault", width=25, command=self.import_vault).pack(pady=2)


        ttk.Separator(self.root, orient="horizontal").pack(fill="x", padx=10, pady=5)
        
        # Search Bar
        search_frame = tk.Frame(self.root, padx=10, pady=5)
        search_frame.pack(fill="x")

        tk.Label(search_frame, text="Search:", font=("Segoe UI", 10, "bold")).pack(side="left", padx=5)
        self.search_var = tk.StringVar()
        search_entry = tk.Entry(search_frame, textvariable=self.search_var, font=("Segoe UI", 10), width=30)
        search_entry.pack(side="left", padx=5)
        search_entry.bind("<KeyRelease>", self.handle_search)
        
        # Filter DropDown
        tk.Label(search_frame, text="Filter by Category:", font=label_font).pack(side="left", padx=5)

        self.category_filter = ttk.Combobox(search_frame, values=[], state="readonly")
        self.category_filter.pack(side="left")
        self.category_filter.bind("<<ComboboxSelected>>", self.handle_search)


        # Listbox
        list_frame = tk.Frame(self.root, padx=10, pady=5)
        list_frame.pack(fill="both", expand=True)

        self.listbox = tk.Listbox(list_frame, font=("Consolas", 10), height=10, width=80)
        self.listbox.pack(side="left", fill="both", expand=True)
        self.listbox.bind("<<ListboxSelect>>", self.on_select)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.listbox.config(yscrollcommand=scrollbar.set)

        # Copy Buttons under Listbox
        copy_frame = tk.Frame(self.root, pady=10)
        copy_frame.pack()

        tk.Button(copy_frame, text="Copy Username", width=20, command=self.copy_selected_username).pack(side="left", padx=10)
        tk.Button(copy_frame, text="Copy Password", width=20, command=self.copy_selected_password).pack(side="left", padx=10)
        
        # Change Master Password Button
        settings_frame = tk.Frame(self.root, pady=5)
        settings_frame.pack()
        tk.Button(settings_frame, text="Change Master Password", width=25, command=self.change_master_password).pack()

# ======== ACTIONS ========
    def add_entry(self):
        site = self.site_entry.get()
        username = self.username_entry.get()
        password = self.password_entry.get()
        category = self.category_entry.get()
        if site and username and password:
            encrypted_pw = encryption.encrypt_password(self.fernet, password)
            db_manager.add_entry(site, username, encrypted_pw, category)
            self.refresh_list()
            self.clear_fields()
        else:
            messagebox.showwarning("Input error", "All fields are required.")

    def update_entry(self):
        if not hasattr(self, 'selected_entry_id') or self.selected_entry_id is None:
            return messagebox.showwarning("Selection error", "Select an entry to update.")

        new_site = self.site_entry.get()
        new_username = self.username_entry.get()
        new_password = self.password_entry.get()
        new_category = self.category_entry.get()

        if not new_site or not new_username or not new_password:
            return messagebox.showwarning("Input error", "All fields must be filled out.")

        encrypted_pw = encryption.encrypt_password(self.fernet, new_password)

        # Update full entry with category
        db_manager.update_full_entry(self.selected_entry_id, new_site, new_username, encrypted_pw, new_category)

        self.refresh_list()
        self.clear_fields()
        self.selected_entry_id = None

# ======== ACTIONS ========
    def delete_entry(self):
        selected = self.listbox.curselection()
        if not selected:
            return messagebox.showwarning("Selection error", "Select an entry to delete.")

        index = selected[0]
        entry_id = self.entries[index][0]
        confirm = messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?")
        if confirm:
            db_manager.delete_entry_by_id(entry_id)
            self.refresh_list()
            self.clear_fields()
            
# ======== REFRESH ========
    def refresh_list(self):
        self.entries = db_manager.get_all_entries()
        self.listbox.delete(0, tk.END)
        
        categories = set()  # For the category dropdown

        for entry in self.entries:
            try:
                entry_id, site, username, encrypted_pw, category = entry
            except ValueError:
                # Fallback for entries without category
                entry_id, site, username, encrypted_pw = entry
                category = ""

            decrypted_pw = encryption.decrypt_password(self.fernet, encrypted_pw)
            self.listbox.insert(
                tk.END, 
                f"[{entry_id}] {site:<15} | {username:<20} | {decrypted_pw:<20} | {category}"
            )
            categories.add(category)

        if hasattr(self, 'category_filter'):
            self.category_filter['values'] = [""] + sorted(c for c in categories if c)
            
# ======== ON SELECT ========
    def on_select(self, event):
        selected = self.listbox.curselection()
        if not selected:
            return
        index = selected[0]
        entry_id, site, username, encrypted_pw, category = self.entries[index]
        decrypted_pw = encryption.decrypt_password(self.fernet, encrypted_pw)
        self.site_entry.delete(0, tk.END)
        self.site_entry.insert(0, site)
        self.username_entry.delete(0, tk.END)
        self.username_entry.insert(0, username)
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, decrypted_pw)
        
        self.selected_entry_id = entry_id
        self.category_entry.delete(0, tk.END)
        self.category_entry.insert(0, category)

    def clear_fields(self):
        self.site_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)
# ======== GENERATE STRONG PASSWORD ========        
    def handle_generate_password(self):
        import string, random

        length = 12
        use_upper = True
        use_digits = True
        use_symbols = True

        lower = string.ascii_lowercase
        upper = string.ascii_uppercase if use_upper else ''
        digits = string.digits if use_digits else ''
        symbols = string.punctuation if use_symbols else ''

        all_chars = lower + upper + digits + symbols
        if not all_chars:
            return

        # Ensure at least one of each selected type
        password = []
        if use_upper:
            password.append(random.choice(upper))
        if use_digits:
            password.append(random.choice(digits))
        if use_symbols:
            password.append(random.choice(symbols))

        password += random.choices(all_chars, k=length - len(password))
        random.shuffle(password)
        final_password = ''.join(password)

        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, final_password)
        self.check_password_strength()
# ======== COPY USERNAME ========
    def copy_selected_username(self):
        import pyperclip
        import threading, time

        selected = self.listbox.curselection()
        if not selected:
            print("No entry selected.")
            return

        index = selected[0]
        entry = self.entries[index]
        _, _, username, _ = entry

        pyperclip.copy(username)
        print(f"Username copied: {username}")

        self._start_clipboard_clear_timer()
# ======== COPY PASSWORD ========
    def copy_selected_password(self):

        selected = self.listbox.curselection()
        if not selected:
            print("No entry selected.")
            return

        index = selected[0]
        entry = self.entries[index]
        _, _, _, encrypted_password = entry

        decrypted_password = encryption.decrypt_password(self.fernet, encrypted_password)
        pyperclip.copy(decrypted_password)
        print(f"Password copied: {decrypted_password}")

        self._start_clipboard_clear_timer()


    def _start_clipboard_clear_timer(self):
        import threading, time, pyperclip

        def clear_clipboard():
            time.sleep(20)
            pyperclip.copy("")
            print("Clipboard cleared.")

        threading.Thread(target=clear_clipboard, daemon=True).start()
# ======== SEARCH ========
    def handle_search(self, event=None):
        query = self.search_var.get().lower()
        filtered = []
        filter_value = self.category_filter.get().lower()

        for entry in self.entries:
            entry_id, site, username, encrypted_pw, category = entry
            if (query in site.lower() or query in username.lower()) and (filter_value == "" or filter_value == category.lower()):
                decrypted_pw = encryption.decrypt_password(self.fernet, encrypted_pw)
                filtered.append((entry_id, site, username, decrypted_pw))

        self.listbox.delete(0, tk.END)
        for entry_id, site, username, password in filtered:
            self.listbox.insert(tk.END, f"[{entry_id}] {site:<15} | {username:<20} | {password}")

    def check_password_strength(self, event=None):
        password = self.password_entry.get()
        strength = 0

        if len(password) >= 8:
            strength += 1
        if any(c.islower() for c in password):
            strength += 1
        if any(c.isupper() for c in password):
            strength += 1
        if any(c.isdigit() for c in password):
            strength += 1
        if any(c in "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~" for c in password):
            strength += 1

        if strength <= 2:
            color = "red"
            text = "Weak"
        elif strength == 3 or strength == 4:
            color = "orange"
            text = "Moderate"
        else:
            color = "green"
            text = "Strong"

        self.strength_label.config(text=f"Password Strength: {text}", fg=color)

    def reset_idle_timer(self, event=None):
        self.last_activity = time.time()

    def check_idle(self):
        current_time = time.time()
        if current_time - self.last_activity > self.idle_timeout:
            self.lock_app()
        else:
            self.root.after(1000, self.check_idle)  # check every second

    def lock_app(self):
        from gui.login_ui import LoginWindow

        self.root.withdraw()  # hide main window

        lock_window = tk.Toplevel()
        login = LoginWindow(lock_window)
        lock_window.wait_window()

        if login.result:
            self.last_activity = time.time()
            self.root.deiconify()  # show main window again
            self.check_idle()
        else:
            self.root.quit()  # or kill the app if login fails

    def change_master_password(self):
        win = tk.Toplevel(self.root)
        win.title("Change Master Password")
        win.geometry("300x200")
        win.resizable(False, False)

        tk.Label(win, text="Current Password:").pack(pady=5)
        current_entry = tk.Entry(win, show="*")
        current_entry.pack()

        tk.Label(win, text="New Password:").pack(pady=5)
        new_entry = tk.Entry(win, show="*")
        new_entry.pack()

        tk.Label(win, text="Confirm New Password:").pack(pady=5)
        confirm_entry = tk.Entry(win, show="*")
        confirm_entry.pack()

        def save_new_password():
            current = current_entry.get()
            new = new_entry.get()
            confirm = confirm_entry.get()

            if not current or not new or not confirm:
                messagebox.showwarning("Input Error", "All fields are required.")
                return

            stored_hash = auth.load_master()
            if not auth.verify_password(current, stored_hash):
                messagebox.showerror("Auth Failed", "Current password is incorrect.")
                return

            if new != confirm:
                messagebox.showerror("Mismatch", "New passwords do not match.")
                return

            auth.save_master(new)
            messagebox.showinfo("Success", "Master password updated successfully.")
            win.destroy()

        tk.Button(win, text="Save", command=save_new_password).pack(pady=10)



    def listen_for_hotkey(self):
        def on_activate():
            self.root.after(0, self.show_quick_add_popup)  # ensure it runs on main thread

        hotkey = keyboard.HotKey(
            keyboard.HotKey.parse('<ctrl>+<shift>+s'),
            on_activate
        )

        def for_canonical(f):
            return lambda k: f(l.canonical(k))

        with keyboard.Listener(
            on_press=for_canonical(hotkey.press),
            on_release=for_canonical(hotkey.release)
        ) as l:
            l.join()


    def show_quick_add_popup(self):
        def save():
            site = site_entry.get().strip()
            username = user_entry.get().strip()
            password = pass_entry.get().strip()

            if not site or not username or not password:
                messagebox.showwarning("Missing Info", "All fields are required.")
                return

            encrypted_pw = encryption.encrypt_password(self.fernet, password)
            db_manager.add_entry(site, username, encrypted_pw)
            popup.destroy()
            self.refresh_list()

        popup = tk.Toplevel(self.root)
        popup.title("Quick Add Password")
        popup.geometry("300x220")
        popup.resizable(False, False)

        tk.Label(popup, text="Site:").pack(pady=5)
        site_entry = tk.Entry(popup, width=30)
        site_entry.pack()

        tk.Label(popup, text="Username:").pack(pady=5)
        user_entry = tk.Entry(popup, width=30)
        user_entry.pack()

        tk.Label(popup, text="Password:").pack(pady=5)
        pass_entry = tk.Entry(popup, width=30, show="*")
        pass_entry.pack()

        pass_entry.bind('<Return>', lambda e: save())  # Press Enter to submit

        tk.Button(popup, text="Save", command=save).pack(pady=10)

        popup.grab_set()
        site_entry.focus()
# ======== EXPORT VAULT ========
    def export_vault(self):
        entries = db_manager.get_all_entries_raw()
        password = simpledialog.askstring("Encrypt Export", "Enter master password:", show="*")

        if not password or not auth.verify_password(password, auth.load_master()):
            messagebox.showerror("Error", "Incorrect master password.")
            return

        f = encryption.get_fernet(encryption.derive_fernet_key_from_password(password))

        export_data = []
        for entry in entries:
            try:
                site, username, enc_pw, category = entry
                decrypted_pw = encryption.decrypt_password(self.fernet, enc_pw)
                data = {
                    "site": site,
                    "username": username,
                    "password": f.encrypt(decrypted_pw.encode()).decode(),
                    "category": category
                }
                export_data.append(data)
            except Exception as e:
                print(f"[!] Skipped during export: {e}")

        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as file:
                json.dump(export_data, file, indent=2)
            messagebox.showinfo("Success", f"Vault exported to {path}")
# ======== IMPORT VAULT ========
    def import_vault(self):
        password = simpledialog.askstring("Decrypt Import", "Enter master password to decrypt vault:", show="*")
        if not password:
            return

        f = encryption.get_fernet(encryption.derive_fernet_key_from_password(password))

        file_path = filedialog.askopenfilename(filetypes=[("JSON files", "*.json")])
        if not file_path:
            return

        with open(file_path, "r", encoding="utf-8") as f_in:
            try:
                data = json.load(f_in)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load file: {e}")
                return

        success_count = 0
        for entry in data:
            try:
                site = entry.get("site")
                username = entry.get("username")
                encrypted_pw = entry.get("password")
                category = entry.get("category", "")

                decrypted_pw = f.decrypt(encrypted_pw.encode()).decode()
                re_encrypted = encryption.encrypt_password(self.fernet, decrypted_pw)
                db_manager.add_entry(site, username, re_encrypted, category)
                success_count += 1
            except Exception as e:
                print(f"[!] Skipped invalid entry: {e}")

        self.refresh_list()
        messagebox.showinfo("Imported", f"Successfully imported {success_count} entries.")

        








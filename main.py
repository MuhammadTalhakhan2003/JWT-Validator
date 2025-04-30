import tkinter as tk
from tkinter import messagebox, simpledialog, scrolledtext, filedialog
import tkinter.ttk as ttk
from ttkthemes import ThemedTk
import jwt
import json
import os
import time
from datetime import datetime, timedelta, timezone
from jwt.exceptions import ExpiredSignatureError, DecodeError, InvalidTokenError
import webbrowser
import pyperclip
import uuid
import hashlib
import qrcode
from PIL import Image, ImageTk
import io
import threading
import requests
from bs4 import BeautifulSoup
import markdown
import sv_ttk

# Configuration
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRES_HOURS = 0.5
REFRESH_TOKEN_EXPIRES_DAYS = 3
TOKENS_DIR = "user_tokens"
BLACKLIST_FILE = "blacklist.json"
HISTORY_FILE = "token_history.json"
SETTINGS_FILE = "app_settings.json"

# Color Palette
COLORS = {
    "primary": "#4361ee",
    "secondary": "#3a0ca3",
    "accent": "#f72585",
    "success": "#4cc9f0",
    "warning": "#f8961e",
    "danger": "#ef233c",
    "light": "#f8f9fa",
    "dark": "#212529",
    "text": "#2b2d42",
    "text_light": "#8d99ae",
    "bg": "#ffffff",
    "card": "#f8f9fa"
}

DARK_COLORS = {
    "primary": "#4895ef",
    "secondary": "#560bad",
    "accent": "#b5179e",
    "success": "#4cc9f0",
    "warning": "#f8961e",
    "danger": "#ef233c",
    "light": "#343a40",
    "dark": "#121212",
    "text": "#e9ecef",
    "text_light": "#adb5bd",
    "bg": "#1e1e1e",
    "card": "#2d2d2d"
}

# --- Utility Functions ---
def ensure_directory_exists(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def get_user_token_file(username):
    username_hash = hashlib.sha256(username.encode()).hexdigest()
    return os.path.join(TOKENS_DIR, f"{username_hash}.json")

def load_blacklist():
    try:
        if os.path.exists(BLACKLIST_FILE):
            with open(BLACKLIST_FILE, "r") as f:
                return set(json.load(f))
        return set()
    except Exception:
        return set()

def save_blacklist(blacklist):
    with open(BLACKLIST_FILE, "w") as f:
        json.dump(list(blacklist), f)

def load_token_history():
    try:
        if os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        return []
    except Exception:
        return []

def save_token_history(history):
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=2)

def load_settings():
    try:
        if os.path.exists(SETTINGS_FILE):
            with open(SETTINGS_FILE, "r") as f:
                return json.load(f)
        return {"theme": "dark", "font_size": 11, "auto_refresh": False, "color_scheme": "default"}
    except Exception:
        return {"theme": "dark", "font_size": 11, "auto_refresh": False, "color_scheme": "default"}

def save_settings(settings):
    with open(SETTINGS_FILE, "w") as f:
        json.dump(settings, f, indent=2)

def create_jwt_with_claims(user_id, roles, permissions, secret_key, custom_claims=None):
    access_exp = datetime.now(timezone.utc) + timedelta(hours=ACCESS_TOKEN_EXPIRES_HOURS)
    refresh_exp = datetime.now(timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRES_DAYS)
    now_ts = int(datetime.now(timezone.utc).timestamp())

    access_payload = {
        "sub": user_id,
        "roles": roles,
        "permissions": permissions,
        "iat": now_ts,
        "exp": int(access_exp.timestamp()),
        "iss": "SecureApp",
        "aud": "SecureAppClient",
        "jti": f"access-{uuid.uuid4()}"
    }
    
    if custom_claims:
        access_payload.update(custom_claims)

    refresh_payload = {
        "sub": user_id,
        "type": "refresh",
        "iat": now_ts,
        "exp": int(refresh_exp.timestamp()),
        "iss": "SecureApp",
        "aud": "SecureAppClient",
        "jti": f"refresh-{uuid.uuid4()}"
    }

    access_token = jwt.encode(access_payload, secret_key, algorithm=ALGORITHM)
    refresh_token = jwt.encode(refresh_payload, secret_key, algorithm=ALGORITHM)

    return access_token, refresh_token, access_payload, refresh_payload

def validate_jwt(token, secret_key):
    try:
        payload = jwt.decode(token, secret_key, algorithms=[ALGORITHM], audience="SecureAppClient", issuer="SecureApp")
        if payload["jti"] in blacklist:
            messagebox.showerror("Error", "Token has been revoked (blacklisted).")
            return None
        return payload
    except ExpiredSignatureError:
        messagebox.showerror("Error", "Token has expired.")
    except DecodeError:
        messagebox.showerror("Error", "Token is invalid or malformed.")
    except InvalidTokenError:
        messagebox.showerror("Error", "Token validation failed.")
    return None

def refresh_access_token(refresh_token, secret_key):
    payload = validate_jwt(refresh_token, secret_key)
    if not payload:
        return None

    if payload.get("jti") in blacklist:
        messagebox.showerror("Error", "Token is blacklisted.")
        return None

    if payload.get("jti", "").startswith("access"):
        messagebox.showerror("Error", "Provided token is not a refresh token.")
        return None

    if payload["exp"] < int(datetime.now(timezone.utc).timestamp()):
        messagebox.showerror("Error", "Refresh token has expired.")
        return None

    user_id = payload["sub"]
    roles = payload.get("roles", [])
    permissions = payload.get("permissions", [])

    new_access_token, _, _, _ = create_jwt_with_claims(user_id, roles, permissions, secret_key)
    return new_access_token

def save_tokens_to_json(username, access_token, refresh_token):
    ensure_directory_exists(TOKENS_DIR)
    token_file = get_user_token_file(username)
    
    history = load_token_history()
    history_entry = {
        "username": username,
        "access_token": access_token,
        "refresh_token": refresh_token,
        "timestamp": datetime.now().isoformat()
    }
    history.append(history_entry)
    if len(history) > 50:
        history = history[-50:]
    save_token_history(history)
    
    with open(token_file, "w") as file:
        json.dump({
            "access_token": access_token,
            "refresh_token": refresh_token,
            "username": username,
            "timestamp": datetime.now().isoformat()
        }, file, indent=4)

def load_tokens_from_json(username):
    token_file = get_user_token_file(username)
    if not os.path.exists(token_file):
        return None, None
    with open(token_file, "r") as file:
        tokens = json.load(file)
        return tokens.get("access_token"), tokens.get("refresh_token")

def revoke_token(token, secret_key):
    payload = validate_jwt(token, secret_key)
    if payload:
        blacklist.add(payload["jti"])
        save_blacklist(blacklist)
        messagebox.showinfo("Success", f"Token with jti '{payload['jti']}' has been revoked.")
    else:
        messagebox.showerror("Error", "Invalid token. Cannot revoke.")

def generate_qr_code(data):
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#4361ee", back_color="white")
    
    bio = io.BytesIO()
    img.save(bio, format="PNG")
    return tk.PhotoImage(data=bio.getvalue())

def check_for_updates(current_version="1.0.0"):
    try:
        response = requests.get("https://api.github.com/repos/yourusername/jwt-token-manager/releases/latest")
        if response.status_code == 200:
            latest_version = response.json()["tag_name"]
            if latest_version > current_version:
                return True, latest_version
        return False, current_version
    except Exception:
        return False, current_version

def get_jwt_documentation():
    try:
        response = requests.get("https://jwt.io/introduction/")
        soup = BeautifulSoup(response.text, 'html.parser')
        content = soup.find('article').get_text()
        return content[:1000] + "..."
    except Exception:
        return "Could not fetch latest JWT documentation. Please check your internet connection."

# --- Modern UI Components ---
class AuthDialog(tk.Toplevel):
    def __init__(self, parent, title):
        super().__init__(parent)
        self.title(title)
        self.username = None
        self.password = None
        self.parent = parent
        
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        self.configure(bg=self.current_colors["bg"])
        self.resizable(False, False)
        
        window_width = 400
        window_height = 350
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        self.grab_set()
        self.focus_force()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Main container
        main_frame = tk.Frame(self, bg=self.current_colors["bg"], padx=30, pady=30)
        main_frame.pack(fill="both", expand=True)
        
        # App logo and title
        logo_frame = tk.Frame(main_frame, bg=self.current_colors["bg"])
        logo_frame.pack(pady=(0, 20))
        
        tk.Label(
            logo_frame,
            text="🔐",
            font=("Segoe UI", 32),
            bg=self.current_colors["bg"],
            fg=self.current_colors["primary"]
        ).pack(side="left", padx=5)
        
        tk.Label(
            logo_frame,
            text="Secure Token Manager",
            font=("Segoe UI", 18, "bold"),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).pack(side="left")
        
        # Form container
        form_frame = tk.Frame(main_frame, bg=self.current_colors["bg"])
        form_frame.pack(fill="x")
        
        # Username field
        tk.Label(
            form_frame,
            text="Username",
            font=("Segoe UI", 10),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text_light"]
        ).pack(anchor="w", pady=(5, 0))
        
        self.username_entry = ttk.Entry(
            form_frame,
            font=("Segoe UI", 11),
            style="Custom.TEntry"
        )
        self.username_entry.pack(fill="x", pady=(0, 15), ipady=5)
        
        # Password field
        tk.Label(
            form_frame,
            text="Password",
            font=("Segoe UI", 10),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text_light"]
        ).pack(anchor="w", pady=(5, 0))
        
        self.password_entry = ttk.Entry(
            form_frame,
            show="•",
            font=("Segoe UI", 11),
            style="Custom.TEntry"
        )
        self.password_entry.pack(fill="x", pady=(0, 20), ipady=5)
        
        # Login button
        login_btn = ttk.Button(
            form_frame,
            text="Login",
            command=self.on_submit,
            style="Accent.TButton"
        )
        login_btn.pack(fill="x", pady=(10, 0), ipady=8)
        
        # Footer
        footer_frame = tk.Frame(main_frame, bg=self.current_colors["bg"])
        footer_frame.pack(fill="x", pady=(20, 0))
        
        tk.Label(
            footer_frame,
            text="© 2023 Secure Token Manager",
            font=("Segoe UI", 9),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text_light"]
        ).pack(side="right")
        
        self.bind("<Return>", lambda e: self.on_submit())
        self.username_entry.focus_set()
        
    def on_submit(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        
        if not username or not password:
            messagebox.showerror("Error", "Username and password are required.")
            return
            
        self.username = username
        self.password = password
        self.destroy()

class TokenDisplayDialog(tk.Toplevel):
    def __init__(self, parent, title, token, payload=None):
        super().__init__(parent)
        self.title(title)
        self.token = token
        self.payload = payload
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        
        self.configure(bg=self.current_colors["bg"])
        self.resizable(True, True)
        
        window_width = 750
        window_height = 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        self.grab_set()
        self.focus_force()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self, bg=self.current_colors["primary"], height=60)
        header_frame.pack(fill="x")
        
        tk.Label(
            header_frame,
            text="Token Details",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg=self.current_colors["primary"]
        ).pack(side="left", padx=20)
        
        close_btn = tk.Button(
            header_frame,
            text="×",
            font=("Arial", 16),
            command=self.destroy,
            bd=0,
            fg="white",
            bg=self.current_colors["primary"],
            activebackground=self.current_colors["secondary"],
            activeforeground="white"
        )
        close_btn.pack(side="right", padx=15)
        
        # Main content
        main_frame = tk.Frame(self, bg=self.current_colors["bg"])
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Notebook for tabs
        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True)
        
        # Token tab
        token_frame = ttk.Frame(notebook)
        notebook.add(token_frame, text="Token")
        
        # Payload tab if available
        if self.payload:
            payload_frame = ttk.Frame(notebook)
            notebook.add(payload_frame, text="Payload")
            self.create_payload_tab(payload_frame)
        
        # QR Code tab
        qr_frame = ttk.Frame(notebook)
        notebook.add(qr_frame, text="QR Code")
        self.create_qr_tab(qr_frame)
        
        # Token display
        tk.Label(
            token_frame,
            text="Token:",
            font=("Segoe UI", 10, "bold"),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).pack(anchor="w", pady=(5, 0))
        
        self.token_text = scrolledtext.ScrolledText(
            token_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            width=80,
            height=15,
            padx=10,
            pady=10,
            bg=self.current_colors["card"],
            fg=self.current_colors["text"],
            insertbackground=self.current_colors["text"],
            bd=1,
            relief="solid",
            highlightthickness=0
        )
        self.token_text.pack(fill="both", expand=True, padx=5, pady=5)
        self.token_text.insert("1.0", self.token)
        self.token_text.config(state="disabled")
        
        # Button frame
        btn_frame = tk.Frame(token_frame, bg=self.current_colors["bg"])
        btn_frame.pack(fill="x", pady=(10, 0))
        
        # Copy button
        copy_btn = ttk.Button(
            btn_frame,
            text="Copy to Clipboard",
            command=self.copy_token,
            style="Accent.TButton"
        )
        copy_btn.pack(side="left", padx=5)
        
        # Save to file button
        save_btn = ttk.Button(
            btn_frame,
            text="Save to File",
            command=self.save_to_file
        )
        save_btn.pack(side="left", padx=5)
        
        # Close button
        close_btn = ttk.Button(
            btn_frame,
            text="Close",
            command=self.destroy
        )
        close_btn.pack(side="right", padx=5)
        
    def create_payload_tab(self, parent):
        payload_str = json.dumps(self.payload, indent=2)
        
        tk.Label(
            parent,
            text="Decoded Payload:",
            font=("Segoe UI", 10, "bold"),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).pack(anchor="w", pady=(5, 0))
        
        payload_text = scrolledtext.ScrolledText(
            parent,
            wrap=tk.WORD,
            font=("Consolas", 11),
            width=80,
            height=15,
            padx=10,
            pady=10,
            bg=self.current_colors["card"],
            fg=self.current_colors["text"],
            insertbackground=self.current_colors["text"],
            bd=1,
            relief="solid",
            highlightthickness=0
        )
        payload_text.pack(fill="both", expand=True, padx=5, pady=5)
        payload_text.insert("1.0", payload_str)
        payload_text.config(state="disabled")
        
        # Add button frame
        btn_frame = tk.Frame(parent, bg=self.current_colors["bg"])
        btn_frame.pack(fill="x", pady=(10, 0))
        
        # Copy button
        copy_btn = ttk.Button(
            btn_frame,
            text="Copy Payload",
            command=lambda: pyperclip.copy(payload_str),
            style="Accent.TButton"
        )
        copy_btn.pack(side="left", padx=5)
        
    def create_qr_tab(self, parent):
        try:
            qr_img = generate_qr_code(self.token)
            
            qr_label = tk.Label(parent, image=qr_img, bg="white")
            qr_label.image = qr_img
            qr_label.pack(pady=20)
            
            tk.Label(
                parent,
                text="Scan this QR code to transfer the token to a mobile device",
                font=("Segoe UI", 10),
                bg=self.current_colors["bg"],
                fg=self.current_colors["text_light"]
            ).pack(pady=(0, 10))
            
            # Save QR button
            save_btn = ttk.Button(
                parent,
                text="Save QR Code",
                command=lambda: self.save_qr_code(qr_img),
                style="Accent.TButton"
            )
            save_btn.pack(pady=5)
        except Exception as e:
            tk.Label(
                parent,
                text=f"Failed to generate QR code: {str(e)}",
                font=("Segoe UI", 10),
                fg=self.current_colors["danger"],
                bg=self.current_colors["bg"]
            ).pack(pady=20)
    
    def save_qr_code(self, qr_img):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
            title="Save QR Code As"
        )
        if file_path:
            try:
                with open(file_path, "wb") as f:
                    f.write(qr_img.data)
                messagebox.showinfo("Success", "QR code saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save QR code: {str(e)}")
        
    def copy_token(self):
        pyperclip.copy(self.token)
        messagebox.showinfo("Success", "Token copied to clipboard.")
        
    def save_to_file(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")],
            title="Save Token As"
        )
        if file_path:
            try:
                with open(file_path, "w") as f:
                    f.write(self.token)
                messagebox.showinfo("Success", "Token saved successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save token: {str(e)}")

class TokenGeneratorDialog(tk.Toplevel):
    def __init__(self, parent, username):
        super().__init__(parent)
        self.title("Generate Tokens")
        self.username = username
        self.parent = parent
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        
        self.configure(bg=self.current_colors["bg"])
        self.resizable(False, False)
        
        # Center window
        window_width = 600
        window_height = 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Make modal
        self.grab_set()
        self.focus_force()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self, bg=self.current_colors["primary"], height=60)
        header_frame.pack(fill="x")
        
        tk.Label(
            header_frame,
            text="Generate New Tokens",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg=self.current_colors["primary"]
        ).pack(side="left", padx=20)
        
        # Close button
        close_btn = tk.Button(
            header_frame,
            text="×",
            font=("Arial", 16),
            command=self.destroy,
            bd=0,
            fg="white",
            bg=self.current_colors["primary"],
            activebackground=self.current_colors["secondary"],
            activeforeground="white"
        )
        close_btn.pack(side="right", padx=15)
        
        # Main form
        form_frame = tk.Frame(self, bg=self.current_colors["bg"], padx=25, pady=25)
        form_frame.pack(fill="both", expand=True)
        
        # User ID field
        tk.Label(
            form_frame,
            text="User ID:",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        self.user_id_entry = ttk.Entry(form_frame, font=("Segoe UI", 11))
        self.user_id_entry.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        self.user_id_entry.insert(0, self.username)
        
        # Roles field
        tk.Label(
            form_frame,
            text="Roles (comma separated):",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).grid(row=2, column=0, sticky="w", pady=(0, 5))
        
        self.roles_entry = ttk.Entry(form_frame, font=("Segoe UI", 11))
        self.roles_entry.grid(row=3, column=0, sticky="ew", pady=(0, 15))
        self.roles_entry.insert(0, "user")
        
        # Permissions field
        tk.Label(
            form_frame,
            text="Permissions (comma separated):",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).grid(row=4, column=0, sticky="w", pady=(0, 5))
        
        self.perms_entry = ttk.Entry(form_frame, font=("Segoe UI", 11))
        self.perms_entry.grid(row=5, column=0, sticky="ew", pady=(0, 15))
        self.perms_entry.insert(0, "read,write")
        
        # Custom claims
        tk.Label(
            form_frame,
            text="Custom Claims (JSON format):",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).grid(row=6, column=0, sticky="w", pady=(0, 5))
        
        self.claims_text = scrolledtext.ScrolledText(
            form_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            width=50,
            height=6,
            padx=10,
            pady=10,
            bg=self.current_colors["card"],
            fg=self.current_colors["text"],
            insertbackground="white",
            bd=1,
            relief="solid"
        )
        self.claims_text.grid(row=7, column=0, sticky="ew", pady=(0, 15))
        self.claims_text.insert("1.0", '{\n  "custom_claim": "value"\n}')
        
        # Secret key field
        tk.Label(
            form_frame,
            text="Secret Key:",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).grid(row=8, column=0, sticky="w", pady=(0, 5))
        
        self.secret_entry = ttk.Entry(form_frame, show="•", font=("Segoe UI", 11))
        self.secret_entry.grid(row=9, column=0, sticky="ew", pady=(0, 20))
        
        # Button frame
        btn_frame = tk.Frame(form_frame, bg=self.current_colors["bg"])
        btn_frame.grid(row=10, column=0, sticky="ew", pady=(10, 0))
        
        # Generate button
        gen_btn = ttk.Button(
            btn_frame,
            text="Generate Tokens",
            command=self.generate_tokens,
            style="Accent.TButton"
        )
        gen_btn.pack(side="right", padx=5)
        
        # Cancel button
        cancel_btn = ttk.Button(
            btn_frame,
            text="Cancel",
            command=self.destroy
        )
        cancel_btn.pack(side="right", padx=5)
        
    def generate_tokens(self):
        user_id = self.user_id_entry.get().strip()
        roles = [r.strip() for r in self.roles_entry.get().split(",") if r.strip()]
        permissions = [p.strip() for p in self.perms_entry.get().split(",") if p.strip()]
        secret_key = self.secret_entry.get().strip()
        
        # Parse custom claims
        custom_claims = None
        claims_text = self.claims_text.get("1.0", tk.END).strip()
        if claims_text:
            try:
                custom_claims = json.loads(claims_text)
            except json.JSONDecodeError as e:
                messagebox.showerror("Error", f"Invalid JSON in custom claims: {str(e)}")
                return
        
        if not user_id:
            messagebox.showerror("Error", "User ID is required.")
            return
            
        if not secret_key:
            messagebox.showerror("Error", "Secret key is required.")
            return
            
        try:
            access_token, refresh_token, access_payload, refresh_payload = create_jwt_with_claims(
                user_id, roles, permissions, secret_key, custom_claims
            )
            save_tokens_to_json(self.username, access_token, refresh_token)
            
            # Show tokens in separate dialogs
            TokenDisplayDialog(self.parent, "Access Token", access_token, access_payload)
            TokenDisplayDialog(self.parent, "Refresh Token", refresh_token, refresh_payload)
            
            messagebox.showinfo("Success", "Tokens generated and saved securely.")
            self.destroy()
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate tokens: {str(e)}")

class TokenValidatorDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Validate Token")
        self.parent = parent
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        
        self.configure(bg=self.current_colors["bg"])
        self.resizable(False, False)
        
        # Center window
        window_width = 600
        window_height = 450
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Make modal
        self.grab_set()
        self.focus_force()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self, bg=self.current_colors["primary"], height=60)
        header_frame.pack(fill="x")
        
        tk.Label(
            header_frame,
            text="Validate Token",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg=self.current_colors["primary"]
        ).pack(side="left", padx=20)
        
        # Close button
        close_btn = tk.Button(
            header_frame,
            text="×",
            font=("Arial", 16),
            command=self.destroy,
            bd=0,
            fg="white",
            bg=self.current_colors["primary"],
            activebackground=self.current_colors["secondary"],
            activeforeground="white"
        )
        close_btn.pack(side="right", padx=15)
        
        # Main form
        form_frame = tk.Frame(self, bg=self.current_colors["bg"], padx=25, pady=25)
        form_frame.pack(fill="both", expand=True)
        
        # Token input
        tk.Label(
            form_frame,
            text="Enter JWT Token:",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).pack(anchor="w", pady=(0, 5))
        
        self.token_text = scrolledtext.ScrolledText(
            form_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            width=60,
            height=10,
            padx=10,
            pady=10,
            bg=self.current_colors["card"],
            fg=self.current_colors["text"],
            insertbackground="white",
            bd=1,
            relief="solid"
        )
        self.token_text.pack(fill="both", expand=True)
        
        # Secret key
        tk.Label(
            form_frame,
            text="Secret Key:",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).pack(anchor="w", pady=(5, 5))
        
        self.secret_entry = ttk.Entry(form_frame, show="•", font=("Segoe UI", 11))
        self.secret_entry.pack(fill="x", pady=(0, 15))
        
        # Button frame
        btn_frame = tk.Frame(form_frame, bg=self.current_colors["bg"])
        btn_frame.pack(fill="x")
        
        # Validate button
        validate_btn = ttk.Button(
            btn_frame,
            text="Validate",
            command=self.validate_token,
            style="Accent.TButton"
        )
        validate_btn.pack(side="right", padx=5)
        
        # Paste button
        paste_btn = ttk.Button(
            btn_frame,
            text="Paste",
            command=self.paste_token
        )
        paste_btn.pack(side="left", padx=5)
        
        # Load from file button
        load_btn = ttk.Button(
            btn_frame,
            text="Load from File",
            command=self.load_from_file
        )
        load_btn.pack(side="left", padx=5)
        
        # Cancel button
        cancel_btn = ttk.Button(
            btn_frame,
            text="Cancel",
            command=self.destroy
        )
        cancel_btn.pack(side="right", padx=5)
        
    def paste_token(self):
        try:
            clipboard_text = pyperclip.paste()
            self.token_text.delete("1.0", tk.END)
            self.token_text.insert("1.0", clipboard_text)
        except:
            messagebox.showerror("Error", "Failed to paste from clipboard")
    
    def load_from_file(self):
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("JSON files", "*.json"), ("All files", "*.*")],
            title="Select Token File"
        )
        if file_path:
            try:
                with open(file_path, "r") as f:
                    token = f.read()
                self.token_text.delete("1.0", tk.END)
                self.token_text.insert("1.0", token)
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load token: {str(e)}")
        
    def validate_token(self):
        token = self.token_text.get("1.0", tk.END).strip()
        secret_key = self.secret_entry.get().strip()
        
        if not token:
            messagebox.showerror("Error", "Token is required.")
            return
            
        if not secret_key:
            messagebox.showerror("Error", "Secret key is required.")
            return
            
        payload = validate_jwt(token, secret_key)
        if payload:
            # Display payload in a formatted way
            payload_str = json.dumps(payload, indent=2)
            TokenDisplayDialog(self.parent, "Token Payload", token, payload)
        else:
            messagebox.showerror("Error", "Token is invalid or expired.")

class TokenHistoryDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Token History")
        self.parent = parent
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        
        self.configure(bg=self.current_colors["bg"])
        self.resizable(True, True)
        
        # Center window
        window_width = 850
        window_height = 650
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Make modal
        self.grab_set()
        self.focus_force()
        
        self.create_widgets()
        self.load_history()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self, bg=self.current_colors["primary"], height=60)
        header_frame.pack(fill="x")
        
        tk.Label(
            header_frame,
            text="Token History",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg=self.current_colors["primary"]
        ).pack(side="left", padx=20)
        
        # Close button
        close_btn = tk.Button(
            header_frame,
            text="×",
            font=("Arial", 16),
            command=self.destroy,
            bd=0,
            fg="white",
            bg=self.current_colors["primary"],
            activebackground=self.current_colors["secondary"],
            activeforeground="white"
        )
        close_btn.pack(side="right", padx=15)
        
        # Main content
        main_frame = tk.Frame(self, bg=self.current_colors["bg"])
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Treeview for history
        style = ttk.Style()
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        
        self.tree = ttk.Treeview(main_frame, columns=("username", "timestamp"), show="headings")
        self.tree.heading("username", text="Username")
        self.tree.heading("timestamp", text="Timestamp")
        self.tree.column("username", width=200, anchor="w")
        self.tree.column("timestamp", width=250, anchor="w")
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(main_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Button frame
        btn_frame = tk.Frame(main_frame, bg=self.current_colors["bg"])
        btn_frame.pack(fill="x", pady=(10, 0))
        
        # View button
        view_btn = ttk.Button(
            btn_frame,
            text="View Token",
            command=self.view_token,
            style="Accent.TButton"
        )
        view_btn.pack(side="left", padx=5)
        
        # Refresh button
        refresh_btn = ttk.Button(
            btn_frame,
            text="Refresh",
            command=self.load_history
        )
        refresh_btn.pack(side="left", padx=5)
        
        # Clear button
        clear_btn = ttk.Button(
            btn_frame,
            text="Clear History",
            command=self.clear_history
        )
        clear_btn.pack(side="right", padx=5)
        
    def load_history(self):
        history = load_token_history()
        self.tree.delete(*self.tree.get_children())
        
        for i, entry in enumerate(reversed(history)):  # Show newest first
            self.tree.insert("", "end", values=(entry["username"], entry["timestamp"]), iid=str(i))
        
    def view_token(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry from the history.")
            return
            
        index = int(selected[0])
        history = load_token_history()
        entry = history[-(index+1)]  # Reverse index since we displayed in reverse
        
        TokenDisplayDialog(self.parent, "Historical Token", entry["access_token"])
        
    def clear_history(self):
        if messagebox.askyesno("Confirm", "Are you sure you want to clear all history?"):
            save_token_history([])
            self.load_history()

class SettingsDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("Settings")
        self.parent = parent
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        
        self.configure(bg=self.current_colors["bg"])
        self.resizable(False, False)
        
        # Center window
        window_width = 450
        window_height = 350
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Make modal
        self.grab_set()
        self.focus_force()
        
        self.create_widgets()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self, bg=self.current_colors["primary"], height=60)
        header_frame.pack(fill="x")
        
        tk.Label(
            header_frame,
            text="Application Settings",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg=self.current_colors["primary"]
        ).pack(side="left", padx=20)
        
        # Close button
        close_btn = tk.Button(
            header_frame,
            text="×",
            font=("Arial", 16),
            command=self.destroy,
            bd=0,
            fg="white",
            bg=self.current_colors["primary"],
            activebackground=self.current_colors["secondary"],
            activeforeground="white"
        )
        close_btn.pack(side="right", padx=15)
        
        # Main form
        form_frame = tk.Frame(self, bg=self.current_colors["bg"], padx=25, pady=25)
        form_frame.pack(fill="both", expand=True)
        
        # Theme selection
        tk.Label(
            form_frame,
            text="Theme:",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).grid(row=0, column=0, sticky="w", pady=(0, 5))
        
        self.theme_var = tk.StringVar(value=settings["theme"])
        theme_menu = ttk.OptionMenu(
            form_frame,
            self.theme_var,
            settings["theme"],
            "light",
            "dark",
            "system"
        )
        theme_menu.grid(row=1, column=0, sticky="ew", pady=(0, 15))
        
        # Font size
        tk.Label(
            form_frame,
            text="Font Size:",
            font=("Segoe UI", 11),
            bg=self.current_colors["bg"],
            fg=self.current_colors["text"]
        ).grid(row=2, column=0, sticky="w", pady=(0, 5))
        
        self.font_size_var = tk.StringVar(value=str(settings["font_size"]))
        font_size_spin = ttk.Spinbox(
            form_frame,
            from_=8,
            to=16,
            textvariable=self.font_size_var,
            width=5
        )
        font_size_spin.grid(row=3, column=0, sticky="w", pady=(0, 15))
        
        # Auto-refresh
        self.auto_refresh_var = tk.BooleanVar(value=settings["auto_refresh"])
        auto_refresh_cb = ttk.Checkbutton(
            form_frame,
            text="Auto-refresh tokens when expired",
            variable=self.auto_refresh_var
        )
        auto_refresh_cb.grid(row=4, column=0, sticky="w", pady=(0, 15))
        
        # Button frame
        btn_frame = tk.Frame(form_frame, bg=self.current_colors["bg"])
        btn_frame.grid(row=5, column=0, sticky="ew", pady=(10, 0))
        
        # Save button
        save_btn = ttk.Button(
            btn_frame,
            text="Save Settings",
            command=self.save_settings,
            style="Accent.TButton"
        )
        save_btn.pack(side="right", padx=5)
        
        # Cancel button
        cancel_btn = ttk.Button(
            btn_frame,
            text="Cancel",
            command=self.destroy
        )
        cancel_btn.pack(side="right", padx=5)
        
    def save_settings(self):
        new_settings = {
            "theme": self.theme_var.get(),
            "font_size": int(self.font_size_var.get()),
            "auto_refresh": self.auto_refresh_var.get()
        }
        
        # Apply theme change immediately if different
        if new_settings["theme"] != settings["theme"]:
            sv_ttk.set_theme(new_settings["theme"])
            
        # Update global settings
        settings.update(new_settings)
        save_settings(settings)
        
        messagebox.showinfo("Success", "Settings saved. Some changes may require restart to take full effect.")
        self.destroy()

class DocumentationDialog(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("JWT Documentation")
        self.parent = parent
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        
        self.configure(bg=self.current_colors["bg"])
        self.resizable(True, True)
        
        # Center window
        window_width = 850
        window_height = 650
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        x = (screen_width - window_width) // 2
        y = (screen_height - window_height) // 2
        self.geometry(f"{window_width}x{window_height}+{x}+{y}")
        
        # Make modal
        self.grab_set()
        self.focus_force()
        
        self.create_widgets()
        self.load_documentation()
        
    def create_widgets(self):
        # Header
        header_frame = tk.Frame(self, bg=self.current_colors["primary"], height=60)
        header_frame.pack(fill="x")
        
        tk.Label(
            header_frame,
            text="JWT Documentation",
            font=("Segoe UI", 16, "bold"),
            fg="white",
            bg=self.current_colors["primary"]
        ).pack(side="left", padx=20)
        
        # Close button
        close_btn = tk.Button(
            header_frame,
            text="×",
            font=("Arial", 16),
            command=self.destroy,
            bd=0,
            fg="white",
            bg=self.current_colors["primary"],
            activebackground=self.current_colors["secondary"],
            activeforeground="white"
        )
        close_btn.pack(side="right", padx=15)
        
        # Refresh button
        refresh_btn = ttk.Button(
            header_frame,
            text="Refresh",
            command=self.load_documentation,
            style="Accent.TButton"
        )
        refresh_btn.pack(side="right", padx=5)
        
        # Main content
        main_frame = tk.Frame(self, bg=self.current_colors["bg"])
        main_frame.pack(fill="both", expand=True, padx=15, pady=15)
        
        # Documentation text
        self.doc_text = scrolledtext.ScrolledText(
            main_frame,
            wrap=tk.WORD,
            font=("Segoe UI", 11),
            width=80,
            height=30,
            padx=15,
            pady=15,
            bg=self.current_colors["card"],
            fg=self.current_colors["text"],
            insertbackground="white",
            bd=1,
            relief="solid"
        )
        self.doc_text.pack(fill="both", expand=True)
        self.doc_text.config(state="disabled")
        
        # Button frame
        btn_frame = tk.Frame(main_frame, bg=self.current_colors["bg"])
        btn_frame.pack(fill="x", pady=(10, 0))
        
        # Open in browser button
        browser_btn = ttk.Button(
            btn_frame,
            text="Open in Browser",
            command=lambda: webbrowser.open("https://jwt.io/introduction/"),
            style="Accent.TButton"
        )
        browser_btn.pack(side="left", padx=5)
        
    def load_documentation(self):
        self.doc_text.config(state="normal")
        self.doc_text.delete("1.0", tk.END)
        
        # Show loading message
        self.doc_text.insert("1.0", "Loading documentation...")
        self.update()
        
        # Fetch documentation in background
        def fetch_docs():
            docs = get_jwt_documentation()
            self.doc_text.delete("1.0", tk.END)
            self.doc_text.insert("1.0", docs)
            self.doc_text.config(state="disabled")
            
        threading.Thread(target=fetch_docs, daemon=True).start()

class MainApplication(ttk.Frame):
    def __init__(self, parent, username):
        super().__init__(parent)
        self.parent = parent
        self.username = username
        self.current_colors = DARK_COLORS if settings["theme"] == "dark" else COLORS
        
        # Configure main window
        self.parent.title("Secure Token Manager")
        self.parent.geometry("1100x750")
        self.parent.minsize(900, 600)
        
        # Setup styles
        self.setup_styles()
        
        # Create UI
        self.create_widgets()
        
        # Check for updates
        self.check_updates()
        
    def setup_styles(self):
        style = ttk.Style()
        
        # Configure main styles
        style.configure(".", font=("Segoe UI", settings["font_size"]))
        
        # Configure notebook
        style.configure("TNotebook", padding=5)
        style.configure("TNotebook.Tab", padding=(10, 5), font=("Segoe UI", 10, "bold"))
        
        # Configure treeview
        style.configure("Treeview", rowheight=28, background=self.current_colors["card"])
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background=self.current_colors["light"])
        style.map("Treeview", background=[("selected", self.current_colors["primary"])])
        
        # Configure buttons
        style.configure("Accent.TButton", foreground="white", background=self.current_colors["primary"])
        style.map("Accent.TButton",
            background=[("active", self.current_colors["secondary"]), ("disabled", "gray")],
            foreground=[("disabled", "white")]
        )
        
    def create_widgets(self):
        # Main container
        self.pack(fill="both", expand=True)
        
        # Header
        header_frame = tk.Frame(self, height=80, bg=self.current_colors["primary"])
        header_frame.pack(fill="x", pady=(0, 10))
        
        # Logo and title
        logo_label = tk.Label(
            header_frame,
            text="🔐",
            font=("Segoe UI", 28),
            bg=self.current_colors["primary"],
            fg="white"
        )
        logo_label.pack(side="left", padx=(25, 15))
        
        title_label = tk.Label(
            header_frame,
            text="Secure Token Manager",
            font=("Segoe UI", 20, "bold"),
            bg=self.current_colors["primary"],
            fg="white"
        )
        title_label.pack(side="left")
        
        # Menu buttons
        menu_frame = tk.Frame(header_frame, bg=self.current_colors["primary"])
        menu_frame.pack(side="right", padx=25)
        
        # Settings button
        settings_btn = ttk.Button(
            menu_frame,
            text="⚙️",
            command=self.show_settings,
            style="Toolbutton.TButton",
            width=3
        )
        settings_btn.pack(side="left", padx=5)
        
        # Docs button
        docs_btn = ttk.Button(
            menu_frame,
            text="📖",
            command=self.show_documentation,
            style="Toolbutton.TButton",
            width=3
        )
        docs_btn.pack(side="left", padx=5)
        
        # User info
        user_frame = tk.Frame(header_frame, bg=self.current_colors["primary"])
        user_frame.pack(side="right", padx=25)
        
        tk.Label(
            user_frame,
            text=f"Logged in as:",
            font=("Segoe UI", 10),
            bg=self.current_colors["primary"],
            fg="#e9ecef"
        ).pack(anchor="e")
        
        tk.Label(
            user_frame,
            text=self.username,
            font=("Segoe UI", 11, "bold"),
            bg=self.current_colors["primary"],
            fg="white"
        ).pack(anchor="e")
        
        # Main content
        notebook = ttk.Notebook(self)
        notebook.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Token generation tab
        gen_frame = ttk.Frame(notebook)
        notebook.add(gen_frame, text="Generate Tokens")
        self.create_generation_tab(gen_frame)
        
        # Token validation tab
        val_frame = ttk.Frame(notebook)
        notebook.add(val_frame, text="Validate Tokens")
        self.create_validation_tab(val_frame)
        
        # Token management tab
        mgmt_frame = ttk.Frame(notebook)
        notebook.add(mgmt_frame, text="Token Management")
        self.create_management_tab(mgmt_frame)
        
        # Status bar
        status_frame = tk.Frame(self, height=30, bg=self.current_colors["primary"])
        status_frame.pack(fill="x", side="bottom")
        
        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            font=("Segoe UI", 10),
            bg=self.current_colors["primary"],
            fg="white"
        )
        self.status_label.pack(side="left", padx=15)
        
    def create_generation_tab(self, parent):
        # Instructions
        instr_frame = ttk.Frame(parent)
        instr_frame.pack(fill="x", padx=25, pady=25)
        
        ttk.Label(
            instr_frame,
            text="Generate new JWT tokens with custom claims",
            font=("Segoe UI", 12, "bold"),
            foreground=self.current_colors["text"]
        ).pack(anchor="w")
        
        ttk.Label(
            instr_frame,
            text="Create access and refresh tokens with specified roles and permissions.",
            font=("Segoe UI", 10),
            foreground=self.current_colors["text_light"]
        ).pack(anchor="w", pady=(0, 15))
        
        # Generate button
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill="x", padx=25, pady=10)
        
        gen_btn = ttk.Button(
            btn_frame,
            text="Generate New Tokens",
            command=self.generate_tokens,
            style="Accent.TButton",
            width=25
        )
        gen_btn.pack(pady=10)
        
        # Recent tokens
        recent_frame = ttk.LabelFrame(parent, text="Recent Tokens", padding=15)
        recent_frame.pack(fill="both", expand=True, padx=25, pady=(0, 25))
        
        # History button
        history_btn = ttk.Button(
            recent_frame,
            text="View Full History",
            command=self.show_history,
            style="Accent.TButton"
        )
        history_btn.pack(anchor="e", pady=(0, 15))
        
        # Treeview for recent tokens
        columns = ("timestamp", "user_id", "roles")
        self.recent_tree = ttk.Treeview(recent_frame, columns=columns, show="headings")
        self.recent_tree.heading("timestamp", text="Timestamp")
        self.recent_tree.heading("user_id", text="User ID")
        self.recent_tree.heading("roles", text="Roles")
        
        self.recent_tree.column("timestamp", width=200)
        self.recent_tree.column("user_id", width=150)
        self.recent_tree.column("roles", width=250)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(recent_frame, orient="vertical", command=self.recent_tree.yview)
        self.recent_tree.configure(yscrollcommand=scrollbar.set)
        
        # Pack tree and scrollbar
        self.recent_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Load recent tokens
        self.load_recent_tokens()
        
    def create_validation_tab(self, parent):
        # Instructions
        instr_frame = ttk.Frame(parent)
        instr_frame.pack(fill="x", padx=25, pady=25)
        
        ttk.Label(
            instr_frame,
            text="Validate and inspect JWT tokens",
            font=("Segoe UI", 12, "bold"),
            foreground=self.current_colors["text"]
        ).pack(anchor="w")
        
        ttk.Label(
            instr_frame,
            text="Check token validity, expiration, and view decoded payload.",
            font=("Segoe UI", 10),
            foreground=self.current_colors["text_light"]
        ).pack(anchor="w", pady=(0, 15))
        
        # Validate button
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill="x", padx=25, pady=10)
        
        val_btn = ttk.Button(
            btn_frame,
            text="Validate Token",
            command=self.validate_token,
            style="Accent.TButton",
            width=25
        )
        val_btn.pack(pady=10)
        
        # Token info
        info_frame = ttk.LabelFrame(parent, text="Token Information", padding=15)
        info_frame.pack(fill="both", expand=True, padx=25, pady=(0, 25))
        
        # Placeholder for token info
        self.token_info_text = scrolledtext.ScrolledText(
            info_frame,
            wrap=tk.WORD,
            font=("Consolas", 11),
            width=80,
            height=15,
            padx=15,
            pady=15,
            bg=self.current_colors["card"],
            fg=self.current_colors["text"],
            insertbackground="white",
            bd=1,
            relief="solid"
        )
        self.token_info_text.pack(fill="both", expand=True)
        self.token_info_text.insert("1.0", "No token information to display")
        self.token_info_text.config(state="disabled")
        
    def create_management_tab(self, parent):
        # Instructions
        instr_frame = ttk.Frame(parent)
        instr_frame.pack(fill="x", padx=25, pady=25)
        
        ttk.Label(
            instr_frame,
            text="Manage your JWT tokens",
            font=("Segoe UI", 12, "bold"),
            foreground=self.current_colors["text"]
        ).pack(anchor="w")
        
        ttk.Label(
            instr_frame,
            text="Refresh or revoke existing tokens.",
            font=("Segoe UI", 10),
            foreground=self.current_colors["text_light"]
        ).pack(anchor="w", pady=(0, 15))
        
        # Action buttons
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill="x", padx=25, pady=10)
        
        refresh_btn = ttk.Button(
            btn_frame,
            text="Refresh Token",
            command=self.refresh_token,
            style="Accent.TButton",
            width=18
        )
        refresh_btn.pack(side="left", padx=5)
        
        revoke_btn = ttk.Button(
            btn_frame,
            text="Revoke Token",
            command=self.revoke_token,
            width=18
        )
        revoke_btn.pack(side="left", padx=5)
        
        blacklist_btn = ttk.Button(
            btn_frame,
            text="View Blacklist",
            command=self.view_blacklist,
            width=18
        )
        blacklist_btn.pack(side="left", padx=5)
        
        # Token list
        list_frame = ttk.LabelFrame(parent, text="Your Tokens", padding=15)
        list_frame.pack(fill="both", expand=True, padx=25, pady=(0, 25))
        
        # Load current tokens
        access_token, refresh_token = load_tokens_from_json(self.username)
        
        if access_token or refresh_token:
            # Display tokens in a treeview
            self.token_tree = ttk.Treeview(list_frame, columns=("type", "status"), show="headings")
            self.token_tree.heading("type", text="Token Type")
            self.token_tree.heading("status", text="Status")
            
            self.token_tree.column("type", width=200)
            self.token_tree.column("status", width=200)
            
            if access_token:
                status = self.get_token_status(access_token)
                self.token_tree.insert("", "end", values=("Access Token", status))
                
            if refresh_token:
                status = self.get_token_status(refresh_token)
                self.token_tree.insert("", "end", values=("Refresh Token", status))
                
            # Add scrollbar
            scrollbar = ttk.Scrollbar(list_frame, orient="vertical", command=self.token_tree.yview)
            self.token_tree.configure(yscrollcommand=scrollbar.set)
            
            # Pack tree and scrollbar
            self.token_tree.pack(side="left", fill="both", expand=True)
            scrollbar.pack(side="right", fill="y")
        else:
            ttk.Label(
                list_frame,
                text="No tokens available",
                font=("Segoe UI", 10),
                foreground=self.current_colors["text_light"]
            ).pack(expand=True)
            
    def get_token_status(self, token):
        try:
            payload = jwt.decode(token, options={"verify_signature": False})
            exp = payload.get("exp", 0)
            if exp < int(datetime.now(timezone.utc).timestamp()):
                return "Expired"
            return "Valid"
        except:
            return "Invalid"
            
    def load_recent_tokens(self):
        history = load_token_history()
        self.recent_tree.delete(*self.recent_tree.get_children())
        
        for entry in reversed(history[-5:]):  # Show last 5 entries
            try:
                payload = jwt.decode(entry["access_token"], options={"verify_signature": False})
                roles = ", ".join(payload.get("roles", []))
                self.recent_tree.insert("", "end", values=(
                    entry["timestamp"],
                    payload.get("sub", "N/A"),
                    roles
                ))
            except:
                continue
                
    def generate_tokens(self):
        dialog = TokenGeneratorDialog(self.parent, self.username)
        self.parent.wait_window(dialog)
        self.load_recent_tokens()
        
    def validate_token(self):
        dialog = TokenValidatorDialog(self.parent)
        self.parent.wait_window(dialog)
        
    def refresh_token(self):
        # Load the refresh token for this user
        _, refresh_token = load_tokens_from_json(self.username)
        
        if not refresh_token:
            messagebox.showerror("Error", "No refresh token found for this user.")
            return
            
        secret_key = simpledialog.askstring("Refresh Token", "Enter secret key:", show="*")
        if not secret_key:
            return
            
        new_access_token = refresh_access_token(refresh_token, secret_key)
        if new_access_token:
            # Save the new access token
            save_tokens_to_json(self.username, new_access_token, refresh_token)
            TokenDisplayDialog(self.parent, "New Access Token", new_access_token)
        else:
            messagebox.showerror("Error", "Failed to refresh token.")
            
    def revoke_token(self):
        token = simpledialog.askstring("Revoke Token", "Enter token to revoke:")
        if not token:
            return
            
        secret_key = simpledialog.askstring("Revoke Token", "Enter secret key:", show="*")
        if not secret_key:
            return
            
        revoke_token(token, secret_key)
        
    def view_blacklist(self):
        blacklist_content = "\n".join(blacklist)
        TokenDisplayDialog(self.parent, "Blacklisted Tokens", blacklist_content)
        
    def show_history(self):
        dialog = TokenHistoryDialog(self.parent)
        self.parent.wait_window(dialog)
        self.load_recent_tokens()
        
    def show_settings(self):
        dialog = SettingsDialog(self.parent)
        self.parent.wait_window(dialog)
        
    def show_documentation(self):
        dialog = DocumentationDialog(self.parent)
        self.parent.wait_window(dialog)
        
    def check_updates(self):
        def update_check():
            update_available, latest_version = check_for_updates()
            if update_available:
                self.status_label.config(text=f"Update available: v{latest_version}")
                
        threading.Thread(target=update_check, daemon=True).start()

# --- Application Entry Point ---
if __name__ == "__main__":
    # Initialize directories and settings
    ensure_directory_exists(TOKENS_DIR)
    blacklist = load_blacklist()
    settings = load_settings()
    
    # Create root window with theme
    root = ThemedTk(theme="arc")
    root.withdraw()  # Hide until we're authenticated
    
    # Apply theme
    sv_ttk.set_theme(settings["theme"])
    
    # Show login dialog
    auth_dialog = AuthDialog(root, "Login")
    root.wait_window(auth_dialog)
    
    if auth_dialog.username:
        # User authenticated, show main app
        root.deiconify()
        app = MainApplication(root, auth_dialog.username)
        root.mainloop()


 # JWT Token Manager

![Python](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![License](https://img.shields.io/github/license/yourusername/jwt-token-manager)
![Last Updated](https://img.shields.io/github/last-commit/yourusername/jwt-token-manager)

A secure desktop application for managing **JSON Web Tokens (JWT)** with a clean and modern interface. Create, validate, refresh, and revoke tokens with custom claims and secure handling.

---

## 📑 Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Screenshots](#screenshots)
- [Documentation](#documentation)
- [Contributing](#contributing)
- [License](#license)

---

## ✨ Features

### 🔐 Token Generation
- Create **access** and **refresh** tokens
- Add custom claims (e.g., roles, permissions)
- Set custom expiration times
- Securely store generated tokens

### 🔍 Token Validation
- Verify token signatures
- Check expiration and validity
- Decode & inspect JWT payloads
- Validate with your own secret key

### ♻️ Token Management
- Refresh access tokens using refresh tokens
- Blacklist compromised tokens
- Token history tracking
- **QR code** generation for easy sharing

### 🎨 Modern UI/UX
- Light and dark theme support
- Tabbed, responsive design
- Built with `Tkinter`, `ttkthemes`, and `sv_ttk`

---

## 🚀 Installation

### Prerequisites
- Python 3.8 or higher
- `pip` package manager

### Steps
```bash
git clone https://github.com/yourusername/JWT-Validator.git
cd JWT-Validator
pip install -r requirements.txt
python main.py
---
###🧰 Usage
Login

Start the app: python main.py

Use basic authentication (can be extended)

Main Interface

Generate Token: Choose claims, expiration, and generate JWT

Validate Token: Paste a token to verify

Manage Tokens: Refresh, blacklist, and view token history

Advanced Features

Generate QR codes

Inspect headers & payloads

Clipboard copy support

Update checker (requires internet)

🔒 Security Notes
Tokens stored per user in user_tokens/

Blacklisted tokens stored in blacklist.json

Token history in token_history.json

Recommendations for Production
Use strong secret keys (consider .env files or key vaults)

Implement encryption for stored tokens

Replace basic auth with secure login (OAuth2, etc.)

Sanitize user inputs to prevent token injection

📚 Documentation
Access built-in help from the Help → JWT Guide menu, or visit jwt.io for official JWT documentation.

🛠 Tech Stack
Python 3.8+

Tkinter + TTK Themes

PyJWT

QRCode / Pillow

Requests, Markdown, Pyperclip

📌 Use Cases
Debug JWTs in development

Share tokens securely (QR)

Test JWT authentication flows

Validate JWT payloads for APIs
---

### ✅ What You Should Add to Your Repo

1. **`requirements.txt`**
   ```txt
   PyJWT>=2.0.0
   ttkthemes>=3.2.0
   sv_ttk>=1.0.0
   qrcode>=7.0.0
   Pillow>=9.0.0
   requests>=2.0.0
   pyperclip>=1.8.0
   markdown>=3.0.0

👨‍💻 Created By
Muhammad Talha Khan
Feel free to connect on GitHub

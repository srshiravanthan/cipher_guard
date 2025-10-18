# 🔐 CipherGuard

CipherGuard is a **folder encryption and decryption tool** built with Python and Tkinter.  
It allows users to **securely encrypt and decrypt entire folders**, generate digital signatures, and send the encrypted files via email — all through a simple graphical interface.

---

## 🚀 Features

- 🧩 **Folder Encryption & Decryption** — Encrypt or decrypt all files in a folder with AES-GCM.
- 🔑 **Password-Based Key Derivation** — Uses Argon2 for secure key generation.
- 🛡️ **Integrity & Authenticity** — Generates and verifies HMACs and ECDSA digital signatures.
- 📧 **Email Notification** — Sends success notifications and encrypted ZIP files to the recipient.
- 💻 **User-Friendly GUI** — Built using Python’s Tkinter for easy interaction.

---

## 🧰 Tech Stack

- **Language:** Python 3.x  
- **Libraries Used:**
  - `tkinter` – GUI interface  
  - `cryptography` – AES, HMAC, and ECDSA encryption  
  - `argon2` – Password hashing and key derivation  
  - `smtplib`, `email` – Sending notifications and attachments  
  - `zipfile`, `shutil`, `os` – File and folder handling  

---

## 📦 Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/<your-username>/Cipher-Guard.git
   cd Cipher-Guard

2. Create and activate a virtual environment (recommended):
   python -m venv venv
   source venv/bin/activate       # For Linux/Mac
   venv\Scripts\activate          # For Windows
   
4. If you don’t have a requirements.txt, create one using:
    
   pip install cryptography argon2-cffi
   pip freeze > requirements.txt

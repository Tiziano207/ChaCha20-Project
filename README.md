# ChaCha20-Project
ChaCha20 File Encryption Project with CLI and Flask Drag &amp; Drop Web Interface. Securely encrypt and decrypt files using ChaCha20-Poly1305 with optional key derivation via PBKDF2

This repository provides tools for **file encryption and decryption** using the **ChaCha20-Poly1305** symmetric cipher, along with a **web interface** for easy drag & drop usage.

---

## 📂 Repository Structure

```
ChaCha20-Project/
│
├─ encryption/       # Scripts and tools for command-line encryption
│   ├─ chacha_encrypt.py
│   ├─ encrypt_wrapper.sh
│   ├─ Makefile
│   ├─ README.md     # Documentation about ChaCha20, usage, and commands
│
├─ webapp/           # Flask web app with drag & drop support
│   ├─ server.py
│   ├─ README.md     # Documentation about Flask setup and drag & drop interface
│
└─ LICENSE           # Optional license for the project
```
---

## 🔑 Features

### Encryption Scripts (`encryption/`)
- Symmetric encryption/decryption using ChaCha20-Poly1305
- Key derivation via PBKDF2 (recommended)
- Bash wrapper for easier command-line usage
- Makefile for quick execution

### Web Application (`webapp/`)
- Simple **drag & drop interface** in the browser
- Encrypt or decrypt files with the same ChaCha20 scripts
- Automatic download of processed files
- Maintains `.enc` suffix for encrypted files; removes `.enc` when decrypted

---

## ⚙️ Installation & Usage

### Command-line scripts
See [`encryption/README.md`](encryption/README.md) for detailed instructions and examples.

### Web Application
See [`webapp/README.md`](webapp/README.md) for setup instructions and usage.

```bash
# Example: run the web server
cd webapp
python3 server.py
# Open browser at http://localhost:8080
```

---

## 📖 References
- [ChaCha20 Cipher](https://cr.yp.to/chacha.html)
- [ChaCha20-Poly1305 AEAD](https://tools.ietf.org/html/rfc8439)

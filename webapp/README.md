# Flask Drag & Drop WebApp

This folder contains a simple Flask web application for file encryption/decryption with **drag & drop** support.

## Files
- `server.py` → Flask server with HTML/JS frontend.

## Features
- Drag & Drop file upload
- Enter key, choose mode (derive/pad) and action (encrypt/decrypt)
- Automatic file download after encryption/decryption
- Decrypted files remove the `.enc` suffix, restoring the original name.

## Setup
```bash
sudo apt update
sudo apt install python3-flask -y
```

## Run
```bash
python3 server.py
```

Then open in your browser: `http://localhost:8080`

## How it works
1. User drags a file into the dropzone.
2. Flask saves the file temporarily.
3. The server calls `chacha_encrypt.py` to encrypt/decrypt.
4. The result is sent back as a download.
5. Decrypted files remove the `.enc` suffix, restoring the original name.

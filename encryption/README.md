# ChaCha20 Encryption Scripts

This folder contains scripts to encrypt and decrypt files using **ChaCha20-Poly1305**.

## Files
- `chacha_encrypt.py` → Main Python script for encryption/decryption.
- `encrypt_wrapper.sh` → Bash wrapper for easier use and optional file deletion.
- `Makefile` → Optional commands for quick execution.

## ChaCha20 Algorithm
ChaCha20 is a **symmetric stream cipher** designed by Daniel J. Bernstein.  
It provides:
- High performance
- Strong security
- Resistance against timing attacks

ChaCha20-Poly1305 combines ChaCha20 encryption with Poly1305 for **authenticated encryption** (integrity + confidentiality).

## Usage

### Encrypt a file
```bash
python3 chacha_encrypt.py encrypt input.txt output.enc --key "MySecret" --mode derive
```

### Decrypt a file
```bash
python3 chacha_encrypt.py decrypt output.enc decrypted.txt --key "MySecret"
```

### Using the wrapper
```bash
./encrypt_wrapper.sh encrypt file input.txt output.enc "MySecret" derive
./encrypt_wrapper.sh decrypt file output.enc decrypted.txt "MySecret"
```

### Makefile examples
```bash
make encrypt-file INPUT_FILE=input.txt OUTPUT_FILE=output.enc KEY="MySecret" MODE=derive
make decrypt-file INPUT_FILE=output.enc OUTPUT_FILE=decrypted.txt KEY="MySecret"
```

## Security Notes
- Always use `--mode derive` with high PBKDF2 iterations.
- Never reuse a nonce with the same key.
- Losing the key means permanent loss of access.

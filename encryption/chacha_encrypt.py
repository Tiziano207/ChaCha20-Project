#!/usr/bin/env python3
"""
chacha_encrypt.py

Usage:
  # --- FILES ---
  # Encrypt a file (recommended: derive with PBKDF2)
  python chacha_encrypt.py encrypt <input_file> <output_file> --key "my secret passphrase" --mode derive
  # Encrypt a file with pad (NOT recommended, insecure)
  python chacha_encrypt.py encrypt <input_file> <output_file> --key "my secret passphrase" --mode pad

  # Decrypt a file
  python chacha_encrypt.py decrypt <input_file> <output_file> --key "my secret passphrase"

  # --- STRINGS ---
  # Encrypt a string
  python chacha_encrypt.py encrypt-string "text to encrypt" --key "my secret passphrase" --mode derive
  # Decrypt a string (use the base64 output from encryption)
  python chacha_encrypt.py decrypt-string "<base64_data>" --key "my secret passphrase"

File output format (binary):
  8 bytes  magic: b"CH20P1\x00\x00"
  1 byte   version: 1
  1 byte   mode: 0x01 = derive (salt present), 0x02 = pad (no salt)
  if mode == derive:
      16 bytes salt
      4 bytes  iterations (big-endian uint32)
  12 bytes nonce
  remaining bytes: ciphertext (includes ChaCha20-Poly1305 tag)

String output format (base64):
  The same structure as file output is encoded as base64.

Security notes:
- Always prefer --mode derive (PBKDF2). Use --mode pad only if you really know what you are doing.
- Nonce must not be reused with the same key. This script generates a fresh random nonce for every encryption.
- Losing the passphrase means permanent data loss.
- Pad mode is weak against brute-force and should be avoided for sensitive data.
"""
import sys
import os
import struct
import argparse
import base64
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# Constants
MAGIC = b"CH20P1\x00\x00"
VERSION = 1
NONCE_SIZE = 12
KEY_SIZE = 32
SALT_SIZE = 16
DEFAULT_PBKDF2_ITERS = 200_000  # Recommended PBKDF2 iteration count

# --- Key derivation helpers ---
def derive_key_from_passphrase(passphrase: bytes, salt: bytes, iterations: int) -> bytes:
    """Derive a 32-byte key from a passphrase using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(passphrase)

def pad_or_truncate_key(passphrase: bytes) -> bytes:
    """Insecure: pad with zeroes or truncate to 32 bytes."""
    if len(passphrase) >= KEY_SIZE:
        return passphrase[:KEY_SIZE]
    else:
        return passphrase + b"\x00" * (KEY_SIZE - len(passphrase))

# --- File operations ---
def encrypt_file(input_path: str, output_path: str, key_string: str, mode: str, iterations:int = DEFAULT_PBKDF2_ITERS):
    """Encrypt a file with ChaCha20-Poly1305."""
    data = open(input_path, "rb").read()
    mode_byte = 0x01 if mode == "derive" else 0x02

    if mode == "derive":
        salt = os.urandom(SALT_SIZE)
        key = derive_key_from_passphrase(key_string.encode("utf-8"), salt, iterations)
    else:
        salt = b""
        key = pad_or_truncate_key(key_string.encode("utf-8"))

    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aead.encrypt(nonce, data, None)

    with open(output_path, "wb") as f:
        f.write(MAGIC)
        f.write(bytes([VERSION]))
        f.write(bytes([mode_byte]))
        if mode == "derive":
            f.write(salt)
            f.write(struct.pack(">I", iterations))
        f.write(nonce)
        f.write(ct)
    print(f"[+] File encrypted: {output_path}")

def decrypt_file(input_path: str, output_path: str, key_string: str):
    """Decrypt a file previously encrypted with this script."""
    with open(input_path, "rb") as f:
        magic = f.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError("File format not recognized (magic mismatch).")
        version = f.read(1)[0]
        if version != VERSION:
            raise ValueError(f"Unsupported version: {version}")
        mode = f.read(1)[0]
        if mode == 0x01:
            salt = f.read(SALT_SIZE)
            iterations = struct.unpack(">I", f.read(4))[0]
            key = derive_key_from_passphrase(key_string.encode("utf-8"), salt, iterations)
        elif mode == 0x02:
            key = pad_or_truncate_key(key_string.encode("utf-8"))
        else:
            raise ValueError("Unrecognized mode in file.")

        nonce = f.read(NONCE_SIZE)
        ct = f.read()

    aead = ChaCha20Poly1305(key)
    pt = aead.decrypt(nonce, ct, None)
    with open(output_path, "wb") as f:
        f.write(pt)
    print(f"[+] File decrypted: {output_path}")

# --- String operations ---
def encrypt_string(plaintext: str, key_string: str, mode: str, iterations:int = DEFAULT_PBKDF2_ITERS) -> str:
    """Encrypt a string and return base64 output."""
    data = plaintext.encode("utf-8")
    mode_byte = 0x01 if mode == "derive" else 0x02

    if mode == "derive":
        salt = os.urandom(SALT_SIZE)
        key = derive_key_from_passphrase(key_string.encode("utf-8"), salt, iterations)
    else:
        salt = b""
        key = pad_or_truncate_key(key_string.encode("utf-8"))

    aead = ChaCha20Poly1305(key)
    nonce = os.urandom(NONCE_SIZE)
    ct = aead.encrypt(nonce, data, None)

    blob = bytearray()
    blob.extend(MAGIC)
    blob.extend(bytes([VERSION]))
    blob.extend(bytes([mode_byte]))
    if mode == "derive":
        blob.extend(salt)
        blob.extend(struct.pack(">I", iterations))
    blob.extend(nonce)
    blob.extend(ct)

    return base64.b64encode(blob).decode("utf-8")

def decrypt_string(b64data: str, key_string: str) -> str:
    """Decrypt a base64 string previously encrypted with this script."""
    blob = base64.b64decode(b64data)
    off = 0
    if blob[off:off+len(MAGIC)] != MAGIC:
        raise ValueError("String format not recognized (magic mismatch).")
    off += len(MAGIC)

    version = blob[off]; off+=1
    if version != VERSION:
        raise ValueError(f"Unsupported version: {version}")
    mode = blob[off]; off+=1

    if mode == 0x01:
        salt = blob[off:off+SALT_SIZE]; off+=SALT_SIZE
        iterations = struct.unpack(">I", blob[off:off+4])[0]; off+=4
        key = derive_key_from_passphrase(key_string.encode("utf-8"), salt, iterations)
    elif mode == 0x02:
        key = pad_or_truncate_key(key_string.encode("utf-8"))
    else:
        raise ValueError("Unrecognized mode.")

    nonce = blob[off:off+NONCE_SIZE]; off+=NONCE_SIZE
    ct = blob[off:]

    aead = ChaCha20Poly1305(key)
    pt = aead.decrypt(nonce, ct, None)
    return pt.decode("utf-8")

# --- CLI ---
def parse_args():
    p = argparse.ArgumentParser(description="ChaCha20-Poly1305 file/string encrypt/decrypt")
    sub = p.add_subparsers(dest="cmd", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt a file")
    enc.add_argument("input")
    enc.add_argument("output")
    enc.add_argument("--key", required=True)
    enc.add_argument("--mode", choices=["derive","pad"], default="derive")
    enc.add_argument("--iters", type=int, default=DEFAULT_PBKDF2_ITERS)

    dec = sub.add_parser("decrypt", help="Decrypt a file")
    dec.add_argument("input")
    dec.add_argument("output")
    dec.add_argument("--key", required=True)

    encs = sub.add_parser("encrypt-string", help="Encrypt a string")
    encs.add_argument("text")
    encs.add_argument("--key", required=True)
    encs.add_argument("--mode", choices=["derive","pad"], default="derive")
    encs.add_argument("--iters", type=int, default=DEFAULT_PBKDF2_ITERS)

    decs = sub.add_parser("decrypt-string", help="Decrypt a string")
    decs.add_argument("b64data")
    decs.add_argument("--key", required=True)

    return p.parse_args()

if __name__ == "__main__":
    args = parse_args()
    try:
        if args.cmd == "encrypt":
            encrypt_file(args.input, args.output, args.key, args.mode, args.iters)
        elif args.cmd == "decrypt":
            decrypt_file(args.input, args.output, args.key)
        elif args.cmd == "encrypt-string":
            result = encrypt_string(args.text, args.key, args.mode, args.iters)
            print(result)
        elif args.cmd == "decrypt-string":
            result = decrypt_string(args.b64data, args.key)
            print(result)
    except Exception as e:
        print("[ERROR]", e)
        sys.exit(2)

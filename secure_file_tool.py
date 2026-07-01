#!/usr/bin/env python3
"""
=====================================================================
 Secure File Tool - Simple File Encryption and Decryption Tool
=====================================================================
 Information Security Course Project - Project 4

 Purpose:
   A small, self-contained tool that lets a user encrypt and decrypt
   either typed text or the contents of a text file, using a secret
   key (password) supplied by the user.

 Cryptography used (industry-standard primitives, not "home-made"):
   - AES-128 in CBC mode with HMAC-SHA256 authentication, combined
     into the "Fernet" recipe provided by the Python `cryptography`
     library. Fernet guarantees CONFIDENTIALITY (AES encryption) and
     INTEGRITY/AUTHENTICITY (HMAC) - if the ciphertext or key is
     wrong, decryption fails loudly instead of returning garbage.
   - PBKDF2-HMAC-SHA256 with a random 16-byte salt and 480,000
     iterations is used to turn the user's plain-text secret key
     (a password/passphrase) into a proper 256-bit cryptographic key.
     This protects against rainbow-table and brute-force attacks on
     weak passwords.

 Two interfaces are provided:
   1. Command Line Interface (CLI)   -> works anywhere, used for the
      automated demo / sample files in this submission.
   2. Graphical User Interface (GUI) -> built with Tkinter (included
      with Python). Run `python secure_file_tool.py --gui` on your
      own computer (with a screen) to take the screenshots required
      by the assignment.

 Output file format produced by this tool (plain text, line based):
   Line 1:  SECURE-FILE-TOOL-V1          (format marker)
   Line 2:  <base64 salt>                (16 random bytes)
   Line 3:  <base64 fernet token>        (the actual encrypted data)

 Author: Course Project Submission
=====================================================================
"""

import argparse
import base64
import getpass
import os
import sys

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

FORMAT_MARKER = "SECURE-FILE-TOOL-V1"
SALT_SIZE_BYTES = 16
PBKDF2_ITERATIONS = 480_000


# ---------------------------------------------------------------------------
# Core cryptographic functions
# ---------------------------------------------------------------------------

def derive_key(secret_key: str, salt: bytes) -> bytes:
    """
    Derive a 32-byte Fernet-compatible key from a human-chosen secret key
    (password/passphrase) and a random salt, using PBKDF2-HMAC-SHA256.

    Using a Key Derivation Function (KDF) instead of using the password
    directly is a core security principle: it slows down brute-force /
    dictionary attacks and ensures the key has full cryptographic strength
    regardless of how the user chose their password.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(secret_key.encode("utf-8"))
    return base64.urlsafe_b64encode(raw_key)


def encrypt_bytes(plaintext: bytes, secret_key: str) -> str:
    """
    Encrypt raw bytes with the given secret key.
    Returns a text blob ready to be written to an output file.
    """
    salt = os.urandom(SALT_SIZE_BYTES)
    key = derive_key(secret_key, salt)
    token = Fernet(key).encrypt(plaintext)

    salt_b64 = base64.urlsafe_b64encode(salt).decode("ascii")
    token_b64 = token.decode("ascii")  # Fernet tokens are already base64

    return f"{FORMAT_MARKER}\n{salt_b64}\n{token_b64}\n"


def decrypt_blob(blob: str, secret_key: str) -> bytes:
    """
    Decrypt a text blob produced by encrypt_bytes().
    Raises ValueError if the format is invalid, or InvalidToken if the
    key is wrong or the data was tampered with.
    """
    lines = blob.strip().splitlines()
    if len(lines) < 3 or lines[0] != FORMAT_MARKER:
        raise ValueError("Input does not look like a file produced by this tool.")

    salt = base64.urlsafe_b64decode(lines[1])
    token = lines[2].encode("ascii")

    key = derive_key(secret_key, salt)
    plaintext = Fernet(key).decrypt(token)  # raises InvalidToken on wrong key
    return plaintext


# ---------------------------------------------------------------------------
# Command Line Interface
# ---------------------------------------------------------------------------

def cmd_encrypt(args):
    if args.text is not None:
        data = args.text.encode("utf-8")
        source_desc = "typed text"
    else:
        with open(args.input, "rb") as f:
            data = f.read()
        source_desc = f"file '{args.input}'"

    key = args.key or getpass.getpass("Enter secret key: ")

    blob = encrypt_bytes(data, key)

    print(f"[+] Encrypting {source_desc} ({len(data)} bytes of plaintext)...")
    print(f"[+] Algorithm : AES-128-CBC + HMAC-SHA256 (Fernet)")
    print(f"[+] Key derivation : PBKDF2-HMAC-SHA256, {PBKDF2_ITERATIONS:,} iterations, random 16-byte salt")

    if args.output:
        with open(args.output, "w") as f:
            f.write(blob)
        print(f"[+] Encrypted output written to: {args.output}")
    else:
        print("[+] Encrypted output:\n")
        print(blob)

    print("\n[+] Preview of encrypted content (unreadable without the key):")
    preview = blob.strip().splitlines()[2]
    print("    " + preview[:80] + ("..." if len(preview) > 80 else ""))


def cmd_decrypt(args):
    if args.input_text is not None:
        blob = args.input_text
        source_desc = "pasted text"
    else:
        with open(args.input, "r") as f:
            blob = f.read()
        source_desc = f"file '{args.input}'"

    key = args.key or getpass.getpass("Enter secret key: ")

    print(f"[+] Decrypting {source_desc} ...")
    try:
        plaintext = decrypt_blob(blob, key)
    except InvalidToken:
        print("[-] DECRYPTION FAILED: Wrong secret key, or the data has been")
        print("    tampered with / corrupted. No plaintext can be recovered.")
        print("    This demonstrates that encrypted data is meaningless")
        print("    without the correct key (confidentiality is preserved).")
        sys.exit(1)
    except ValueError as e:
        print(f"[-] DECRYPTION FAILED: {e}")
        sys.exit(1)

    print(f"[+] SUCCESS: correct key supplied. Recovered {len(plaintext)} bytes of plaintext.")

    if args.output:
        with open(args.output, "wb") as f:
            f.write(plaintext)
        print(f"[+] Decrypted output written to: {args.output}")
    else:
        print("[+] Decrypted content:\n")
        try:
            print(plaintext.decode("utf-8"))
        except UnicodeDecodeError:
            print(plaintext)


def cmd_gui(_args):
    try:
        launch_gui()
    except Exception as e:
        print(f"[-] Could not start GUI (no display available?): {e}")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Optional Tkinter GUI (run locally on a machine with a screen, e.g.
#   python secure_file_tool.py --gui
# to take the screenshots required by the assignment)
# ---------------------------------------------------------------------------

def launch_gui():
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext

    root = tk.Tk()
    root.title("Secure File Tool - Encryption / Decryption")
    root.geometry("700x560")

    tk.Label(root, text="Secret Key:").pack(anchor="w", padx=10, pady=(10, 0))
    key_entry = tk.Entry(root, show="*", width=40)
    key_entry.pack(anchor="w", padx=10)

    tk.Label(root, text="Text content (type here, or load a file below):").pack(
        anchor="w", padx=10, pady=(10, 0)
    )
    text_box = scrolledtext.ScrolledText(root, width=80, height=18)
    text_box.pack(padx=10, pady=5)

    loaded_path = {"path": None}

    def load_file():
        path = filedialog.askopenfilename(title="Select a text file")
        if not path:
            return
        with open(path, "r", errors="replace") as f:
            text_box.delete("1.0", tk.END)
            text_box.insert(tk.END, f.read())
        loaded_path["path"] = path
        status_var.set(f"Loaded: {os.path.basename(path)}")

    def do_encrypt():
        key = key_entry.get()
        if not key:
            messagebox.showerror("Error", "Please enter a secret key.")
            return
        plaintext = text_box.get("1.0", tk.END).rstrip("\n").encode("utf-8")
        blob = encrypt_bytes(plaintext, key)
        text_box.delete("1.0", tk.END)
        text_box.insert(tk.END, blob)
        status_var.set("Encrypted. Output cannot be read without the correct key.")

    def do_decrypt():
        key = key_entry.get()
        if not key:
            messagebox.showerror("Error", "Please enter a secret key.")
            return
        blob = text_box.get("1.0", tk.END)
        try:
            plaintext = decrypt_blob(blob, key)
        except InvalidToken:
            messagebox.showerror(
                "Decryption Failed",
                "Wrong secret key or corrupted/tampered data.\n"
                "No plaintext could be recovered.",
            )
            status_var.set("Decryption failed: wrong key.")
            return
        except ValueError as e:
            messagebox.showerror("Decryption Failed", str(e))
            return
        text_box.delete("1.0", tk.END)
        text_box.insert(tk.END, plaintext.decode("utf-8", errors="replace"))
        status_var.set("Decrypted successfully with the correct key.")

    def save_output():
        path = filedialog.asksaveasfilename(title="Save current content as...")
        if not path:
            return
        with open(path, "w") as f:
            f.write(text_box.get("1.0", tk.END))
        status_var.set(f"Saved to {os.path.basename(path)}")

    btn_frame = tk.Frame(root)
    btn_frame.pack(pady=8)
    tk.Button(btn_frame, text="Load Text File...", width=16, command=load_file).grid(row=0, column=0, padx=4)
    tk.Button(btn_frame, text="Encrypt", width=16, bg="#c8e6c9", command=do_encrypt).grid(row=0, column=1, padx=4)
    tk.Button(btn_frame, text="Decrypt", width=16, bg="#bbdefb", command=do_decrypt).grid(row=0, column=2, padx=4)
    tk.Button(btn_frame, text="Save As...", width=16, command=save_output).grid(row=0, column=3, padx=4)

    status_var = tk.StringVar(value="Ready.")
    tk.Label(root, textvariable=status_var, fg="#555").pack(anchor="w", padx=10, pady=(0, 10))

    root.mainloop()


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        description="Simple File Encryption and Decryption Tool (AES via Fernet)."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    enc = sub.add_parser("encrypt", help="Encrypt text or a file.")
    group = enc.add_mutually_exclusive_group(required=True)
    group.add_argument("--text", help="Text to encrypt directly.")
    group.add_argument("--input", help="Path to a plaintext file to encrypt.")
    enc.add_argument("--output", help="Path to write the encrypted output to.")
    enc.add_argument("--key", help="Secret key (omit to be prompted securely).")
    enc.set_defaults(func=cmd_encrypt)

    dec = sub.add_parser("decrypt", help="Decrypt text or a file.")
    group2 = dec.add_mutually_exclusive_group(required=True)
    group2.add_argument("--input-text", help="Encrypted blob to decrypt directly.")
    group2.add_argument("--input", help="Path to an encrypted file to decrypt.")
    dec.add_argument("--output", help="Path to write the decrypted output to.")
    dec.add_argument("--key", help="Secret key (omit to be prompted securely).")
    dec.set_defaults(func=cmd_decrypt)

    gui = sub.add_parser("gui", help="Launch the graphical interface.")
    gui.set_defaults(func=cmd_gui)

    return parser


def main():
    parser = build_parser()
    if len(sys.argv) > 1 and sys.argv[1] == "--gui":
        sys.argv[1] = "gui"
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()

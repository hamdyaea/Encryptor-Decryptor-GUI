#!/usr/bin/env python3
# Developer: Hamdy Abou El Anein
# Contact: info@daylightlinux.ch
# SPDX-License-Identifier: GPL-3.0-only
"""Non-destructive authenticated file encryption (new format only)."""
from __future__ import annotations
import argparse
import getpass
import os
from pathlib import Path
import secrets
import tempfile

MAGIC = b"DAYENC01"
SALT_BYTES = 16
NONCE_BYTES = 12
MAX_BYTES = 128 * 1024 * 1024

def derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    if not password:
        raise ValueError("Password cannot be empty")
    return Scrypt(salt=salt, length=32, n=2**14, r=8, p=1).derive(password.encode("utf-8"))

def _publish_without_overwrite(output: Path, content: bytes) -> Path:
    output = output.absolute()
    if output.exists() or output.is_symlink():
        raise FileExistsError(f"Output already exists: {output}")
    fd, tmpname = tempfile.mkstemp(prefix=".dayenc-", dir=output.parent)
    tmp = Path(tmpname)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o600)
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(tmp, output)
        return output
    finally:
        tmp.unlink(missing_ok=True)

def encrypt(password: str, filename: str | Path) -> Path:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    source = Path(filename)
    if not source.is_file() or source.is_symlink():
        raise ValueError("Input must be a regular, non-symlink file")
    if source.stat().st_size > MAX_BYTES:
        raise ValueError("File exceeds 128 MiB safety limit")
    data = source.read_bytes()
    salt = secrets.token_bytes(SALT_BYTES)
    nonce = secrets.token_bytes(NONCE_BYTES)
    ciphertext = AESGCM(derive_key(password, salt)).encrypt(nonce, data, MAGIC)
    return _publish_without_overwrite(source.with_name(source.name + ".dle"), MAGIC + salt + nonce + ciphertext)

def decrypt(password: str, filename: str | Path) -> Path:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    source = Path(filename)
    if not source.is_file() or source.is_symlink():
        raise ValueError("Input must be a regular, non-symlink file")
    if not source.name.endswith(".dle"):
        raise ValueError("Only authenticated .dle files are supported; legacy CBC files are not modified")
    if source.stat().st_size > MAX_BYTES + 64:
        raise ValueError("File exceeds safety limit")
    payload = source.read_bytes()
    if not payload.startswith(MAGIC) or len(payload) < len(MAGIC) + SALT_BYTES + NONCE_BYTES + 16:
        raise ValueError("Unknown or truncated encrypted format")
    pos = len(MAGIC)
    salt = payload[pos:pos + SALT_BYTES]
    pos += SALT_BYTES
    nonce = payload[pos:pos + NONCE_BYTES]
    pos += NONCE_BYTES
    plaintext = AESGCM(derive_key(password, salt)).decrypt(nonce, payload[pos:], MAGIC)
    return _publish_without_overwrite(source.with_name(source.name[:-4]), plaintext)

def gui() -> None:
    import tkinter as tk
    from tkinter import filedialog, messagebox, simpledialog
    root = tk.Tk()
    root.title("Daylight File Encryption")
    def run(mode: str) -> None:
        name = filedialog.askopenfilename(parent=root)
        if not name:
            return
        password = simpledialog.askstring("Password", "Enter password:", show="*", parent=root)
        if password is None:
            return
        try:
            result = encrypt(password, name) if mode == "encrypt" else decrypt(password, name)
        except Exception as exc:
            messagebox.showerror("Operation failed", str(exc), parent=root)
        else:
            messagebox.showinfo("Completed", f"Created {result}\nOriginal file retained.", parent=root)
    artwork = tk.PhotoImage(file=str(Path(__file__).resolve().parent / "images/encryption-ui.png"))
    illustration = tk.Label(root, image=artwork)
    illustration.image = artwork
    illustration.pack()
    tk.Label(root, text="Authenticated encryption; original files are preserved.").pack(pady=10)
    tk.Button(root, text="Encrypt file", command=lambda: run("encrypt")).pack()
    tk.Button(root, text="Decrypt .dle file", command=lambda: run("decrypt")).pack()
    root.mainloop()

def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_mutually_exclusive_group()
    actions.add_argument("--encrypt", metavar="FILE")
    actions.add_argument("--decrypt", metavar="FILE")
    args = parser.parse_args()
    if not args.encrypt and not args.decrypt:
        gui()
        return
    password = getpass.getpass("Password: ")
    output = encrypt(password, args.encrypt) if args.encrypt else decrypt(password, args.decrypt)
    print(f"Created {output}; original file retained")

if __name__ == "__main__":
    main()

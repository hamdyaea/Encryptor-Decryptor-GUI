# Daylight Encryptor / Decryptor

**Developer:** Hamdy Abou El Anein  
**Contact:** info@daylightlinux.ch  
**License:** GPL v3 (see LICENSE).

This version replaces the historical unauthenticated AES-CBC format with authenticated AES-256-GCM, scrypt password derivation, a random salt and a random nonce. The new format is identified by `DAYENC01`. Original files are never removed or overwritten; encrypted output uses `.dle`, and existing destinations are rejected.

Install `cryptography` in a virtual environment, then run:

```sh
python3 -m pip install 'cryptography>=42'
python3 crypto.py
python3 crypto.py --encrypt file.txt
python3 crypto.py --decrypt file.txt.dle
python3 -m unittest discover -s tests -v
```

The CLI prompts for a password; never supply passwords in command-line arguments.

**Compatibility warning:** Legacy `-encrypted` AES-CBC files are deliberately **not supported** by this version. The old format was unauthenticated and its decryptor could overwrite input files. The historical implementation remains on the [old branch](https://github.com/hamdyaea/Encryptor-Decryptor-GUI/tree/old). Preserve original legacy files and use a separately tested migration workflow before attempting recovery.

Maximum input size: 128 MiB, read into memory. This utility is not a replacement for audited backups or disk encryption.

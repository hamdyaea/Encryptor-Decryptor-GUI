# Developer: Hamdy Abou El Anein
# Contact: info@daylightlinux.ch
# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
from pathlib import Path
import tempfile
import unittest
from cryptography.exceptions import InvalidTag

spec = importlib.util.spec_from_file_location("daycrypto", Path(__file__).resolve().parents[1] / "crypto.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)

class CryptoTests(unittest.TestCase):
    def test_round_trip_preserves_original(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "a.txt"
            source.write_bytes(b"secret\x00" * 100)
            enc = mod.encrypt("strong passphrase", source)
            self.assertEqual(source.read_bytes(), b"secret\x00" * 100)
            self.assertTrue(enc.read_bytes().startswith(mod.MAGIC))
            with self.assertRaises(FileExistsError):
                mod.decrypt("strong passphrase", enc)
            source.unlink()
            restored = mod.decrypt("strong passphrase", enc)
            self.assertEqual(restored.read_bytes(), b"secret\x00" * 100)
            self.assertTrue(enc.exists())
    def test_wrong_password_and_tamper(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "a"
            source.write_bytes(b"payload")
            enc = mod.encrypt("correct", source)
            source.unlink()
            with self.assertRaises(InvalidTag):
                mod.decrypt("wrong", enc)
            self.assertFalse(source.exists())
            data = bytearray(enc.read_bytes())
            data[-1] ^= 1
            enc.write_bytes(data)
            with self.assertRaises(InvalidTag):
                mod.decrypt("correct", enc)
            self.assertFalse(source.exists())
    def test_collision_and_legacy_rejected(self):
        with tempfile.TemporaryDirectory() as folder:
            source = Path(folder) / "a"
            source.write_bytes(b"one")
            enc = mod.encrypt("password", source)
            with self.assertRaises(FileExistsError):
                mod.encrypt("password", source)
            self.assertEqual(enc, Path(folder) / "a.dle")
            with self.assertRaises(ValueError):
                mod.decrypt("password", source)

if __name__ == "__main__":
    unittest.main()

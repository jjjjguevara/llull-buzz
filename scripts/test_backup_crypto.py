"""Operator-key backup envelope regressions; no real signing key is used."""
import os
from pathlib import Path
import tempfile
import unittest

from backup_crypto import open_sealed, read_key, seal


class BackupCryptoTests(unittest.TestCase):
    def test_roundtrip_binds_owner_and_rejects_tamper(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "operator.key"
            key_path.write_bytes(os.urandom(32))
            key_path.chmod(0o600)
            key = read_key(key_path)
            plaintext = b'{"synthetic_secret":"never in the backup"}'
            blob = seal(plaintext, key, "synthetic-owner-a")
            self.assertNotIn(plaintext, blob)
            self.assertEqual(open_sealed(blob, key, "synthetic-owner-a"), plaintext)
            for changed_blob, changed_key, changed_owner in [
                (blob, os.urandom(32), "synthetic-owner-a"),
                (blob, key, "synthetic-owner-b"),
                (blob[:-1] + bytes([blob[-1] ^ 1]), key, "synthetic-owner-a"),
            ]:
                with self.assertRaises(ValueError):
                    open_sealed(changed_blob, changed_key, changed_owner)

    def test_key_file_must_be_private_regular_and_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "operator.key"
            key_path.write_bytes(os.urandom(32))
            key_path.chmod(0o644)
            with self.assertRaises(ValueError):
                read_key(key_path)
            key_path.chmod(0o600)
            self.assertEqual(len(read_key(key_path)), 32)
            key_path.write_bytes(b"short")
            with self.assertRaises(ValueError):
                read_key(key_path)
            key_path.write_bytes(os.urandom(32))
            link = Path(directory) / "link"
            link.symlink_to(key_path)
            with self.assertRaises(ValueError):
                read_key(link)


if __name__ == "__main__":
    unittest.main()

"""Authenticated envelope for task-local synthetic native-key backups.

The 32-byte operator key lives outside the backup and is never printed. The
caller supplies a fresh backup owner as associated data to prevent moving a
key archive between otherwise valid restore manifests.
"""
import os
from pathlib import Path
import re
import secrets
import stat

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"BZ-NATIVE-KEYS-v1\0"
MAX_PLAINTEXT = 65_536


def read_key(path):
    """Read an operator-owned, mode-0600, non-symlink raw AES-256 key file."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("protected backup requires no-follow file opening")
    try:
        fd = os.open(Path(path), flags)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                    or info.st_mode & 0o077 or info.st_size != 32):
                raise ValueError("operator key must be owner-only and exactly 32 bytes")
            key = os.read(fd, 33)
            if len(key) != 32:
                raise ValueError("operator key must be exactly 32 bytes")
            return key
        finally:
            os.close(fd)
    except OSError as error:
        raise ValueError("operator key is unavailable or unsafe") from error


def _aad(owner):
    if not isinstance(owner, str) or not re.fullmatch(r"[a-zA-Z0-9-]{1,64}", owner):
        raise ValueError("invalid backup owner")
    return MAGIC + owner.encode("ascii")


def seal(plaintext, key, owner):
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_PLAINTEXT or len(key) != 32:
        raise ValueError("invalid protected backup input")
    nonce = secrets.token_bytes(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, plaintext, _aad(owner))


def open_sealed(blob, key, owner):
    minimum = len(MAGIC) + 12 + 16
    if (not isinstance(blob, bytes) or len(blob) < minimum
            or len(blob) > minimum + MAX_PLAINTEXT or not blob.startswith(MAGIC)
            or len(key) != 32):
        raise ValueError("invalid protected backup")
    nonce = blob[len(MAGIC):len(MAGIC) + 12]
    try:
        return AESGCM(key).decrypt(nonce, blob[len(MAGIC) + 12:], _aad(owner))
    except InvalidTag as error:
        raise ValueError("protected backup authentication failed") from error

"""
crypto_utils.py
----------------
Symmetric encryption helpers built on AES-256-GCM.

Learning notes (read these, they matter more than the code):

1. We NEVER store a raw encryption key anywhere (not on disk, not in a
   config file, not in the database). Instead we derive the key from the
   user's passphrase every single time, using PBKDF2-HMAC-SHA256 with a
   random salt. This is "secure key storage" in practice: there is no key
   to steal because the key never persists.

2. The salt is random per-encryption and is stored ALONGSIDE the
   ciphertext (it doesn't need to be secret, it just needs to be unique).
   Without the salt, the key can't be re-derived, so decryption is
   impossible even with the correct passphrase.

3. AES-GCM needs a nonce (a.k.a IV) that must NEVER be reused with the
   same key. We generate a fresh random 12-byte nonce for every
   encryption call. Combined with the random salt, this guarantees that
   encrypting the exact same text twice produces two completely
   different outputs.

4. GCM is an "authenticated" cipher mode: it produces a ciphertext + a
   16-byte authentication tag. On decryption, if the passphrase is wrong
   or the ciphertext/nonce/salt was tampered with, the tag check fails
   and we raise an error instead of silently returning garbage. This is
   strictly better than plain AES-CBC (which has no built-in integrity
   check).

Output format:
    base64( salt (16 bytes) | nonce (12 bytes) | ciphertext+tag )

That single base64 blob is everything needed to decrypt later (given the
correct passphrase) and is safe to store/copy/paste/email as plain text.
"""

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

SALT_LEN = 16          # bytes
NONCE_LEN = 12          # bytes, recommended size for AES-GCM
KEY_LEN = 32            # 256-bit key
PBKDF2_ITERATIONS = 390_000  # OWASP-recommended minimum (2023+) for PBKDF2-SHA256


class DecryptionError(Exception):
    """Raised when decryption fails (wrong passphrase or tampered data)."""


def _derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from a passphrase + salt using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(passphrase.encode("utf-8"))


def encrypt(plaintext: str, passphrase: str) -> str:
    """Encrypt plaintext with a passphrase. Returns a base64 token."""
    if not plaintext:
        raise ValueError("Nothing to encrypt.")
    if not passphrase:
        raise ValueError("Passphrase is required.")

    salt = os.urandom(SALT_LEN)
    nonce = os.urandom(NONCE_LEN)
    key = _derive_key(passphrase, salt)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)

    blob = salt + nonce + ciphertext
    return base64.b64encode(blob).decode("utf-8")


def decrypt(token: str, passphrase: str) -> str:
    """Decrypt a base64 token produced by encrypt(). Raises DecryptionError on failure."""
    if not token:
        raise ValueError("Nothing to decrypt.")
    if not passphrase:
        raise ValueError("Passphrase is required.")

    try:
        blob = base64.b64decode(token, validate=True)
    except Exception as exc:
        raise DecryptionError("Ciphertext is not valid base64.") from exc

    if len(blob) < SALT_LEN + NONCE_LEN:
        raise DecryptionError("Ciphertext is too short / malformed.")

    salt = blob[:SALT_LEN]
    nonce = blob[SALT_LEN:SALT_LEN + NONCE_LEN]
    ciphertext = blob[SALT_LEN + NONCE_LEN:]

    key = _derive_key(passphrase, salt)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong passphrase or corrupted/tampered ciphertext."
        ) from exc

    return plaintext.decode("utf-8")

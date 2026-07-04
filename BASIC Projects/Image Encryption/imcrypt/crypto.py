"""
crypto.py

Key handling and cipher implementations built on top of the `cryptography`
library. Every encryption call generates a fresh random IV/nonce (and salt,
when deriving a key from a password) -- callers never reuse one.
"""

import os

from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# ---- identifiers persisted in the encrypted file header ----
CIPHER_AES_CBC = 1
CIPHER_AES_GCM = 2
CIPHER_CHACHA20_POLY1305 = 3

CIPHER_NAME_TO_ID = {
	"aes-cbc": CIPHER_AES_CBC,
	"aes-gcm": CIPHER_AES_GCM,
	"chacha20": CIPHER_CHACHA20_POLY1305,
}
CIPHER_ID_TO_NAME = {v: k for k, v in CIPHER_NAME_TO_ID.items()}

KEY_SIZE = 32  # 256-bit key for all supported ciphers
PBKDF2_ITERATIONS = 480_000
SALT_SIZE = 16


# ---------------------------- key handling ---------------------------- #

def generate_random_key():
	"""Return a fresh random 256-bit key."""
	return os.urandom(KEY_SIZE)


def derive_key_from_password(password, salt):
	"""Derive a 256-bit key from a password using PBKDF2-HMAC-SHA256."""
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=KEY_SIZE,
		salt=salt,
		iterations=PBKDF2_ITERATIONS,
	)
	return kdf.derive(password.encode("utf-8"))


# ------------------------------ AES-CBC ------------------------------- #

def _aes_cbc_encrypt(key, plaintext):
	iv = os.urandom(16)
	padder = padding.PKCS7(algorithms.AES.block_size).padder()
	padded = padder.update(plaintext) + padder.finalize()
	encryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
	ciphertext = encryptor.update(padded) + encryptor.finalize()
	return iv, ciphertext


def _aes_cbc_decrypt(key, iv, ciphertext):
	decryptor = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
	padded = decryptor.update(ciphertext) + decryptor.finalize()
	unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
	return unpadder.update(padded) + unpadder.finalize()


# ------------------------------ AES-GCM ------------------------------- #

def _aes_gcm_encrypt(key, plaintext):
	nonce = os.urandom(12)
	aesgcm = AESGCM(key)
	ciphertext = aesgcm.encrypt(nonce, plaintext, None)  # tag appended by cryptography
	return nonce, ciphertext


def _aes_gcm_decrypt(key, nonce, ciphertext):
	aesgcm = AESGCM(key)
	return aesgcm.decrypt(nonce, ciphertext, None)


# -------------------------- ChaCha20-Poly1305 -------------------------- #

def _chacha20_encrypt(key, plaintext):
	nonce = os.urandom(12)
	chacha = ChaCha20Poly1305(key)
	ciphertext = chacha.encrypt(nonce, plaintext, None)
	return nonce, ciphertext


def _chacha20_decrypt(key, nonce, ciphertext):
	chacha = ChaCha20Poly1305(key)
	return chacha.decrypt(nonce, ciphertext, None)


# ---------------------------- public dispatch ---------------------------- #

def encrypt(cipher_name, key, plaintext):
	"""
	Encrypt plaintext with the chosen cipher/mode using a fresh random IV/nonce.
	Returns (cipher_id: int, iv_or_nonce: bytes, ciphertext: bytes).
	"""
	cipher_id = CIPHER_NAME_TO_ID[cipher_name]
	if cipher_id == CIPHER_AES_CBC:
		iv, ciphertext = _aes_cbc_encrypt(key, plaintext)
	elif cipher_id == CIPHER_AES_GCM:
		iv, ciphertext = _aes_gcm_encrypt(key, plaintext)
	elif cipher_id == CIPHER_CHACHA20_POLY1305:
		iv, ciphertext = _chacha20_encrypt(key, plaintext)
	else:
		raise ValueError(f"Unsupported cipher: {cipher_name}")
	return cipher_id, iv, ciphertext


def decrypt(cipher_id, key, iv, ciphertext):
	"""Decrypt ciphertext using the cipher identified by cipher_id."""
	if cipher_id == CIPHER_AES_CBC:
		return _aes_cbc_decrypt(key, iv, ciphertext)
	elif cipher_id == CIPHER_AES_GCM:
		return _aes_gcm_decrypt(key, iv, ciphertext)
	elif cipher_id == CIPHER_CHACHA20_POLY1305:
		return _chacha20_decrypt(key, iv, ciphertext)
	else:
		raise ValueError(f"Unsupported cipher id: {cipher_id}")

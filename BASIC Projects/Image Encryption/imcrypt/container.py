"""
container.py

Defines the on-disk binary format for an encrypted image (.imc file) and
provides pack/unpack helpers. Every field needed to decrypt and rebuild the
original image is stored in the header: cipher used, salt (if a password was
used), the random IV/nonce, and the original image's mode/dimensions.

Layout:
	4 bytes   magic        b"IMCR"
	1 byte    version
	1 byte    cipher_id
	1 byte    kdf_flag     0 = raw key file, 1 = password-derived key
	1 byte    salt_len
	N bytes   salt         (present only if kdf_flag == 1)
	1 byte    iv_len
	N bytes   iv_or_nonce
	1 byte    mode_len
	N bytes   mode         (Pillow image mode, e.g. "RGB", ascii)
	4 bytes   width        (big-endian unsigned)
	4 bytes   height       (big-endian unsigned)
	...       ciphertext   (rest of file)
"""

import struct

MAGIC = b"IMCR"
VERSION = 1

KDF_NONE = 0
KDF_PASSWORD = 1


def pack(cipher_id, kdf_flag, salt, iv, mode, size, ciphertext):
	width, height = size
	salt = salt or b""
	parts = [
		MAGIC,
		struct.pack("BBB", VERSION, cipher_id, kdf_flag),
		struct.pack("B", len(salt)),
		salt,
		struct.pack("B", len(iv)),
		iv,
		struct.pack("B", len(mode.encode("ascii"))),
		mode.encode("ascii"),
		struct.pack(">II", width, height),
		ciphertext,
	]
	return b"".join(parts)


def unpack(data):
	if data[:4] != MAGIC:
		raise ValueError("Not a valid imcrypt (.imc) file")
	offset = 4
	version, cipher_id, kdf_flag = struct.unpack_from("BBB", data, offset)
	offset += 3

	(salt_len,) = struct.unpack_from("B", data, offset)
	offset += 1
	salt = data[offset : offset + salt_len]
	offset += salt_len

	(iv_len,) = struct.unpack_from("B", data, offset)
	offset += 1
	iv = data[offset : offset + iv_len]
	offset += iv_len

	(mode_len,) = struct.unpack_from("B", data, offset)
	offset += 1
	mode = data[offset : offset + mode_len].decode("ascii")
	offset += mode_len

	width, height = struct.unpack_from(">II", data, offset)
	offset += 8

	ciphertext = data[offset:]

	return {
		"version": version,
		"cipher_id": cipher_id,
		"kdf_flag": kdf_flag,
		"salt": salt,
		"iv": iv,
		"mode": mode,
		"size": (width, height),
		"ciphertext": ciphertext,
	}

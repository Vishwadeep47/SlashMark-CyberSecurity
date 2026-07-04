"""
cli.py

Command-line interface for imcrypt.

Usage:
	python -m imcrypt encrypt photo.png -c aes-gcm
	python -m imcrypt encrypt photo.png -c chacha20 --password
	python -m imcrypt decrypt photo.imc -k photo_key.bin -o photo_decrypted.png
	python -m imcrypt decrypt photo.imc --password -o photo_decrypted.png
"""

import argparse
import base64
import getpass
import os
import sys

from . import container, crypto, image_io


def _default_output(input_path, suffix, new_ext=None):
	base, ext = os.path.splitext(input_path)
	if new_ext is not None:
		ext = new_ext
	return f"{base}{suffix}{ext}"


def _save_key_file(key, path):
	with open(path, "wb") as f:
		f.write(base64.b64encode(key))


def _load_key_file(path):
	with open(path, "rb") as f:
		return base64.b64decode(f.read())


def encrypt_command(args):
	mode, size, raw_bytes = image_io.load_image_bytes(args.input)

	if args.password:
		password = getpass.getpass("Enter password: ")
		confirm = getpass.getpass("Confirm password: ")
		if password != confirm:
			print("Error: passwords do not match.", file=sys.stderr)
			sys.exit(1)
		salt = os.urandom(crypto.SALT_SIZE)
		key = crypto.derive_key_from_password(password, salt)
		kdf_flag = container.KDF_PASSWORD
	else:
		key = crypto.generate_random_key()
		salt = b""
		kdf_flag = container.KDF_NONE

	cipher_id, iv, ciphertext = crypto.encrypt(args.cipher, key, raw_bytes)

	blob = container.pack(cipher_id, kdf_flag, salt, iv, mode, size, ciphertext)

	output_path = args.output or _default_output(args.input, "_encrypted", ".imc")
	with open(output_path, "wb") as f:
		f.write(blob)

	print(f"Encrypted image written to: {output_path}")
	print(f"Cipher used: {args.cipher}")

	if kdf_flag == container.KDF_NONE:
		key_path = args.key_file or _default_output(args.input, "_key", ".bin")
		_save_key_file(key, key_path)
		print(f"Key saved to: {key_path}")
		print("Keep this key file safe -- it is required to decrypt the image.")
	else:
		print("Key derived from your password (salt stored in the .imc file).")
		print("Remember your password -- it is required to decrypt the image.")


def decrypt_command(args):
	with open(args.input, "rb") as f:
		blob = f.read()

	parsed = container.unpack(blob)
	cipher_name = crypto.CIPHER_ID_TO_NAME.get(parsed["cipher_id"])
	if cipher_name is None:
		print("Error: unknown cipher id in file header.", file=sys.stderr)
		sys.exit(1)

	if parsed["kdf_flag"] == container.KDF_PASSWORD:
		password = getpass.getpass("Enter password: ")
		key = crypto.derive_key_from_password(password, parsed["salt"])
	else:
		if not args.key_file:
			print("Error: this file was encrypted with a key file; "
				"pass it with -k/--key-file.", file=sys.stderr)
			sys.exit(1)
		key = _load_key_file(args.key_file)

	try:
		raw_bytes = crypto.decrypt(
			parsed["cipher_id"], key, parsed["iv"], parsed["ciphertext"]
		)
	except Exception:
		print(
			"Error: decryption failed. Wrong key/password, or the file is corrupted.",
			file=sys.stderr,
		)
		sys.exit(1)

	output_path = args.output or _default_output(args.input, "_decrypted", ".png")
	image_io.save_image_bytes(raw_bytes, parsed["mode"], parsed["size"], output_path)

	print(f"Decrypted image written to: {output_path}")
	print(f"Cipher used: {cipher_name}")


def build_parser():
	parser = argparse.ArgumentParser(
		prog="imcrypt",
		description="Encrypt/decrypt images with AES-CBC, AES-GCM, or ChaCha20-Poly1305.",
	)
	subparsers = parser.add_subparsers(dest="command", required=True)

	enc = subparsers.add_parser("encrypt", help="Encrypt an image")
	enc.add_argument("input", help="Path to the image to encrypt")
	enc.add_argument(
		"-c", "--cipher",
		choices=list(crypto.CIPHER_NAME_TO_ID.keys()),
		default="aes-gcm",
		help="Cipher/mode to use (default: aes-gcm)",
	)
	enc.add_argument("-o", "--output", help="Output path for the encrypted (.imc) file")
	enc.add_argument("-k", "--key-file", help="Output path for the generated key file")
	enc.add_argument(
		"--password", action="store_true",
		help="Derive the key from a password instead of generating a key file",
	)
	enc.set_defaults(func=encrypt_command)

	dec = subparsers.add_parser("decrypt", help="Decrypt an .imc file back into an image")
	dec.add_argument("input", help="Path to the encrypted .imc file")
	dec.add_argument("-o", "--output", help="Output path for the decrypted image")
	dec.add_argument("-k", "--key-file", help="Path to the key file used at encryption time")
	dec.add_argument(
		"--password", action="store_true",
		help="Decrypt using a password instead of a key file",
	)
	dec.set_defaults(func=decrypt_command)

	return parser


def main():
	parser = build_parser()
	args = parser.parse_args()
	args.func(args)


if __name__ == "__main__":
	main()

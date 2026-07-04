"""
image_io.py

Handles reading raw pixel data out of an image with Pillow, and
rebuilding a Pillow Image from raw bytes after decryption.
"""

from PIL import Image


def load_image_bytes(path):
	"""
	Open an image with Pillow and return its raw pixel bytes plus
	the metadata (mode, size) needed to reconstruct it later.

	Returns:
		(mode: str, size: tuple[int, int], raw_bytes: bytes)
	"""
	with Image.open(path) as img:
		# Normalize to a concrete, well-understood mode so encryption/
		# decryption round-trips reliably regardless of the source format.
		if img.mode not in ("L", "RGB", "RGBA"):
			img = img.convert("RGBA")
		img.load()
		mode = img.mode
		size = img.size
		raw_bytes = img.tobytes()
	return mode, size, raw_bytes


def save_image_bytes(raw_bytes, mode, size, output_path):
	"""
	Rebuild a Pillow Image from raw pixel bytes and save it to disk.
	The output format is inferred from output_path's extension.
	"""
	img = Image.frombytes(mode, size, raw_bytes)
	img.save(output_path)

# imcrypt (Python)

A small CLI tool that encrypts images so that only holders of a secure key
(or password) can decrypt them, built with `cryptography` and `Pillow`.

## Features

- Reads/writes images with **Pillow** (`RGB`, `RGBA`, `L` modes supported).
- Encrypts raw pixel data with **multiple ciphers/modes**:
  - `aes-cbc` — AES-256 in CBC mode with PKCS7 padding
  - `aes-gcm` — AES-256 in GCM mode (authenticated)
  - `chacha20` — ChaCha20-Poly1305 (authenticated)
- A fresh, random IV/nonce is generated for **every** encryption — never reused.
- Two key-handling options:
  - Auto-generated random 256-bit key, saved to a `.key` file
  - Password-based key derivation (PBKDF2-HMAC-SHA256, 480,000 iterations, random salt)
- Output is a self-describing `.imc` binary container: cipher id, salt (if
  password-based), IV/nonce, and original image mode/dimensions, followed by
  the ciphertext.

## Install

```bash
pip install -r requirements.txt
```

## Usage

Encrypt with a generated key file (default cipher: AES-GCM):

```bash
python -m imcrypt encrypt photo.png
# -> photo_encrypted.imc, photo_key.bin
```

Choose a different cipher:

```bash
python -m imcrypt encrypt photo.png -c aes-cbc
python -m imcrypt encrypt photo.png -c chacha20
```

Encrypt with a password instead of a key file:

```bash
python -m imcrypt encrypt photo.png --password
```

Decrypt:

```bash
python -m imcrypt decrypt photo_encrypted.imc -k photo_key.bin -o photo_decrypted.png
python -m imcrypt decrypt photo_encrypted.imc --password -o photo_decrypted.png
```

## How it works

1. Pillow opens the image and exposes its raw pixel bytes (`Image.tobytes()`).
2. A 256-bit key is either generated randomly or derived from a password via
   PBKDF2-HMAC-SHA256 with a random salt.
3. The chosen cipher encrypts the raw pixel bytes with a freshly generated
   IV/nonce.
4. Cipher id, salt (if any), IV/nonce, image mode, and image size are packed
   into a small binary header, followed by the ciphertext, and written to a
   `.imc` file.
5. Decryption reverses the process and uses `Image.frombytes()` to rebuild a
   real, viewable image file.

## Project layout

```
imcrypt/
  cli.py        # argparse CLI, encrypt/decrypt commands
  crypto.py     # key derivation + AES-CBC / AES-GCM / ChaCha20-Poly1305
  container.py  # binary .imc file format (pack/unpack)
  image_io.py   # Pillow read/write helpers
```

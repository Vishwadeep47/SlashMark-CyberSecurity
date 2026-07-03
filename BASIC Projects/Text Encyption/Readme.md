# Text Encryption 

A simple web app to encrypt and decrypt user-entered text using **AES-256-GCM**, with a password-derived key (PBKDF2) and a random salt + nonce on every run — so encrypting the same text twice never produces the same output.

Built as a learning project covering: symmetric encryption basics, IV/nonce handling, and secure key storage.

---

## Features

- Encrypt any text with a passphrase — no account, no server-side storage
- Decrypt a ciphertext token back to the original text, given the correct passphrase
- Tamper detection: a wrong passphrase or a modified ciphertext fails loudly instead of silently returning garbage
- Every encryption call uses a fresh random salt and nonce, so identical input never produces identical output
- No encryption key is ever stored anywhere — it's derived from your passphrase on demand and discarded after use
- Simple browser UI, plus a matching JSON API for `curl`/Postman

---

## Tech Stack

| Layer      | Choice                                  |
|------------|------------------------------------------|
| Backend    | Python, Flask                            |
| Crypto     | `cryptography` library — AES-256-GCM + PBKDF2-HMAC-SHA256 |
| Frontend   | HTML, CSS, vanilla JavaScript (`fetch`)  |

---

## Project Structure

```
Text Encryption/
├── app.py              # Flask routes — UI page + JSON API endpoints
├── crypto_utils.py      # All encryption/decryption logic
├── requirements.txt     # Python dependencies
├── templates/
│   └── index.html       # Browser UI
└── static/
    └── style.css         # Styling
```

---

## Setup

**1. Requirements**

- Python 3.9 or newer
- pip

**2. Install dependencies**

From inside the project folder:

```bash
pip install -r requirements.txt
```

If `pip` isn't recognized, or you have multiple Python versions installed, use:

```bash
python -m pip install -r requirements.txt
```

**3. Run the app**

```bash
python app.py
```

You should see output like:

```
 * Running on http://127.0.0.1:5000
```

**4. Open it**

Visit **http://127.0.0.1:5000** in your browser.

> `debug=True` is enabled in `app.py` for local development — the server auto-reloads whenever you save a file. Do not use this setting in production.

---

## Usage

### Browser UI

1. Type text into the **Plaintext** box and a passphrase, then click **Encrypt**.
2. Copy the resulting ciphertext token.
3. Paste it into the **Ciphertext** box on the Decrypt side with the same passphrase, then click **Decrypt** to recover the original text.

### JSON API

Two endpoints are available if you want to call the app programmatically instead of using the browser form.

**Encrypt**

```bash
curl -X POST http://127.0.0.1:5000/api/encrypt \
  -H "Content-Type: application/json" \
  -d '{"text": "Hello World", "passphrase": "Hi"}'
```

Response:
```json
{ "result": "base64-encoded-token-here" }
```

**Decrypt**

```bash
curl -X POST http://127.0.0.1:5000/api/decrypt \
  -H "Content-Type: application/json" \
  -d '{"text": "base64-encoded-token-here", "passphrase": "Hi"}'
```

Response:
```json
{ "result": "Hello World" }
```

A wrong passphrase or a corrupted token returns a `400` with an `error` message instead of garbage output.

---

## How It Works

The output token is a single base64 string made of three parts, concatenated:

```
salt (16 bytes) | nonce (12 bytes) | ciphertext + authentication tag
```

**1. Key derivation (secure key storage)**

No encryption key is ever written to disk, hardcoded, or stored in a config file. Instead, `crypto_utils.py` derives a 256-bit key from your passphrase every time, using **PBKDF2-HMAC-SHA256** with 390,000 iterations (the OWASP-recommended minimum) and a random 16-byte salt. Once the key is used, it's discarded — there's nothing persistent to steal.

**2. Random salt + nonce (unique outputs for identical inputs)**

- The **salt** feeds the key derivation step. A new random salt each time means a new derived key each time, even with the same passphrase.
- The **nonce** (a.k.a IV) feeds AES-GCM itself and must never repeat for a given key.

Because both are freshly randomized on every call, encrypting the exact same text with the exact same passphrase twice produces two completely different ciphertexts.

**3. Authenticated encryption (tamper detection)**

AES-**GCM** (as opposed to AES-CBC) produces both ciphertext and a 16-byte authentication tag. On decryption, if the passphrase is wrong or the token has been altered in any way, the tag check fails and the app raises a clear error — it never silently decrypts into corrupted plaintext.

---

---

## Reference

The AES-GCM + password-based key derivation design in this project follows the same pattern taught in Svetlin Nakov's *[Practical Cryptography for Developers](https://cryptobook.nakov.com/)* — specifically the "AES Encrypt / Decrypt Examples" chapter, which walks through the same salt + nonce + authenticated-encryption construction, using Scrypt instead of PBKDF2 for the key derivation step.

---


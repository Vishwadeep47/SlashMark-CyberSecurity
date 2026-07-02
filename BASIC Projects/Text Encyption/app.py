

from flask import Flask, render_template, request, jsonify

from crypto_utils import encrypt, decrypt, DecryptionError

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    passphrase = data.get("passphrase", "")

    try:
        token = encrypt(text, passphrase)
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"result": token})


@app.route("/api/decrypt", methods=["POST"])
def api_decrypt():
    data = request.get_json(silent=True) or {}
    token = data.get("text", "")
    passphrase = data.get("passphrase", "")

    try:
        plaintext = decrypt(token, passphrase)
    except (ValueError, DecryptionError) as exc:
        return jsonify({"error": str(exc)}), 400

    return jsonify({"result": plaintext})


if __name__ == "__main__":
    # debug=True is fine for local learning/dev only, never in production
    app.run(debug=True)

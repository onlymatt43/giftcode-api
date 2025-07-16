from flask import Flask, request, jsonify, send_file
from fpdf import FPDF
import secrets
import time
import os
import io
import qrcode
import zipfile
import json

# Charger le catalogue produit (durée et lien de redirection)
try:
    with open("product_catalog.json", "r") as f:
        product_catalog = json.load(f)
except:
    product_catalog = {}

DEFAULT_LINK = "https://monsite.com/unlock"
DEFAULT_DURATION = 60
TOKENS_FILE = "tokens.json"
FRONTEND_URL = "https://ornate-dodol-8a4655.netlify.app"

app = Flask(__name__)

def load_tokens():
    if os.path.exists(TOKENS_FILE):
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    return []

def save_tokens(tokens):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f)

@app.route("/generate", methods=["POST"])
def generate():
    try:
        data = request.get_json()
        count = int(data.get("count", 5))
        duration = int(data.get("duration", 60))
        product = data.get("product", "Produit")

        tokens = load_tokens()
        new_tokens = []

        for _ in range(count):
            token = secrets.token_urlsafe(8)
            expires_at = int(time.time()) + duration * 60
            tokens.append({"token": token, "valid_until": expires_at})
            new_tokens.append(token)

        save_tokens(tokens)

        return jsonify({"tokens": new_tokens}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/validate", methods=["POST"])
def validate():
    try:
        data = request.get_json()
        token = data.get("token")
        tokens = load_tokens()

        for t in tokens:
            if t["token"] == token:
                if int(time.time()) < t["valid_until"]:
                    return jsonify({"valid": True}), 200
                else:
                    return jsonify({"valid": False, "reason": "expired"}), 403

        return jsonify({"valid": False, "reason": "not found"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/payhip-webhook", methods=["POST"])
def payhip_webhook():
    try:
        payload = request.form
        product = payload.get("product_name", "Produit")
        config = product_catalog.get(product, {})
        link = config.get("link", DEFAULT_LINK)
        duration = config.get("duration", DEFAULT_DURATION)
        count = int(payload.get("quantity", 1))

        response = app.test_client().post("/generate", json={
            "count": count,
            "duration": duration,
            "product": product
        })

        return (response.data, response.status_code, response.headers.items())

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
import os
import json
from flask import Flask, request, jsonify
from datetime import datetime, timedelta
from uuid import uuid4

app = Flask(__name__)

# === Chargement des fichiers de configuration ===
with open("product_catalog.json") as f:
    product_catalog = json.load(f)

with open("redirect_links.json") as f:
    site_by_product = json.load(f)

TOKENS_FILE = "tokens.db"
DEFAULT_LINK = "https://onlymatt.ca"
DEFAULT_DURATION = 60

# === Fonctions de gestion de tokens ===
def load_tokens():
    try:
        with open(TOKENS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []

def save_tokens(tokens):
    with open(TOKENS_FILE, "w") as f:
        json.dump(tokens, f)

# === Endpoint de génération de tokens ===
@app.route("/generate", methods=["POST"])
def generate():
    try:
        data = request.json
        count = int(data.get("count", 1))
        duration = int(data.get("duration", DEFAULT_DURATION))
        product = data.get("product", "Produit")
        tokens = load_tokens()

        for _ in range(count):
            token = str(uuid4()).replace("-", "")[:12].upper()
            tokens.append({
                "token": token,
                "used": False,
                "product": product,
                "valid_until": (datetime.utcnow() + timedelta(minutes=duration)).isoformat()
            })

        save_tokens(tokens)

        return jsonify({"tokens": [t["token"] for t in tokens[-count:]]})

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# === Endpoint de validation ===
@app.route("/validate", methods=["GET"])
def validate():
    token = request.args.get("token")
    tokens = load_tokens()
    now = datetime.utcnow()

    for t in tokens:
        if t["token"] == token:
            if not t["used"] and t.get("valid_until") and datetime.fromisoformat(t["valid_until"]) > now:
                return jsonify({"valid": True, "product": t["product"]})
            return jsonify({"valid": False, "reason": "Expired or already used"})
    return jsonify({"valid": False, "reason": "Not found"})

# === Webhook Payhip ===
@app.route("/payhip-webhook", methods=["POST"])
def webhook():
    try:
        payload = request.form or request.get_json() or {}
        product = payload.get("product_name", "Produit")
        config = product_catalog.get(product, {})
        link = config.get("link", DEFAULT_LINK)
        duration = config.get("duration", DEFAULT_DURATION)
        count = int(payload.get("quantity", 1))
        site = site_by_product.get(product, DEFAULT_LINK)

        response = app.test_client().post("/generate", json={
            "count": count,
            "duration": duration,
            "product": product
        })

        return (
            response.data,
            response.status_code,
            response.headers.items()
        )

    except Exception as e:
        return jsonify({"error": str(e)}), 400

# === Lancement serveur ===
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
from flask import Flask, request, jsonify, make_response
import json
import time
import secrets
import os

app = Flask(__name__)

# Chargement du fichier JSON externe avec les liens et durées
try:
    with open("product_catalog.json", "r") as f:
        product_catalog = json.load(f)
except:
    product_catalog = {}

DEFAULT_LINK = "https://monsite.com/unlock"
DEFAULT_DURATION = 60  # en minutes

@app.route("/payhip-webhook", methods=["POST"])
def webhook():
    try:
        payload = request.form or request.get_json() or {}
        product = payload.get("product_name", "Produit")
        token = secrets.token_urlsafe(12)

        item = product_catalog.get(product, {})
        link = item.get("link", DEFAULT_LINK)
        duration = item.get("duration", DEFAULT_DURATION)

        ip = request.remote_addr

        try:
            with open("tokens.json", "r") as f:
                tokens = json.load(f)
        except:
            tokens = {}

        tokens[token] = {
            "valid_until": int(time.time()) + duration * 60,
            "link": link,
            "used": False,
            "ip": ip
        }

        with open("tokens.json", "w") as f:
            json.dump(tokens, f)

        return jsonify({"token": token}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 400


@app.route("/validate", methods=["GET"])
def validate():
    token = request.cookies.get("access_token")
    if not token:
        return "Access denied: No token", 403

    try:
        with open("tokens.json", "r") as f:
            tokens = json.load(f)
    except:
        return "Access denied: No token DB", 403

    t = tokens.get(token)
    if not t or t.get("used"):
        return "Access denied: Invalid token", 403

    if t.get("ip") and t["ip"] != request.remote_addr:
        return "Access denied: IP mismatch", 403

    now = int(time.time())
    if now > t["valid_until"]:
        return "Access denied: Token expired", 403

    return jsonify({"access": True, "link": t["link"]}), 200


@app.route("/unlock")
def unlock_page():
    return "<h1>✅ Page débloquée avec succès !</h1>"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
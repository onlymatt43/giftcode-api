from flask import Flask, request, jsonify, make_response
import json
import time
import secrets
import os
import sqlite3

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
    payload = request.form or request.get_json() or {}
    product = payload.get("product_name", "").strip()
    ip = request.remote_addr

    if not product:
        return "Produit manquant", 400

    link = product_catalog.get(product, {}).get("link", DEFAULT_LINK)
    duration = product_catalog.get(product, {}).get("duration", DEFAULT_DURATION)

    token = str(uuid.uuid4())
    valid_until = int(time.time()) + duration * 60

    try:
        conn = sqlite3.connect("tokens.db")
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO tokens (token, link, ip, valid_until)
            VALUES (?, ?, ?, ?)
        """, (token, link, ip, valid_until))
        conn.commit()
        conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    return jsonify({"token": token}), 200


@app.route("/validate")
def validate():
    token = request.args.get("token")
    if not token:
        return "Access denied: No token", 403

    try:
        conn = sqlite3.connect("tokens.db")
        cursor = conn.cursor()
        cursor.execute("SELECT link, ip, valid_until FROM tokens WHERE token = ?", (token,))
        row = cursor.fetchone()
        conn.close()
    except Exception:
        return "Access denied: DB error", 403

    if not row:
        return "Access denied: Invalid token", 403

    link, ip, valid_until = row

    if ip != request.remote_addr:
        return "Access denied: IP mismatch", 403

    now = int(time.time())
    if now > valid_until:
        return "Access denied: Token expired", 403

    return jsonify({"access": True, "link": link}), 200


@app.route("/unlock")
def unlock_page():
    return "<h1>✅ Page débloquée avec succès !</h1>"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
@app.route("/debug-tokens")
def debug_tokens():
    try:
        conn = sqlite3.connect("tokens.db")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM tokens")
        rows = cursor.fetchall()
        conn.close()
        return jsonify({"tokens": rows})
    except Exception as e:
        return jsonify({"error": str(e)}), 500    

from flask import Flask, request, jsonify, render_template
import sqlite3
import uuid
import datetime
import json
import os

app = Flask(__name__, template_folder='templates')

# === CONFIGURATION ===
DB_PATH = "tokens.db"
PRODUCT_CATALOG_PATH = "product_catalog.json"

# === Load Product Catalog ===
if os.path.exists(PRODUCT_CATALOG_PATH):
    with open(PRODUCT_CATALOG_PATH, "r") as f:
        PRODUCT_CATALOG = json.load(f)
else:
    PRODUCT_CATALOG = {}

# === Helper Functions ===
def get_ip():
    return request.remote_addr or "0.0.0.0"

def insert_token(token, link, ip, valid_until):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("INSERT INTO tokens (token, link, ip, valid_until) VALUES (?, ?, ?, ?)",
              (token, link, ip, valid_until))
    conn.commit()
    conn.close()

def is_token_valid(token, ip):
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT link, valid_until FROM tokens WHERE token=? AND ip=?", (token, ip))
    row = c.fetchone()
    conn.close()
    if not row:
        return None
    link, valid_until = row
    now = int(datetime.datetime.utcnow().timestamp())
    if now > valid_until:
        return None
    return link

# === Routes ===
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/unlock")
def unlock():
    token = request.args.get("token")
    ip = get_ip()

    if not token:
        return "Missing token", 400

    link = is_token_valid(token, ip)
    if not link:
        return "Invalid or expired token", 403

    # Find product name and duration from product catalog
    product_name = next((name for name, data in PRODUCT_CATALOG.items() if data["link"] == link), "Unlocked Product")
    duration = PRODUCT_CATALOG.get(product_name, {}).get("duration", "Unknown")

    return render_template("unlock.html", link=link, product=product_name, duration=duration)

@app.route("/validate")
def validate():
    token = request.args.get("token")
    ip = get_ip()

    if not token:
        return jsonify({"error": "Missing token"}), 400

    link = is_token_valid(token, ip)
    if not link:
        return jsonify({"valid": False}), 403

    return jsonify({"valid": True})

@app.route("/payhip-webhook", methods=["POST"])
def payhip_webhook():
    try:
        data = request.get_json(force=True)
    except Exception:
        data = request.form.to_dict()

    print("\n✅ Webhook reçu:", data)

    if data.get("event") != "order.completed":
        return jsonify({"status": "ignored"})

    product_name = data.get("product_name")
    email = data.get("email", "anonymous")
    ip = request.remote_addr or "0.0.0.0"

    product = PRODUCT_CATALOG.get(product_name)
    if not product:
        return jsonify({"error": "Unknown product"}), 400

    link = product["link"]
    duration_minutes = product["duration"]
    valid_until = int((datetime.datetime.utcnow() + datetime.timedelta(minutes=duration_minutes)).timestamp())

    token = str(uuid.uuid4())[:8]
    insert_token(token, link, ip, valid_until)

    print(f"🎟️ Token generated: {token} for {email} (product: {product_name})")

    return jsonify({"status": "ok", "token": token})

# === Run Flask App ===
if __name__ == "__main__":
    app.run(debug=True)

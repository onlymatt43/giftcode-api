from flask import Flask, request, jsonify, redirect
import sqlite3
import uuid
import datetime

app = Flask(__name__)

db_path = "tokens.db"

def get_ip():
    return request.remote_addr or "0.0.0.0"

def insert_token(token, link, ip, valid_until):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("INSERT INTO tokens (token, link, ip, valid_until) VALUES (?, ?, ?, ?)", (token, link, ip, valid_until))
    conn.commit()
    conn.close()

def is_token_valid(token, ip):
    conn = sqlite3.connect(db_path)
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

@app.route("/validate")
def validate():
    token = request.args.get("token")
    ip = get_ip()
    if not token:
        return jsonify({"error": "Missing token"}), 400
    link = is_token_valid(token, ip)
    if not link:
        return jsonify({"error": "Invalid or expired token"}), 403
    return redirect(link, code=302)

@app.route("/payhip-webhook", methods=["POST"])
def payhip_webhook():
    try:
        data = request.get_json(force=True)
    except Exception:
        data = request.form.to_dict()

    print("\n✅ Webhook reçu:", data)

    if data.get("event") != "order.completed":
        return jsonify({"error": "Ignored event"}), 200

    # Exemple basique, adapter selon ton setup produit Payhip
    link = "https://video.onlymatt.ca/unlock"
    token = str(uuid.uuid4()).replace("-", "").upper()[:16]
    ip = get_ip()
    valid_minutes = 10
    expires_at = int(datetime.datetime.utcnow().timestamp()) + (valid_minutes * 60)

    insert_token(token, link, ip, expires_at)

    print(f"\n✅ Token généré et inséré: {token}")
    return jsonify({"status": "ok", "token": token})

@app.route("/debug-tokens")
def debug_tokens():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        c.execute("SELECT * FROM tokens")
        rows = c.fetchall()
        return jsonify({"tokens": rows})
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        conn.close()

if __name__ == "__main__":
    app.run(debug=True)

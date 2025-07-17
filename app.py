from flask import Flask, request, jsonify, redirect, render_template, make_response
from token_tools.token_utils import get_ip, is_token_valid  # ✅ Corrigé ici
import sqlite3
import datetime
import uuid

app = Flask(__name__)

db_path = "flask_app/token_database.db"

def insert_token(token, link, ip, expires_at):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("INSERT INTO tokens (token, link, ip, expires_at) VALUES (?, ?, ?, ?)",
              (token, link, ip, expires_at))
    conn.commit()
    conn.close()

@app.route('/payhip-webhook', methods=["POST"])
def payhip_webhook():
    try:
        data = request.get_json(force=True)
    except Exception:
        data = request.form.to_dict()

    print("\n✅ Webhook reçu:", data)

    if data.get("event") != "order.completed":
        return jsonify({"error": "Ignored event"}), 200

    link = "https://video.onlymatt.ca/unlock"  # ✏️ Remplace si nécessaire
    token = str(uuid.uuid4()).replace("-", "").upper()[:16]
    ip = get_ip()
    valid_minutes = 10
    expires_at = int(datetime.datetime.utcnow().timestamp()) + (valid_minutes * 60)

    insert_token(token, link, ip, expires_at)
    print(f"\n✅ Token généré et inséré: {token}")
    return jsonify({"status": "ok", "token": token})

@app.route("/debug-tokens")
def debug_tokens():
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM tokens")
        rows = c.fetchall()
        return jsonify({"tokens": rows})
    except Exception as e:
        return jsonify({"error": str(e)})
    finally:
        conn.close()

@app.route('/')
def index():
    return redirect('/unlock')  # 🔐 Redirige vers la page sécurisée

if __name__ == '__main__':
    app.run(debug=True)
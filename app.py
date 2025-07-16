from flask import Flask, request, jsonify, send_file
from fpdf import FPDF
import secrets
import time
import os
import io
import qrcode
import zipfile
import json

app = Flask(__name__)

TOKENS_FILE = "tokens.json"
FRONTEND_URL = "https://ornate-dodol-8a4655.netlify.app"

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
        port = request.environ.get('SERVER_PORT', 5000)

        tokens = []
        pdf_files = []
        now = int(time.time())

        for _ in range(count):
            token = secrets.token_hex(5).upper()
            tokens.append({
                "token": token,
                "valid_until": now + duration * 60,
                "used": False,
                "product": product
            })

            full_url = f"{FRONTEND_URL}/?token={token}"

            # QR code
            qr = qrcode.make(full_url)
            qr_io = io.BytesIO()
            qr.save(qr_io, format="PNG")
            qr_io.seek(0)

            # PDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", size=12)
            pdf.multi_cell(0, 10, f"""Code: {token}
Lien: {full_url}""")

            # Ajout logo si besoin
            # pdf.image("logo.png", x=10, y=8, w=30)

            # Ajout QR
            qr_path = f"/tmp/{token}.png"
            with open(qr_path, "wb") as f:
                f.write(qr_io.read())
            pdf.image(qr_path, x=80, y=60, w=60)

            pdf_path = f"/tmp/{token}.pdf"
            pdf.output(pdf_path)
            pdf_files.append(pdf_path)

        save_tokens(tokens)

        # ZIP
        zip_io = io.BytesIO()
        with zipfile.ZipFile(zip_io, "w") as zipf:
            for token, path in zip(tokens, pdf_files):
                zipf.write(path, arcname=f"GIFT-{product}-{token['token']}.pdf")
        zip_io.seek(0)

        return send_file(zip_io, mimetype="application/zip", as_attachment=True, download_name="giftcodes.zip")

    except Exception as e:
        return jsonify({"error": str(e)}), 400

@app.route("/validate", methods=["GET"])
def validate():
    token = request.args.get("token", "")
    tokens = load_tokens()
    now = int(time.time())
    for t in tokens:
        if t["token"] == token:
            if not t["used"] and t["valid_until"] > now:
                return jsonify({"valid": True, "product": t["product"]})
            return jsonify({"valid": False, "reason": "Expired or already used"})
    return jsonify({"valid": False, "reason": "Not found"})

@app.route("/payhip-webhook", methods=["POST"])
def webhook():
    try:
        payload = request.form
        product = payload.get("product_name", "Produit")
        count = int(payload.get("quantity", 1))

        response = app.test_client().post("/generate", json={
            "count": count,
            "duration": 60,
            "product": product
        })

        return (response.data, response.status_code, response.headers.items())
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

from flask import Flask, request, send_file, jsonify
import json, os, io, time, secrets, zipfile
from fpdf import FPDF
import qrcode

app = Flask(__name__)
TOKENS_FILE = "tokens.json"

# Utility to load/save tokens
def load_tokens():
    if not os.path.exists(TOKENS_FILE): return {}
    with open(TOKENS_FILE, 'r') as f:
        return json.load(f)

def save_tokens(tokens):
    with open(TOKENS_FILE, 'w') as f:
        json.dump(tokens, f, indent=2)

# Token generator
@app.route("/generate", methods=["POST"])
def generate():
    try:
        count = int(request.form.get("count", 5))
        duration = int(request.form.get("duration", 60)) * 60
        product = request.form.get("product", "Produit")
        link = request.form.get("link", "https://exemple.com")
        logo = request.files.get("logo")

        tokens = load_tokens()
        new_tokens = {}
        now = int(time.time())
        pdf_files = []

        for _ in range(count):
            token = secrets.token_hex(5).upper()
            tokens[token] = {
                "valid_until": now + duration,
                "used": False,
                "scope": [product],
                "video": "clip.mp4"
            }
            full_url = f"{link}?token={token}"

            # QR
            qr = qrcode.make(full_url)
            qr_io = io.BytesIO()
            qr.save(qr_io, format='PNG')
            qr_io.seek(0)

            # PDF
            pdf = FPDF()
            pdf.add_page()
            pdf.set_font("Arial", 'B', 14)
            pdf.cell(0, 10, f"Merci pour votre achat - {product}", ln=True)
            pdf.set_font("Arial", '', 12)
            pdf.ln(10)
            pdf.multi_cell(0, 10, f"Code: {token}")
Durée: {duration // 60} minutes
Lien: {link}
{full_url}")

            if logo:
                logo_path = f"/tmp/logo.png"
                logo.save(logo_path)
                pdf.image(logo_path, x=10, y=80, w=40)

            qr_path = f"/tmp/qr_{token}.png"
            with open(qr_path, "wb") as f: f.write(qr_io.read())
            pdf.image(qr_path, x=100, y=80, w=60)

            pdf_file = f"/tmp/{token}.pdf"
            pdf.output(pdf_file)
            pdf_files.append((token, pdf_file))

        save_tokens(tokens)

        # Zip everything
        zip_io = io.BytesIO()
        with zipfile.ZipFile(zip_io, 'w') as zipf:
            for token, path in pdf_files:
                zipf.write(path, arcname=f"GIFT-{product}-{token}.pdf")
        zip_io.seek(0)

        return send_file(zip_io, mimetype="application/zip", as_attachment=True, download_name="giftcodes.zip")

    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)

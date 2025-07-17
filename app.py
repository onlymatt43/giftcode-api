
from flask import Flask, request, jsonify, render_template, make_response, abort
import json
from datetime import datetime, timedelta

app = Flask(__name__)

# Simulated product catalog
with open("product_catalog.json") as f:
    CATALOG = json.load(f)

TOKENS = {}

def get_ip():
    return request.remote_addr

def is_token_valid(token, ip):
    entry = TOKENS.get(token)
    if not entry:
        return None
    if entry["ip"] != ip:
        return None
    if datetime.utcnow() > datetime.fromisoformat(entry["expires_at"]):
        return None
    return entry["link"]

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/validate", methods=["POST"])
def validate():
    data = request.get_json()
    token = data.get("token")
    ip = get_ip()

    product = CATALOG.get(token)
    if not product:
        return jsonify(valid=False), 403

    duration = product.get("duration", 1800)  # default to 30 min
    expires_at = datetime.utcnow() + timedelta(seconds=duration)
    TOKENS[token] = {
        "ip": ip,
        "expires_at": expires_at.isoformat(),
        "link": product["link"]
    }
    return jsonify(valid=True, duration=duration)

@app.route("/unlock")
def unlock():
    token = request.cookies.get("gift_token")
    ip = get_ip()
    link = is_token_valid(token, ip)
    if not link:
        abort(403)
    return render_template("unlock.html", link=link)

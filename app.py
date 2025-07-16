
from flask import Flask, request, jsonify
import json
import time

app = Flask(__name__)

TOKENS_FILE = "tokens.json"

def load_tokens():
    with open(TOKENS_FILE, "r") as f:
        return json.load(f)

@app.route("/validate")
def validate():
    token = request.args.get("token")
    if not token:
        return jsonify({"valid": False, "reason": "Missing token"})

    tokens = load_tokens()
    if token not in tokens:
        return jsonify({"valid": False, "reason": "Invalid token"})

    token_data = tokens[token]
    now = int(time.time())

    if token_data["used"]:
        return jsonify({"valid": False, "reason": "Token already used"})

    if token_data["valid_until"] < now:
        return jsonify({"valid": False, "reason": "Token expired"})

    return jsonify({
        "valid": True,
        "expires_in": token_data["valid_until"] - now,
        "scope": token_data["scope"],
        "video": token_data["video"]
    })

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)

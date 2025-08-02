import json
import os
import hashlib
import hmac
import base64
import time

TOKENS_FILE = "token_store.json"
PARENT_FILE = "parent_tokens.json"
LOG_FILE = "system.log"

def load_tokens():
    if not os.path.exists(TOKENS_FILE):
        return {}
    with open(TOKENS_FILE, "r") as f:
        return json.load(f)

def save_tokens(data):
    with open(TOKENS_FILE, "w") as f:
        json.dump(data, f, indent=2)

def load_parent_tokens():
    if not os.path.exists(PARENT_FILE):
        return {}
    with open(PARENT_FILE, "r") as f:
        return json.load(f)

def save_parent_tokens(data):
    with open(PARENT_FILE, "w") as f:
        json.dump(data, f, indent=2)

def hash_code(code, secret):
    return hmac.new(secret.encode(), code.encode(), hashlib.sha256).hexdigest()

def create_cookie(cb_hash, ip, expires, secret):
    payload = f"{cb_hash}|{ip}|{expires}"
    sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f"{payload}|{sig}".encode()).decode()

def validate_cookie(cookie, secret):
    try:
        decoded = base64.urlsafe_b64decode(cookie).decode()
        cb_hash, ip, expires, sig = decoded.split("|")
        payload = f"{cb_hash}|{ip}|{expires}"
        good_sig = hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()
        now = int(time.time())
        if hmac.compare_digest(sig, good_sig) and now <= int(expires):
            return {"valid": True, "cb_hash": cb_hash, "ip": ip, "expires": expires}
    except Exception:
        pass
    return {"valid": False}

def log_event(text):
    with open(LOG_FILE, "a") as f:
        f.write(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] - {text}\n")
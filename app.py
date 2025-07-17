from flask import Flask, request, render_template, make_response
import json
import time
from datetime import datetime
from utils import get_ip, is_token_valid  # Assurez-vous que ces fonctions sont définies

app = Flask(__name__)

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/unlock")
def unlock():
    token = request.args.get("token") or request.cookies.get("token")
    ip = get_ip()

    if not token:
        return render_template("unlock.html", invalid=True)

    link = is_token_valid(token, ip)
    if not link:
        return render_template("unlock.html", invalid=True)

    response = make_response(render_template("unlock.html", link=link, token=token))
    response.set_cookie("token", token, httponly=True)
    return response

if __name__ == "__main__":
    app.run(debug=True)
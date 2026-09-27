"""Deliberately vulnerable sample: Flask routes that trust request input. DO NOT ship.

Each route feeds user input straight into a dangerous sink, so the bundled taint
rules have a realistic source -> sink path to detect.
"""

import pickle

import requests
from flask import Flask, redirect, request, send_file

app = Flask(__name__)


@app.route("/download")
def download():
    # Vulnerable: path traversal, "?file=../../etc/passwd" (CWE-22).
    return send_file("/srv/files/" + request.args.get("file", ""))


@app.route("/preview")
def preview():
    # Vulnerable: SSRF, the server fetches any URL the caller supplies (CWE-918).
    return requests.get(request.args["url"], timeout=5).text


@app.route("/login/next")
def after_login():
    # Vulnerable: open redirect to an attacker-chosen site (CWE-601).
    return redirect(request.args.get("next", "/"))


@app.route("/greet")
def greet():
    # Vulnerable: reflected XSS, input returned as raw HTML (CWE-79).
    return "<h1>Hello " + request.args.get("name", "") + "</h1>"


@app.route("/session", methods=["POST"])
def restore_session():
    # Vulnerable: unpickling client-supplied bytes executes code (CWE-502).
    return str(pickle.loads(request.get_data()))


if __name__ == "__main__":
    # Vulnerable: Werkzeug debugger exposed on all interfaces (CWE-489).
    app.run(host="0.0.0.0", debug=True)

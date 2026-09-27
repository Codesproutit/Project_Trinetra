# Test targets for trinetra/rules/python.yaml, run with `semgrep --test`.
# `ruleid:` marks a line the rule MUST flag; `ok:` marks a line it must NOT flag.
# Deliberately vulnerable. Never import or execute this file.
# ruff: noqa
import hashlib
import os
import pickle
import random
import secrets
import ssl
import subprocess
import tempfile

import jinja2
import jwt
import requests
import yaml
from flask import Flask, redirect, render_template_string, request, send_file
from lxml import etree
from markupsafe import escape

app = Flask(__name__)


# ------------------------------------------------------------- sql-injection
def sql(cursor, user_id, name):
    # ruleid: trinetra.python.sql-injection
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    # ruleid: trinetra.python.sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: trinetra.python.sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(name))
    # ruleid: trinetra.python.sql-injection
    cursor.execute("SELECT * FROM users WHERE name = '" + name + "'")
    query = "DELETE FROM users WHERE id = " + user_id
    # ruleid: trinetra.python.sql-injection
    cursor.execute(query)
    # ok: trinetra.python.sql-injection
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    # ok: trinetra.python.sql-injection
    cursor.execute("SELECT 1")
    # ok: trinetra.python.sql-injection
    cursor.execute(f"SELECT 1")


# --------------------------------------------------------- command-injection
def cmd(host):
    # ruleid: trinetra.python.command-injection-shell
    subprocess.run(f"ping -c 1 {host}", shell=True)
    # ruleid: trinetra.python.command-injection-shell
    os.system("ping " + host)
    # ruleid: trinetra.python.command-injection-shell
    os.popen(host)
    # ok: trinetra.python.command-injection-shell
    subprocess.run(["ping", "-c", "1", host])
    # ok: trinetra.python.command-injection-shell
    subprocess.run("ls -la", shell=True)
    # ok: trinetra.python.command-injection-shell
    os.system("clear")


# ------------------------------------------------------------ code-injection
def code(expr):
    # ruleid: trinetra.python.code-injection
    eval(expr)
    # ruleid: trinetra.python.code-injection
    exec(expr)
    # ok: trinetra.python.code-injection
    eval("1 + 1")


# ---------------------------------------------------------------- flask-ssti
def ssti(tpl):
    # ruleid: trinetra.python.flask-ssti
    return render_template_string(tpl)


def ssti_ok():
    # ok: trinetra.python.flask-ssti
    return render_template_string("<p>{{ name }}</p>", name="x")


# ----------------------------------------------------- taint: request -> sink
@app.route("/download")
def download():
    name = request.args.get("file")
    # ruleid: trinetra.python.web-path-traversal
    return send_file(os.path.join("/srv/files", name))


@app.route("/read")
def read():
    path = request.args["p"]
    # ruleid: trinetra.python.web-path-traversal
    with open(path) as fh:
        return fh.read()


@app.route("/read-safe")
def read_safe():
    path = os.path.basename(request.args["p"])
    # ok: trinetra.python.web-path-traversal
    with open(os.path.join("/srv/files", path)) as fh:
        return fh.read()


@app.route("/fetch")
def fetch():
    url = request.args.get("url")
    # ruleid: trinetra.python.web-ssrf
    return requests.get(url).text


@app.route("/fetch-fixed")
def fetch_fixed():
    q = request.args.get("q")
    # ok: trinetra.python.web-ssrf
    return requests.get("https://api.example.com/search", params={"q": q}).text


@app.route("/go")
def go():
    # ruleid: trinetra.python.web-open-redirect
    return redirect(request.args.get("next"))


@app.route("/home")
def home():
    # ok: trinetra.python.web-open-redirect
    return redirect("/dashboard")


@app.route("/hello")
def hello():
    name = request.args.get("name", "")
    # ruleid: trinetra.python.web-reflected-xss
    return "<h1>Hello " + name + "</h1>"


@app.route("/hello-safe")
def hello_safe():
    name = escape(request.args.get("name", ""))
    # ok: trinetra.python.web-reflected-xss
    return "<h1>Hello " + name + "</h1>"


# ---------------------------------------------------------- deserialization
def deser(blob, text):
    # ruleid: trinetra.python.insecure-deserialization
    pickle.loads(blob)
    # ruleid: trinetra.python.insecure-deserialization
    yaml.load(text)
    # ruleid: trinetra.python.insecure-deserialization
    yaml.load(text, Loader=yaml.Loader)
    # ok: trinetra.python.insecure-deserialization
    yaml.safe_load(text)
    # ok: trinetra.python.insecure-deserialization
    yaml.load(text, Loader=yaml.SafeLoader)


def xxe(doc):
    # ruleid: trinetra.python.xxe-unsafe-parser
    parser = etree.XMLParser(resolve_entities=True)
    # ok: trinetra.python.xxe-unsafe-parser
    safe = etree.XMLParser(resolve_entities=False)
    return parser, safe


# ---------------------------------------------------------------- crypto/TLS
def crypto(data, url):
    # ruleid: trinetra.python.weak-hash
    hashlib.md5(data)
    # ruleid: trinetra.python.weak-hash
    hashlib.sha1(data)
    # ok: trinetra.python.weak-hash
    hashlib.md5(data, usedforsecurity=False)
    # ok: trinetra.python.weak-hash
    hashlib.sha256(data)
    # ruleid: trinetra.python.tls-verification-disabled
    requests.get(url, verify=False)
    # ok: trinetra.python.tls-verification-disabled
    requests.get(url)
    ctx = ssl.create_default_context()
    # ruleid: trinetra.python.tls-verification-disabled
    ctx.verify_mode = ssl.CERT_NONE


def tokens():
    # ruleid: trinetra.python.insecure-random-token
    reset_token = str(random.randint(100000, 999999))
    # ruleid: trinetra.python.insecure-random-token
    session_id = "".join(random.choice("abcdef") for _ in range(32))
    # ok: trinetra.python.insecure-random-token
    api_key = secrets.token_urlsafe(32)
    # ok: trinetra.python.insecure-random-token
    delay = random.random()
    return reset_token, session_id, api_key, delay


# ------------------------------------------------------------- configuration
def config():
    # ruleid: trinetra.python.flask-debug-enabled
    app.run(host="0.0.0.0", debug=True)
    # ok: trinetra.python.flask-debug-enabled
    app.run(host="127.0.0.1")
    # ruleid: trinetra.python.jinja2-autoescape-disabled
    env = jinja2.Environment(autoescape=False)
    # ruleid: trinetra.python.jinja2-autoescape-disabled
    env2 = jinja2.Environment(loader=None)
    # ok: trinetra.python.jinja2-autoescape-disabled
    env3 = jinja2.Environment(autoescape=jinja2.select_autoescape())
    # ruleid: trinetra.python.insecure-tempfile
    tmp = tempfile.mktemp()
    # ok: trinetra.python.insecure-tempfile
    fd, tmp2 = tempfile.mkstemp()
    return env, env2, env3, tmp, fd, tmp2


def jwt_checks(token, key):
    # ruleid: trinetra.python.jwt-verification-disabled
    jwt.decode(token, options={"verify_signature": False})
    # ok: trinetra.python.jwt-verification-disabled
    jwt.decode(token, key, algorithms=["HS256"])


# ------------------------------------------------------------------- secrets
# ruleid: trinetra.python.hardcoded-secret
DB_PASSWORD = "hunter2_placeholder"
# ruleid: trinetra.python.hardcoded-secret
API_KEY = "sk_live_FAKE_demo_key_do_not_use_1234567890"
# ruleid: trinetra.python.hardcoded-secret
settings = {"client_secret": "FAKE-9f8e7d6c5b4a"}
# ruleid: trinetra.python.hardcoded-secret
conn = connect(host="db", password="FAKE-s3cr3t-value")
# ok: trinetra.python.hardcoded-secret
PASSWORD_FIELD = "password_input"
# ok: trinetra.python.hardcoded-secret
API_KEY_HEADER = "X-Api-Key-Header"
# ok: trinetra.python.hardcoded-secret
SECRET_KEY = os.environ["SECRET_KEY"]
# ok: trinetra.python.hardcoded-secret
DB_PASSWORD_DEFAULT = "changeme"
# ok: trinetra.python.hardcoded-secret
password = ""


# ---------------------------------------------------- django settings module
# ruleid: trinetra.python.django-debug-enabled
DEBUG = True
INSTALLED_APPS = ["django.contrib.admin"]

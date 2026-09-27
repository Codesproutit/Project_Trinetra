# Trinetra rule fixture for trinetra/brains/static/rules/python/web.yaml
#
# Deliberately vulnerable snippets (and safe lookalikes) used only by
# `semgrep --test`. This is not a runnable application and must never be
# deployed. Secrets are read from the environment; nothing here is real.
import asyncio
import hashlib
import hmac
import io
import json
import os
import shutil
import string
import urllib.request
import xml.sax
import zipfile
from pathlib import Path
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import aiohttp
import defusedxml.ElementTree as SafeET
import environ
import httpx
import jinja2
import markupsafe
import requests
import requests as http_client
import urllib3
from django.conf import settings
from django.core.files.storage import default_storage
from django.http import FileResponse, HttpResponse, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, render
from django.shortcuts import redirect as django_redirect
from django.template import Context
from django.template import Template as DjangoTemplate
from django.urls import path, reverse
from django.utils.decorators import method_decorator
from django.utils.html import escape as dj_escape
from django.utils.html import format_html
from django.utils.http import url_has_allowed_host_and_scheme
from django.utils.safestring import SafeString, mark_safe
from django.views import View
from django.views.decorators.csrf import csrf_exempt, csrf_protect
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, RedirectResponse
from flask import (
    Flask,
    Response,
    abort,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    url_for,
)
from flask_cors import CORS, cross_origin
from flask_wtf.csrf import CSRFProtect
from jinja2 import Environment, FileSystemLoader, Template, select_autoescape
from jinja2.sandbox import SandboxedEnvironment
from lxml import etree
from lxml import etree as lxml_etree
from mako.template import Template as MakoTemplate
from rest_framework.views import APIView
from markupsafe import Markup, escape
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware as StarletteCORS
from werkzeug.security import safe_join
from werkzeug.serving import run_simple
from werkzeug.utils import secure_filename
from xml.sax.handler import feature_external_ges

from shop.models import Post
from shop.tasks import warm_caches

env = environ.Env()

# ===========================================================================
# settings.py-style module configuration (Django + Flask config objects)
# ===========================================================================
SECRET_KEY = os.environ["DJANGO_SECRET_KEY"]
INSTALLED_APPS = ["django.contrib.auth", "django.contrib.sessions", "corsheaders", "shop"]
ROOT_URLCONF = "shop.urls"

# ruleid: py-django-debug-enabled
DEBUG = True

# ruleid: py-django-debug-enabled
DEBUG = os.environ.get("DJANGO_DEBUG", "True") == "True"

# ruleid: py-django-debug-enabled
DEBUG = env.bool("DJANGO_DEBUG", default=True)

# ruleid: py-django-debug-enabled
DEBUG: bool = True

# ok: py-django-debug-enabled
DEBUG = False

# ok: py-django-debug-enabled
DEBUG = os.environ.get("DJANGO_DEBUG", "False") == "True"

# ok: py-django-debug-enabled
DEBUG = env.bool("DJANGO_DEBUG", default=False)

# ok: py-django-debug-enabled
DEBUG_TOOLBAR_ENABLED = True

# ruleid: py-django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["*"]

# ruleid: py-django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["shop.example.com", "*"]

# ruleid: py-django-allowed-hosts-wildcard
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "*").split(",")

# ruleid: py-django-allowed-hosts-wildcard
ALLOWED_HOSTS += ["*"]

# ok: py-django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["shop.example.com", ".shop.example.com"]

# ok: py-django-allowed-hosts-wildcard
ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

# ok: py-django-allowed-hosts-wildcard
ALLOWED_HOSTS = ["*.shop.example.com"]

# ruleid: py-cookie-secure-disabled
SESSION_COOKIE_SECURE = False

# ruleid: py-cookie-secure-disabled
CSRF_COOKIE_SECURE = False

# ok: py-cookie-secure-disabled
SESSION_COOKIE_SECURE = True

# ok: py-cookie-secure-disabled
CSRF_COOKIE_SECURE = os.environ.get("HTTPS_ONLY", "1") == "1"

# ruleid: py-cookie-httponly-disabled
SESSION_COOKIE_HTTPONLY = False

# ok: py-cookie-httponly-disabled
SESSION_COOKIE_HTTPONLY = True

# ok: py-cookie-httponly-disabled
CSRF_COOKIE_HTTPONLY = False

# django-cors-headers
CORS_ALLOW_CREDENTIALS = True

# ruleid: py-cors-wildcard-credentials
CORS_ALLOW_ALL_ORIGINS = True

# ruleid: py-cors-wildcard-credentials
CORS_ORIGIN_ALLOW_ALL = True

# ok: py-cors-wildcard-credentials
CORS_ALLOW_ALL_ORIGINS = False

# ok: py-cors-wildcard-credentials
CORS_ALLOWED_ORIGINS = ["https://shop.example.com", "https://admin.shop.example.com"]


class Config:
    SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
    SESSION_COOKIE_HTTPONLY = True


class ProductionConfig(Config):
    # ruleid: py-django-debug-enabled
    DEBUG = True
    # ruleid: py-cookie-secure-disabled
    SESSION_COOKIE_SECURE = False
    # ruleid: py-cookie-secure-disabled
    REMEMBER_COOKIE_SECURE = False
    # ruleid: py-cookie-httponly-disabled
    REMEMBER_COOKIE_HTTPONLY = False
    # ruleid: py-csrf-protection-disabled
    WTF_CSRF_ENABLED = False


class DevelopmentConfig(Config):
    # ok: py-django-debug-enabled
    DEBUG = True
    # ok: py-cookie-secure-disabled
    SESSION_COOKIE_SECURE = False


class TestingConfig(Config):
    TESTING = True
    # ok: py-csrf-protection-disabled
    WTF_CSRF_ENABLED = False


def enable_local_debugging():
    # ok: py-django-debug-enabled
    DEBUG = True
    # ok: py-django-allowed-hosts-wildcard
    ALLOWED_HOSTS = ["*"]
    return DEBUG, ALLOWED_HOSTS


# ===========================================================================
# Flask application
# ===========================================================================
app = Flask(__name__)
csrf = CSRFProtect(app)
UPLOAD_DIR = "/srv/shop/uploads"
REPORT_DIR = Path("/srv/shop/reports")
API_BASE = "https://api.partner.example.com"
ALLOWED_WEBHOOK_HOSTS = {"hooks.slack.com", "api.github.com"}
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "").encode()
FOOTER_TEMPLATE = "<footer>Shop Inc.</footer>"
ICON_CLASS = "icon-cart"
JINJA_OPTIONS = {"autoescape": True, "trim_blocks": True}

# ruleid: py-cors-wildcard-credentials
CORS(app, supports_credentials=True)

# ruleid: py-cors-wildcard-credentials
CORS(app, resources={r"/api/*": {"origins": "*"}}, supports_credentials=True)

# ruleid: py-cors-wildcard-credentials
CORS(app, origins="*", supports_credentials=True)

# ok: py-cors-wildcard-credentials
CORS(app, origins=["https://shop.example.com"], supports_credentials=True)

# ok: py-cors-wildcard-credentials
CORS(app, origins="*")

# ok: py-cors-wildcard-credentials
CORS(app, resources={r"/api/*": {"origins": ["https://admin.shop.example.com"]}}, supports_credentials=True)

# ruleid: py-jinja2-autoescape-disabled
report_env = Environment(loader=FileSystemLoader("reports"))

# ruleid: py-jinja2-autoescape-disabled
mail_env = jinja2.Environment(loader=jinja2.PackageLoader("shop"), autoescape=False)

# ruleid: py-jinja2-autoescape-disabled
app.jinja_env.autoescape = False

# ruleid: py-jinja2-autoescape-disabled
receipt_template = Template("<p>Thanks {{ name }}</p>", autoescape=False)

# ok: py-jinja2-autoescape-disabled
jinja_env = Environment(loader=FileSystemLoader("templates"), autoescape=select_autoescape(["html", "xml"]))

# ok: py-jinja2-autoescape-disabled
strict_env = jinja2.Environment(autoescape=True)

# ok: py-jinja2-autoescape-disabled
configured_env = Environment(**JINJA_OPTIONS)

# ok: py-jinja2-autoescape-disabled
sandbox_env = SandboxedEnvironment(autoescape=True)

# ruleid: py-xxe-insecure-parser-config
legacy_parser = etree.XMLParser(resolve_entities=True)

# ruleid: py-xxe-insecure-parser-config
feed_parser = lxml_etree.XMLParser(recover=True, no_network=False)

# ok: py-xxe-insecure-parser-config
hardened_parser = etree.XMLParser(resolve_entities=False, no_network=True, huge_tree=False)

# ok: py-xxe-insecure-parser-config
pretty_parser = etree.XMLParser(remove_blank_text=True)


def create_app():
    flask_app = Flask(__name__)
    # ruleid: py-flask-debug-enabled
    flask_app.config["DEBUG"] = True
    # ruleid: py-flask-debug-enabled
    flask_app.config.update(DEBUG=True, SECRET_KEY=os.environ["FLASK_SECRET_KEY"])
    # ok: py-flask-debug-enabled
    flask_app.config["DEBUG"] = os.environ.get("FLASK_DEBUG") == "1"
    # ok: py-flask-debug-enabled
    flask_app.config.update(DEBUG=False)
    # ruleid: py-cookie-secure-disabled
    flask_app.config["SESSION_COOKIE_SECURE"] = False
    # ruleid: py-cookie-secure-disabled
    flask_app.config.update(SESSION_COOKIE_SECURE=False, SESSION_COOKIE_SAMESITE="Lax")
    # ok: py-cookie-secure-disabled
    flask_app.config["SESSION_COOKIE_SECURE"] = True
    # ruleid: py-cookie-httponly-disabled
    flask_app.config["SESSION_COOKIE_HTTPONLY"] = False
    # ruleid: py-cookie-httponly-disabled
    flask_app.config.update(SESSION_COOKIE_HTTPONLY=False)
    # ok: py-cookie-httponly-disabled
    flask_app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax")
    # ruleid: py-csrf-protection-disabled
    flask_app.config["WTF_CSRF_ENABLED"] = False
    return flask_app


def make_test_app():
    test_app = create_app()
    # ok: py-csrf-protection-disabled
    test_app.config.update(TESTING=True, WTF_CSRF_ENABLED=False)
    return test_app


def is_safe_url(target):
    ref_url = urlparse(request.host_url)
    test_url = urlparse(urljoin(request.host_url, target))
    return test_url.scheme in ("http", "https") and ref_url.netloc == test_url.netloc


# ---------------------------------------------------------------------------
# Flask: SSRF
# ---------------------------------------------------------------------------
@app.route("/fetch")
def fetch_preview():
    target = request.args.get("url")
    # ruleid: py-ssrf-tainted
    resp = requests.get(target, timeout=5)
    return jsonify(status=resp.status_code, length=len(resp.content))


@app.route("/webhooks/test", methods=["POST"])
def test_webhook():
    payload = request.get_json()
    # ruleid: py-ssrf-tainted
    http_client.post(payload["callback_url"], json={"ping": True}, timeout=3)
    return "", 204


@app.route("/avatar/import", methods=["POST"])
def import_avatar():
    # ruleid: py-ssrf-tainted
    with urllib.request.urlopen(request.form["avatar_url"]) as fh:
        data = fh.read()
    return jsonify(size=len(data))


@app.route("/proxy/<path:upstream>")
def proxy(upstream):
    # ruleid: py-ssrf-tainted, py-ssrf-dynamic-url
    r = httpx.get(f"http://{upstream}/status", timeout=2)
    return jsonify(code=r.status_code)


@app.route("/feeds/import", methods=["POST"])
def import_feed():
    feed_url = request.form["feed"]
    session = requests.Session()
    session.headers["User-Agent"] = "shop-importer/1.0"
    # ruleid: py-ssrf-tainted
    feed = session.get(feed_url, timeout=10)
    pool = urllib3.PoolManager()
    # ruleid: py-ssrf-tainted
    pool.request("GET", feed_url)
    return jsonify(ok=feed.ok)


@app.route("/partner/proxy")
def partner_proxy():
    # ruleid: py-ssrf-tainted
    upstream = requests.get(urljoin(API_BASE, request.args["path"]), timeout=5)
    # ruleid: py-ssrf-tainted
    other = requests.get(API_BASE + request.args["path"], timeout=5)
    return jsonify(a=upstream.status_code, b=other.status_code)


@app.route("/hooks/check")
def check_hook():
    hook_url = request.args["hook_url"]
    if not hook_url.startswith("https://"):
        abort(400)
    # ruleid: py-ssrf-tainted
    requests.head(hook_url, timeout=3)
    return "", 204


@app.route("/weather")
def weather():
    city = request.args.get("city", "London")
    # ok: py-ssrf-tainted
    current = requests.get("https://api.weather.example.com/v1/current", params={"q": city}, timeout=5)
    # ok: py-ssrf-tainted
    forecast = requests.get(f"https://api.weather.example.com/v1/forecast/{city}", timeout=5)
    # ok: py-ssrf-tainted
    history = requests.get("https://api.weather.example.com/v1/history/%s" % city, timeout=5)
    # ok: py-ssrf-tainted
    alerts = requests.get(API_BASE + "/v1/alerts/" + city, timeout=5)
    # ok: py-ssrf-tainted
    radar = requests.get(f"{API_BASE}/v1/radar/{city}", timeout=5)
    return jsonify(current=current.json(), forecast=forecast.json(), history=history.json(), alerts=alerts.json(), radar=radar.json())


@app.route("/hooks/relay", methods=["POST"])
def relay_hook():
    hook_url = request.form["hook_url"]
    if urlparse(hook_url).hostname not in ALLOWED_WEBHOOK_HOSTS:
        abort(400)
    # ok: py-ssrf-tainted
    requests.post(hook_url, json=request.get_json(), timeout=5)
    return "", 202


@app.route("/hooks/relay2", methods=["POST"])
def relay_hook_v2():
    hook_url = request.form["hook_url"]
    host = urlparse(hook_url).hostname
    if host in ALLOWED_WEBHOOK_HOSTS:
        # ok: py-ssrf-tainted
        requests.post(hook_url, data=request.form["body"], timeout=5)
    return "", 202


@app.route("/users/lookup")
def user_lookup():
    # ok: py-ssrf-tainted
    r = requests.get(f"{current_app.config['USER_API']}/users/{request.args['id']}", timeout=5)
    return jsonify(r.json())


@app.route("/avatar/fetch")
def fetch_avatar_legacy():
    req = urllib.request.Request(request.args["src"], headers={"User-Agent": "shop"})
    # ruleid: py-ssrf-tainted
    with urllib.request.urlopen(req) as fh:
        return jsonify(size=len(fh.read()))


@app.route("/stock")
def stock_level():
    sku = request.args.get("sku", type=int)
    # ok: py-ssrf-tainted
    requests.get(sku)
    return "", 204


# ---------------------------------------------------------------------------
# Flask: path traversal
# ---------------------------------------------------------------------------
@app.route("/download")
def download():
    filename = request.args["file"]
    # ruleid: py-path-traversal-tainted
    return send_file(os.path.join(UPLOAD_DIR, filename))


@app.route("/reports/<name>")
def report(name):
    # ruleid: py-path-traversal-tainted, py-path-traversal-dynamic-path
    return (REPORT_DIR / name).read_text()


@app.route("/upload", methods=["POST"])
def upload():
    document = request.files["document"]
    # ruleid: py-path-traversal-tainted
    document.save(os.path.join(UPLOAD_DIR, document.filename))
    return "", 201


@app.route("/theme")
def theme_file():
    # ruleid: py-path-traversal-tainted
    return send_from_directory(request.args["theme"], "style.css")


@app.route("/export-naive")
def export_naive():
    name = request.args["name"]
    target = os.path.join(UPLOAD_DIR, name)
    # startswith() on a non-canonical path: "reports/../../etc/passwd" passes
    if not target.startswith(UPLOAD_DIR):
        abort(403)
    # ruleid: py-path-traversal-tainted
    return send_file(target)


@app.route("/uploads/delete", methods=["POST"])
def delete_upload():
    name = request.form["name"]
    # a ".." blacklist does not stop absolute paths such as "/etc/passwd"
    if ".." in name:
        abort(400)
    # ruleid: py-path-traversal-tainted
    os.remove(os.path.join(UPLOAD_DIR, name))
    return "", 204


@app.route("/templates/clone", methods=["POST"])
def clone_template():
    # ruleid: py-path-traversal-tainted
    shutil.copy("/srv/shop/templates/base.html", os.path.join(UPLOAD_DIR, request.form["dest"]))
    return "", 201


@app.route("/avatar", methods=["POST"])
def upload_avatar():
    avatar = request.files["avatar"]
    # ok: py-path-traversal-tainted
    avatar.save(os.path.join(UPLOAD_DIR, secure_filename(avatar.filename)))
    return "", 201


@app.route("/files")
def static_files():
    # ok: py-path-traversal-tainted
    return send_from_directory(UPLOAD_DIR, request.args["name"])


@app.route("/export")
def export():
    name = request.args["name"]
    target = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if not target.startswith(UPLOAD_DIR + os.sep):
        abort(403)
    # ok: py-path-traversal-tainted
    return send_file(target)


@app.route("/export/v2")
def export_v2():
    requested = (REPORT_DIR / request.args["name"]).resolve()
    if not requested.is_relative_to(REPORT_DIR):
        abort(403)
    # ok: py-path-traversal-tainted
    return requested.read_bytes()


@app.route("/attachments")
def attachment():
    joined = safe_join(UPLOAD_DIR, request.args["name"])
    if joined is None:
        abort(404)
    # ok: py-path-traversal-tainted
    return send_file(joined)


@app.route("/logs")
def read_log():
    # ok: py-path-traversal-tainted
    with open(os.path.join("/var/log/shop", os.path.basename(request.args["log"]))) as fh:
        lines = fh.readlines()
    return jsonify(lines=lines[-50:])


@app.route("/bundles", methods=["POST"])
def import_bundle():
    archive = zipfile.ZipFile(request.files["bundle"])
    # ok: py-path-traversal-tainted
    manifest = archive.open("manifest.json").read()
    # ok: py-path-traversal-tainted
    slug = request.form["slug"].replace(" ", "-")
    return jsonify(manifest=json.loads(manifest), slug=slug)


@app.route("/receipt", methods=["POST"])
def receipt():
    # ok: py-path-traversal-tainted
    return send_file(io.BytesIO(request.data), mimetype="application/pdf", download_name="receipt.pdf")


# ---------------------------------------------------------------------------
# Flask: open redirect
# ---------------------------------------------------------------------------
@app.route("/login", methods=["POST"])
def login():
    next_url = request.args.get("next", "/")
    # ruleid: py-open-redirect-tainted
    return redirect(next_url)


@app.route("/back")
def go_back():
    # ruleid: py-open-redirect-tainted
    return redirect(request.referrer or url_for("index"))


@app.route("/after-login")
def after_login():
    target = request.args.get("next", "")
    # "/" + "/evil.example" is the protocol-relative URL "//evil.example"
    # ruleid: py-open-redirect-tainted
    return redirect("/" + target)


@app.route("/lang")
def set_language():
    resp = make_response("", 302)
    # ruleid: py-open-redirect-tainted
    resp.headers["Location"] = request.args.get("return_to")
    return resp


@app.route("/profile/<username>")
def profile_redirect(username):
    # ok: py-open-redirect-tainted
    return redirect(f"/users/{username}")


@app.route("/checkout/done")
def checkout_done():
    # ok: py-open-redirect-tainted
    return redirect(url_for("orders.detail", order_id=request.args["order"]))


@app.route("/continue")
def continue_to():
    target = request.args.get("next")
    if not is_safe_url(target):
        return redirect(url_for("index"))
    # ok: py-open-redirect-tainted
    return redirect(target)


@app.route("/shop")
def shop_redirect():
    # ok: py-open-redirect-tainted
    return redirect("https://shop.example.com/catalog?q=" + request.args.get("q", ""))


@app.route("/members")
def members_only():
    # ok: py-open-redirect-tainted
    return redirect(url_for("auth.login") + "?page=" + request.args.get("page", "1"))


# ---------------------------------------------------------------------------
# Flask: server-side template injection
# ---------------------------------------------------------------------------
@app.route("/hello")
def hello():
    name = request.args.get("name", "guest")
    # ruleid: py-ssti-tainted, py-ssti-dynamic-template
    return render_template_string(f"<h1>Hello {name}!</h1>")


@app.route("/templates/preview", methods=["POST"])
def preview_template():
    body = request.form["template"]
    # ruleid: py-ssti-tainted
    tpl = jinja2.Template(body)
    return tpl.render(shop="Shop Inc.")


@app.route("/email/preview", methods=["POST"])
def email_preview():
    # ruleid: py-ssti-tainted
    tpl = strict_env.from_string(request.form["body"])
    return tpl.render(order_id=42)


@app.route("/greeting")
def greeting():
    # ok: py-ssti-tainted
    return render_template_string("<h1>Hello {{ name }}!</h1>", name=request.args.get("name"))


@app.route("/campaign/preview", methods=["POST"])
def campaign_preview():
    # ok: py-ssti-tainted
    tpl = sandbox_env.from_string(request.form["body"])
    return tpl.render(customer="Ada")


@app.route("/motd")
def motd():
    # ok: py-ssti-tainted
    text = string.Template(request.args["greeting"]).safe_substitute(user="guest")
    return jsonify(text=text)


# ---------------------------------------------------------------------------
# Flask: XSS
# ---------------------------------------------------------------------------
@app.route("/search")
def search():
    q = request.args.get("q", "")
    # ruleid: py-xss-tainted
    return f"<h2>Results for {q}</h2>"


@app.route("/error")
def error_page():
    msg = request.args.get("msg", "")
    # ruleid: py-xss-tainted
    return make_response("<p>Error: %s</p>" % msg, 400)


@app.route("/comment", methods=["POST"])
def post_comment():
    # ruleid: py-xss-tainted, py-xss-dynamic-safe-markup
    html = Markup("<p>" + request.form["comment"] + "</p>")
    return render_template("comment.html", html=html)


@app.route("/banner")
def banner():
    # ruleid: py-xss-tainted
    return Response("<div>{}</div>".format(request.cookies.get("banner", "")))


@app.route("/search/safe")
def search_safe():
    q = request.args.get("q", "")
    # ok: py-xss-tainted
    return f"<h2>Results for {escape(q)}</h2>"


@app.route("/search/template")
def search_template():
    # ok: py-xss-tainted
    return render_template("search.html", q=request.args.get("q", ""))


@app.route("/api/search")
def search_api():
    # ok: py-xss-tainted
    return jsonify(query=request.args.get("q"), results=[])


@app.route("/api/echo")
def echo_api():
    # ok: py-xss-tainted
    return {"echo": request.args.get("msg")}


@app.route("/badge")
def badge():
    # ok: py-xss-tainted
    label = Markup("<span class='badge'>{}</span>").format(request.args["label"])
    return render_template("badge.html", label=label)


@app.route("/plain")
def plain():
    # ok: py-xss-tainted
    return Response(request.args.get("msg", ""), mimetype="text/plain")


@app.route("/api/filters")
def filters_api():
    data = {"q": request.args.get("q"), "sort": request.args.get("sort")}
    # ok: py-xss-tainted
    return data


@app.route("/hi")
def hi():
    # ruleid: py-xss-tainted
    return request.args["name"]


# ---------------------------------------------------------------------------
# Flask: XML
# ---------------------------------------------------------------------------
@app.route("/api/catalog/import", methods=["POST"])
def import_catalog():
    # ruleid: py-xxe-tainted
    doc = etree.fromstring(request.data)
    return jsonify(items=len(doc))


@app.route("/api/catalog/upload", methods=["POST"])
def upload_catalog():
    upload_file = request.files["catalog"]
    # ruleid: py-xxe-tainted
    tree = lxml_etree.parse(upload_file)
    return jsonify(root=tree.getroot().tag)


@app.route("/api/catalog/stream", methods=["POST"])
def stream_catalog():
    count = 0
    # ruleid: py-xxe-tainted
    for _event, _elem in etree.iterparse(request.files["catalog"].stream, events=("end",)):
        count += 1
    # ok: py-xxe-tainted
    for _event, _elem in etree.iterparse(request.stream, events=("end",), resolve_entities=False, no_network=True):
        count += 1
    return jsonify(count=count)


@app.route("/api/catalog/safe", methods=["POST"])
def import_catalog_safe():
    # ok: py-xxe-tainted
    doc = etree.fromstring(request.data, parser=hardened_parser)
    # ok: py-xxe-tainted
    other = SafeET.fromstring(request.data)
    # ok: py-xxe-tainted
    stdlib_doc = ElementTree.fromstring(request.data)
    return jsonify(a=len(doc), b=len(other), c=len(stdlib_doc))


def configure_sax():
    parser = xml.sax.make_parser()
    # ruleid: py-xxe-insecure-parser-config
    parser.setFeature(feature_external_ges, True)
    # ruleid: py-xxe-insecure-parser-config
    parser.setFeature("http://xml.org/sax/features/external-parameter-entities", True)
    # ok: py-xxe-insecure-parser-config
    parser.setFeature(feature_external_ges, False)
    return parser


# ---------------------------------------------------------------------------
# Flask: CSRF / CORS decorators
# ---------------------------------------------------------------------------
@app.route("/api/cart", methods=["POST"])
# ruleid: py-csrf-protection-disabled
@csrf.exempt
def cart_api():
    return jsonify(ok=True)


@app.route("/api/profile")
# ruleid: py-cors-wildcard-credentials
@cross_origin(supports_credentials=True)
def api_profile():
    return jsonify(user="me")


@app.route("/api/public")
# ok: py-cors-wildcard-credentials
@cross_origin(origins="*")
def api_public():
    return jsonify(status="up")


# ===========================================================================
# Django views
# ===========================================================================
def proxy_image(request):
    # ruleid: py-ssrf-tainted
    upstream = requests.get(request.GET["src"], stream=True, timeout=5)
    return HttpResponse(upstream.content, content_type=upstream.headers["Content-Type"])


class CallbackView(APIView):
    def post(self, request):
        # ruleid: py-ssrf-tainted
        requests.post(request.data["callback"], json={"status": "queued"}, timeout=5)
        return JsonResponse({"queued": True})


class PreviewView(View):
    def get(self, request):
        # ruleid: py-ssrf-tainted
        page = requests.get(self.request.GET["u"], timeout=5)
        return JsonResponse({"status": page.status_code})


def store_upload(request):
    upload_file = request.FILES["document"]
    # ok: py-path-traversal-tainted
    saved_name = default_storage.save(upload_file.name, upload_file)
    return JsonResponse({"name": saved_name})


def fetch_by_id(request, object_id):
    # ok: py-ssrf-tainted, py-ssrf-dynamic-url
    resp = requests.get(f"https://cdn.shop.example.com/objects/{object_id}.json", timeout=5)
    return HttpResponse(resp.content, content_type="application/json")


def media_download(request):
    media_path = os.path.join(settings.MEDIA_ROOT, request.GET["path"])
    # ruleid: py-path-traversal-tainted
    return FileResponse(open(media_path, "rb"))


def invoice_pdf(request, invoice_name):
    # ruleid: py-path-traversal-tainted, py-path-traversal-dynamic-path
    return FileResponse(open(f"{settings.MEDIA_ROOT}/invoices/{invoice_name}", "rb"))


def invoice_pdf_safe(request, invoice_name):
    # ok: py-path-traversal-tainted, py-path-traversal-dynamic-path
    return FileResponse(open(os.path.join(settings.MEDIA_ROOT, "invoices", os.path.basename(invoice_name)), "rb"))


def login_view(request):
    next_url = request.POST.get("next", "/")
    if not url_has_allowed_host_and_scheme(next_url, allowed_hosts={request.get_host()}, require_https=request.is_secure()):
        next_url = "/"
    # ok: py-open-redirect-tainted
    return django_redirect(next_url)


def logout_view(request):
    # ruleid: py-open-redirect-tainted
    return HttpResponseRedirect(request.GET.get("next", "/"))


def set_currency(request):
    target = request.META.get("HTTP_REFERER", "/")
    # ruleid: py-open-redirect-tainted
    response = django_redirect(target)
    response.set_cookie("currency", "EUR", secure=True, httponly=True)
    return response


def post_publish(request, pk):
    post = get_object_or_404(Post, pk=pk)
    # ok: py-open-redirect-tainted, py-open-redirect-dynamic-url
    return django_redirect(post)


def post_edit(request, pk):
    # ok: py-open-redirect-tainted, py-open-redirect-dynamic-url
    return django_redirect("blog:post_detail", pk=pk)


def post_detail_redirect(request, slug):
    # ok: py-open-redirect-tainted, py-open-redirect-dynamic-url
    return HttpResponseRedirect(reverse("blog:post_detail", args=[slug]))


def render_snippet(request):
    # ruleid: py-ssti-tainted, py-ssti-dynamic-template
    template = DjangoTemplate("<p>" + request.GET["snippet"] + "</p>")
    return HttpResponse(template.render(Context({})))


def mako_preview(request):
    # ruleid: py-ssti-tainted
    return HttpResponse(MakoTemplate(request.POST["tpl"]).render())


def search_view(request):
    q = request.GET.get("q", "")
    # ruleid: py-xss-tainted
    return HttpResponse(f"<h1>Results for {q}</h1>")


def bio_view(request):
    # ruleid: py-xss-tainted
    bio = mark_safe(request.POST["bio"])
    return render(request, "bio.html", {"bio": bio})


def signature_view(request):
    # ruleid: py-xss-tainted
    return HttpResponse(SafeString(request.GET["sig"]))


def search_view_safe(request):
    q = request.GET.get("q", "")
    # ok: py-xss-tainted
    return HttpResponse(format_html("<h1>Results for {}</h1>", q))


def search_json(request):
    # ok: py-xss-tainted
    return HttpResponse(json.dumps({"q": request.GET.get("q")}), content_type="application/json")


def page_view(request):
    # ok: py-xss-tainted
    return HttpResponse(dj_escape(request.GET.get("page", "")))


def soap_endpoint(request):
    # ruleid: py-xxe-tainted
    envelope = etree.fromstring(request.body, legacy_parser)
    # ruleid: py-xxe-tainted, py-xxe-insecure-parser-config
    header = etree.fromstring(request.body, parser=etree.XMLParser(resolve_entities=True))
    # ok: py-xxe-tainted
    safe_envelope = etree.fromstring(request.body, parser=hardened_parser)
    return HttpResponse(etree.tostring(safe_envelope), content_type="text/xml")


# ruleid: py-csrf-protection-disabled
@csrf_exempt
def update_profile(request):
    request.user.email = request.POST["email"]
    request.user.save()
    return HttpResponse(status=204)


# ok: py-csrf-protection-disabled
@csrf_protect
def change_email(request):
    request.user.email = request.POST["email"]
    request.user.save()
    return HttpResponse(status=204)


# ruleid: py-csrf-protection-disabled
@method_decorator(csrf_exempt, name="dispatch")
class OrderApiView(View):
    def post(self, request):
        return HttpResponse(status=201)


# Webhook authenticated with an HMAC signature on every request.
# ok: py-csrf-protection-disabled
@csrf_exempt
def payment_webhook(request):
    signature = request.headers.get("X-Signature", "")
    expected = hmac.new(WEBHOOK_SECRET, request.body, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        return HttpResponse(status=403)
    return HttpResponse(status=200)


def legacy_checkout(request):
    return HttpResponse(status=204)


urlpatterns = [
    # ruleid: py-csrf-protection-disabled
    path("legacy/checkout/", csrf_exempt(legacy_checkout)),
    # ok: py-csrf-protection-disabled
    path("checkout/", legacy_checkout),
]


# ===========================================================================
# FastAPI / Starlette
# ===========================================================================
api = FastAPI()

# ruleid: py-cors-wildcard-credentials
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"])

# ok: py-cors-wildcard-credentials
api.add_middleware(CORSMiddleware, allow_origins=["https://shop.example.com"], allow_credentials=True)

# ok: py-cors-wildcard-credentials
api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"])

# ruleid: py-cors-wildcard-credentials
starlette_middleware = [Middleware(StarletteCORS, allow_origins=["*"], allow_credentials=True)]


@api.get("/unfurl")
async def unfurl(link: str):
    async with aiohttp.ClientSession() as http:
        # ruleid: py-ssrf-tainted, py-ssrf-dynamic-url
        async with http.get(link) as resp:
            return {"status": resp.status}


@api.get("/inventory/{item_id}")
async def inventory(item_id: int):
    async with httpx.AsyncClient() as client:
        # ok: py-ssrf-tainted, py-ssrf-dynamic-url
        r = await client.get(f"{API_BASE}/items/{item_id}")
    return r.json()


@api.get("/oauth/callback")
async def oauth_callback(code: str, state: str):
    # ruleid: py-open-redirect-tainted, py-open-redirect-dynamic-url
    return RedirectResponse(url=state)


@api.get("/welcome", response_class=HTMLResponse)
async def welcome(name: str):
    # ruleid: py-xss-tainted
    return HTMLResponse(f"<h1>Welcome {name}</h1>")


@api.get("/count", response_class=HTMLResponse)
async def count_items(n: int):
    # ok: py-xss-tainted
    return HTMLResponse(f"<p>{n} items</p>")


# ===========================================================================
# Helpers: source unknown (function parameters / runtime-built strings)
# ===========================================================================
def send_webhook(url, payload):
    # ruleid: py-ssrf-dynamic-url
    return requests.post(url, json=payload, timeout=5)


def tenant_health(tenant_host):
    # ruleid: py-ssrf-dynamic-url
    return httpx.get(f"https://{tenant_host}/healthz", timeout=2)


def download_asset(base_url, name):
    # ruleid: py-ssrf-dynamic-url
    return urllib.request.urlopen(base_url + "/assets/" + name)


def get_order(order_id):
    # ok: py-ssrf-dynamic-url
    return requests.get(f"https://api.partner.example.com/orders/{order_id}", timeout=5)


class PartnerClient:
    def __init__(self, base_url, token):
        self.base_url = base_url
        self.http = requests.Session()
        self.http.headers["Authorization"] = f"Bearer {token}"

    def get_invoice(self, invoice_id):
        # ok: py-ssrf-dynamic-url
        return self.http.get(f"{self.base_url}/invoices/{invoice_id}")

    def list_invoices(self, page):
        # ok: py-ssrf-dynamic-url
        return requests.get(self.base_url + "/invoices", params={"page": page}, timeout=5)


def load_template_file(template_dir, name):
    # ruleid: py-path-traversal-dynamic-path
    with open(os.path.join(template_dir, name)) as fh:
        return fh.read()


def write_export(user_dir, export_name, data):
    target = Path(user_dir) / export_name
    # ruleid: py-path-traversal-dynamic-path
    target.write_text(data)


def remove_cache_entry(key):
    # ruleid: py-path-traversal-dynamic-path
    os.unlink("/var/cache/shop/" + key)


def read_config(config_path):
    # ok: py-path-traversal-dynamic-path
    with open(config_path) as fh:
        return fh.read()


def backup_file(file_path):
    # ok: py-path-traversal-dynamic-path
    shutil.copy(file_path, f"{file_path}.bak")


def load_upload(name):
    # ok: py-path-traversal-dynamic-path
    with open(os.path.join(UPLOAD_DIR, secure_filename(name))) as fh:
        return fh.read()


def load_contained(name):
    full = os.path.realpath(os.path.join(UPLOAD_DIR, name))
    if os.path.commonpath([full, UPLOAD_DIR]) != UPLOAD_DIR:
        raise PermissionError(name)
    # ok: py-path-traversal-dynamic-path
    return open(full).read()


def redirect_back(fallback, next_page):
    # ruleid: py-open-redirect-dynamic-url
    return redirect(next_page or fallback)


def finish_signup(return_to):
    # ruleid: py-open-redirect-dynamic-url
    return HttpResponseRedirect(return_to)


def go_external(domain):
    # ruleid: py-open-redirect-dynamic-url
    return redirect(f"https://{domain}/welcome")


def go_home(section):
    # ok: py-open-redirect-dynamic-url
    return redirect(url_for("home", section=section))


def go_order(order_id):
    # ok: py-open-redirect-dynamic-url
    return redirect(f"/orders/{order_id}")


def go_checked(target):
    safe_target = target if url_has_allowed_host_and_scheme(target, allowed_hosts={"shop.example.com"}) else "/"
    # ok: py-open-redirect-dynamic-url
    return redirect(safe_target)


def render_banner(title):
    # ruleid: py-ssti-dynamic-template
    return render_template_string("<div class='banner'>" + title + "</div>")


def welcome_email(user):
    body = f"Hi {user.first_name}, your order {{{{ order_id }}}} has shipped."
    # ruleid: py-ssti-dynamic-template
    return mail_env.from_string(body).render(order_id=user.last_order_id)


def product_blurb(product):
    # ruleid: py-ssti-dynamic-template
    return jinja2.Template("<p>%s</p>" % product.description).render()


def order_summary(order):
    # ok: py-ssti-dynamic-template
    return render_template_string("<p>Order {{ order.id }} total {{ order.total }}</p>", order=order)


def footer_html(year):
    # ok: py-ssti-dynamic-template
    return jinja_env.from_string(FOOTER_TEMPLATE + "<p>{{ year }}</p>").render(year=year)


def load_report_template(report_name):
    with open(os.path.join("/srv/shop/report-templates", secure_filename(report_name))) as fh:
        source = fh.read()
    # ok: py-ssti-dynamic-template
    return report_env.from_string(source)


def render_comment(comment):
    # ruleid: py-xss-dynamic-safe-markup
    return mark_safe(f"<p class='comment'>{comment.body}</p>")


def user_link(user):
    # ruleid: py-xss-dynamic-safe-markup
    return Markup('<a href="/u/%s">%s</a>' % (user.id, user.display_name))


def status_badge(status):
    html = "<span class='status'>" + status + "</span>"
    # ruleid: py-xss-dynamic-safe-markup
    return SafeString(html)


def order_row(order):
    # ruleid: py-xss-dynamic-safe-markup
    return markupsafe.Markup("<td>{}</td><td>{}</td>".format(order.number, order.customer_note))


def safe_comment(comment):
    # ok: py-xss-dynamic-safe-markup
    return mark_safe(f"<p class='comment'>{dj_escape(comment.body)}</p>")


def safe_link(user):
    # ok: py-xss-dynamic-safe-markup
    return format_html('<a href="/u/{}">{}</a>', user.id, user.display_name)


def safe_badge(status):
    label = markupsafe.escape(status)
    # ok: py-xss-dynamic-safe-markup
    return Markup(f"<span class='status'>{label}</span>")


def static_icon():
    # ok: py-xss-dynamic-safe-markup
    return mark_safe(f"<i class='{ICON_CLASS}'></i>")


def markup_format(user):
    # ok: py-xss-dynamic-safe-markup
    return Markup("<b>{}</b>").format(user.display_name)


# ===========================================================================
# Development servers
# ===========================================================================
def run_dev_server():
    dev_app = Flask("dev")
    # ruleid: py-flask-debug-enabled
    dev_app.debug = True
    # ruleid: py-debug-server-public-bind
    dev_app.run(host="0.0.0.0", port=5000)


def run_local_server():
    local_app = Flask("local")
    # ok: py-flask-debug-enabled, py-debug-server-public-bind
    local_app.run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    # ruleid: py-flask-debug-enabled
    app.run(debug=True)
    # ruleid: py-flask-debug-enabled
    app.run(host="127.0.0.1", port=5000, debug=True)
    # ok: py-flask-debug-enabled
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
    # ok: py-debug-server-public-bind
    app.run(host="0.0.0.0", port=8080, debug=False)
    # ruleid: py-debug-server-public-bind
    app.run(host="0.0.0.0", port=8080, debug=True)
    # ruleid: py-debug-server-public-bind
    app.run("::", 5000, debug=True)
    # ruleid: py-debug-server-public-bind
    app.run(host=os.environ.get("HOST", "0.0.0.0"), debug=True)
    # ruleid: py-debug-server-public-bind
    run_simple("0.0.0.0", 5000, app, use_debugger=True, use_reloader=True)
    # ruleid: py-flask-debug-enabled
    run_simple("localhost", 5000, app, use_debugger=True)
    # ok: py-debug-server-public-bind
    run_simple("0.0.0.0", 5000, app, use_reloader=True)
    # ok: py-flask-debug-enabled
    asyncio.run(warm_caches(), debug=True)

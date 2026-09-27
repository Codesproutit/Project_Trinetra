# Test fixture for trinetra/brains/static/rules/python/injection.yaml.
#
# Deliberately vulnerable snippets for rule tests. Every "ruleid:" line is a flaw the
# rules must report; every "ok:" line is a safe lookalike they must stay quiet on.
# Nothing here is meant to run.

import argparse
import ast
import asyncio
import builtins
import html
import importlib
import json
import os
import pty
import re
import runpy
import shlex
import sqlite3
import subprocess as sp
import sys
import textwrap
from os import popen, system as run_shell
from subprocess import Popen, check_output

import ldap
import ldap3
import mysql.connector
import pandas as pd
import psycopg2
import pymysql
from django.db import connection
from django.db.models.expressions import RawSQL
from django.http import HttpResponse, JsonResponse
from fastapi import Depends, FastAPI, Query, Request
from flask import Blueprint, Flask, abort, jsonify
from flask import request
from flask import request as flask_req
from ldap.filter import escape_filter_chars, filter_format
from ldap3 import SUBTREE
from ldap3.utils.conv import escape_filter_chars as ldap3_escape
from psycopg2 import sql
from sqlalchemy import create_engine, insert, select, text, update
from sqlalchemy.orm import Session

app = Flask(__name__)
bp = Blueprint("admin", __name__)
api = FastAPI()
engine = create_engine("postgresql://app@localhost/app")

USERS_TABLE = "users"
SORT_COLUMNS = {"name": "u.name", "created": "u.created_at"}
ALLOWED_PLUGINS = {"csv", "xlsx"}
REPORT_TOOLS = {"df": "/bin/df", "uptime": "/usr/bin/uptime"}
BACKUP_DIR = "/var/backups/app"
BASE_DN = "ou=people,dc=example,dc=com"


def get_db():
    return sqlite3.connect("app.db")


# ===========================================================================
# SQL injection: HTTP input (py-sqli-tainted)
# ===========================================================================


@app.route("/users/search")
def search_users():
    username = request.args.get("username")
    conn = get_db()
    cur = conn.cursor()
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    cur.execute(f"SELECT id, email FROM users WHERE username = '{username}'")
    rows = cur.fetchall()

    # ok: py-sqli-tainted, py-sqli-dynamic-query
    cur.execute("SELECT id, email FROM users WHERE username = ?", (username,))
    return jsonify(rows)


@app.route("/users/by-email", methods=["POST"])
def user_by_email():
    pg = psycopg2.connect("dbname=app")
    with pg.cursor() as cur:
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        cur.execute("SELECT * FROM users WHERE email = '%s'" % request.form["email"])

        # %s placeholders with a separate parameter tuple are bound by the driver.
        # ok: py-sqli-tainted, py-sqli-dynamic-query
        cur.execute("SELECT * FROM users WHERE email = %s", (request.form["email"],))
        return jsonify(cur.fetchone())


@app.route("/orders")
def list_orders():
    db = pymysql.connect(host="db", user="app", database="shop")
    status = request.values.get("status", "open")
    query = "SELECT * FROM orders WHERE status = '{}' ORDER BY id".format(status)
    with db.cursor() as cur:
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        cur.execute(query)

        # Driver escaping of a quoted literal.
        safe_status = db.escape_string(status)
        # ok: py-sqli-tainted, py-sqli-dynamic-query
        cur.execute("SELECT * FROM orders WHERE status = '" + safe_status + "'")
        return jsonify(cur.fetchall())


@app.route("/sessions")
def session_lookup():
    cnx = mysql.connector.connect(user="app", database="app")
    cursor = cnx.cursor()
    token = request.cookies.get("session_token")
    sql_text = "SELECT user_id FROM sessions WHERE token = '" + token + "'"
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    cursor.execute(sql_text)

    # ok: py-sqli-tainted, py-sqli-dynamic-query
    cursor.execute("SELECT user_id FROM sessions WHERE token = %(token)s", {"token": token})
    return jsonify(cursor.fetchone())


@app.route("/admin/import", methods=["POST"])
def import_sql():
    conn = get_db()
    # Whole statements taken from the request body; no string building involved.
    # ruleid: py-sqli-tainted
    conn.executescript(request.get_data(as_text=True))
    rows = request.get_json()["rows"]
    # ruleid: py-sqli-tainted
    conn.executemany(rows[0]["statement"], [])
    return "", 204


@app.route("/products")
def products():
    conn = get_db()
    limit = request.args.get("limit", 20, type=int)
    # Typed getter: werkzeug converts to int or falls back to the default.
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM products LIMIT {limit}")

    # ok: py-sqli-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM products OFFSET {int(request.args['offset'])}")

    # Column names cannot be bound, so they are mapped through a constant allowlist.
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM products ORDER BY {SORT_COLUMNS[request.args['sort']]}")

    order_col = SORT_COLUMNS.get(request.args.get("sort"), "u.name")
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    conn.execute("SELECT * FROM products ORDER BY " + order_col)

    direction = request.args.get("dir", "asc")
    if direction not in ("asc", "desc"):
        abort(400)
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM products ORDER BY price {direction}")

    category = request.args.get("category", "")
    if category not in ("books", "music"):
        app.logger.warning("unexpected category %s", category)
    # The check above only logs, so the value is still attacker controlled.
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM products WHERE category = '{category}'")
    return "ok"


@app.route("/page")
def paged():
    page = request.args.get("page", "1")
    conn = get_db()
    if page.isdigit():
        # ok: py-sqli-tainted, py-sqli-dynamic-query
        conn.execute(f"SELECT * FROM posts LIMIT 20 OFFSET {page}")
    # HTML escaping is not SQL escaping: numeric contexts need no quote at all.
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM posts WHERE id = {html.escape(request.args['id'])}")
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    total = int(conn.execute("SELECT count(*) FROM posts WHERE author = '" + request.args["author"] + "'").fetchone()[0])
    return str(total)


@app.route("/aliased")
def aliased_request():
    term = flask_req.args["q"]
    clauses = []
    clauses.append(f"title LIKE '%{term}%'")
    where = " AND ".join(clauses)
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    get_db().execute("SELECT * FROM posts WHERE " + where)

    # A LIKE pattern built in Python but passed as a bound parameter.
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    get_db().execute("SELECT * FROM posts WHERE title LIKE ?", (f"%{term}%",))
    return "ok"


@app.route("/report")
def report():
    region = request.args["region"]
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    df = pd.read_sql(f"SELECT * FROM sales WHERE region = '{region}'", engine)
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    df = pd.read_sql("SELECT * FROM sales WHERE region = %(r)s", engine, params={"r": region})
    return df.to_json()


@app.route("/graphql", methods=["POST"])
def graphql_endpoint():
    # GraphQL schemas have an execute() method too; this is not SQL.
    # ok: py-sqli-tainted
    result = schema.execute(request.json["query"])
    return jsonify(result.data)


# --- SQLAlchemy -------------------------------------------------------------


@bp.route("/accounts")
def accounts():
    with Session(engine) as session:
        sort = request.args.get("sort", "id")
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        rows = session.execute(text(f"SELECT * FROM accounts ORDER BY {sort}"))

        # ok: py-sqli-tainted, py-sqli-dynamic-query
        rows = session.execute(text("SELECT * FROM accounts WHERE owner = :owner"), {"owner": request.args["owner"]})

        # SQLAlchemy Core statements bind every value as a parameter.
        stmt = select(Account).where(Account.owner == request.args["owner"]).order_by(Account.id)
        # ok: py-sqli-tainted
        rows = session.execute(stmt)

        # ok: py-sqli-tainted
        session.execute(update(Account).where(Account.id == request.form["id"]).values(name=request.form["name"]))

        # ok: py-sqli-tainted
        session.execute(insert(Account).values(owner=request.form["owner"]))

        # Statements refined step by step keep binding their values.
        query = select(Account)
        if request.args.get("owner"):
            query = query.where(Account.owner == request.args["owner"])
        # ok: py-sqli-tainted
        rows = session.execute(query)

        # Textual SQL inside an ORM statement is still raw SQL.
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        session.execute(select(Account).where(text(f"owner = '{request.args['owner']}'")))
        return jsonify([dict(r) for r in rows])


# --- Django -----------------------------------------------------------------


def django_search(request):
    q = request.GET.get("q", "")
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    people = Person.objects.raw(f"SELECT * FROM app_person WHERE last_name = '{q}'")

    # ok: py-sqli-tainted, py-sqli-dynamic-query
    people = Person.objects.raw("SELECT * FROM app_person WHERE last_name = %s", [q])

    # The ORM parameterizes filter() values.
    # ok: py-sqli-tainted
    people = Person.objects.filter(last_name=q)
    return HttpResponse(people)


def django_cursor(request):
    name = request.POST["name"]
    with connection.cursor() as cursor:
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        cursor.execute("UPDATE app_person SET nickname = '" + name + "' WHERE id = 1")
        # ok: py-sqli-tainted, py-sqli-dynamic-query
        cursor.execute("UPDATE app_person SET nickname = %s WHERE id = %s", [name, 1])
    return HttpResponse(status=204)


def django_extra(request):
    city = request.GET["city"]
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    qs = Person.objects.extra(where=[f"city = '{city}'"])
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    qs = Person.objects.extra(where=["city = %s"], params=[city])
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    qs = Person.objects.annotate(score=RawSQL("SELECT rank FROM ranks WHERE city = '%s'" % city, ()))
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    qs = Person.objects.annotate(score=RawSQL("SELECT rank FROM ranks WHERE city = %s", (city,)))
    # Identifier quoted by the database backend.
    # ok: py-sqli-tainted
    qs = Person.objects.raw("SELECT * FROM app_person ORDER BY " + connection.ops.quote_name(request.GET["col"]))
    return JsonResponse(list(qs.values()), safe=False)


def run_raw(sql_text):
    with connection.cursor() as cursor:
        # Known limit: taint does not follow calls into helper functions
        # (Semgrep OSS analyses one function at a time).
        # todoruleid: py-sqli-tainted
        cursor.execute(sql_text)


def owner_report(request):
    return run_raw("SELECT * FROM reports WHERE owner = '%s'" % request.GET["owner"])


def article_detail(request, slug):
    # Known limit: Django URLconf captures (slug) are not modelled as request input;
    # the structural rule still reports the formatted query.
    with connection.cursor() as cursor:
        # todoruleid: py-sqli-tainted
        # ruleid: py-sqli-dynamic-query
        cursor.execute(f"SELECT * FROM blog_article WHERE slug = '{slug}'")
    return HttpResponse()


@app.route("/invoices/<int:invoice_id>")
def invoice(invoice_id):
    # Known false positive: Flask's <int:...> converter already rejected
    # non-digits, but the rules cannot read the converter from the route string.
    # todook: py-sqli-tainted, py-sqli-dynamic-query
    get_db().execute(f"SELECT * FROM invoices WHERE id = {invoice_id}")
    return "ok"


class PersonSearchAPIView:
    """Django REST framework view."""

    def get(self, request):
        term = request.query_params.get("term", "")
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        rows = Person.objects.raw("SELECT * FROM app_person WHERE name LIKE '%%" + term + "%%'")
        # ok: py-sqli-tainted, py-sqli-dynamic-query
        rows = Person.objects.raw("SELECT * FROM app_person WHERE name LIKE %s", [f"%{term}%"])
        return JsonResponse([p.pk for p in rows], safe=False)


class PersonExportView:
    def get(self, request):
        fmt = self.request.GET.get("fields", "id")
        with connection.cursor() as cursor:
            # ruleid: py-sqli-tainted, py-sqli-dynamic-query
            cursor.execute("SELECT %s FROM app_person" % fmt)
        return HttpResponse()


# --- FastAPI / Starlette ------------------------------------------------------


@api.get("/items/{item_id}")
async def read_item(item_id: int, q: str = Query(None), db: Session = Depends(get_db)):
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    db.execute(text(f"SELECT * FROM items WHERE id = {item_id}"))
    # ruleid: py-sqli-tainted, py-sqli-dynamic-query
    db.execute(text(f"SELECT * FROM items WHERE name LIKE '%{q}%'"))
    # ok: py-sqli-tainted, py-sqli-dynamic-query
    db.execute(text("SELECT * FROM items WHERE name LIKE :q"), {"q": f"%{q}%"})
    return {}


@api.get("/tags/{slug}")
async def tag_page(request: Request):
    slug = request.path_params["slug"]
    with engine.connect() as conn:
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        conn.execute(text("SELECT * FROM tags WHERE slug = '%s'" % slug))
        # ok: py-sqli-tainted, py-sqli-dynamic-query
        conn.execute(text("SELECT * FROM tags WHERE slug = :slug"), {"slug": slug})
    return {}


@api.post("/raw")
async def raw_query(request: Request):
    payload = await request.json()
    params = request.query_params
    with engine.connect() as conn:
        # ruleid: py-sqli-tainted
        conn.execute(text(payload["sql"]))
        # ruleid: py-sqli-tainted, py-sqli-dynamic-query
        conn.execute(text("DELETE FROM carts WHERE owner = '%s'" % params["owner"]))
        # ok: py-sqli-tainted, py-sqli-dynamic-query
        conn.execute(text("DELETE FROM carts WHERE owner = :o"), {"o": params["owner"]})
    return {}


# ===========================================================================
# SQL injection: unknown source (py-sqli-dynamic-query)
# ===========================================================================


def get_user(cursor, user_id):
    # ruleid: py-sqli-dynamic-query
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()


def delete_rows(cursor, table, ids):
    # ruleid: py-sqli-dynamic-query
    cursor.execute("DELETE FROM %s WHERE id IN (%s)" % (table, ",".join(ids)))

    # Placeholder list: only "?" characters are interpolated.
    placeholders = ", ".join(["?"] * len(ids))
    # ok: py-sqli-dynamic-query
    cursor.execute(f"DELETE FROM users WHERE id IN ({placeholders})", ids)

    # ok: py-sqli-dynamic-query
    cursor.execute(f"DELETE FROM users WHERE id IN ({','.join('?' * len(ids))})", ids)


def find_customers(cursor, name=None, city=None, order="name"):
    # Built from constant fragments only; values are bound.
    sql_query = "SELECT * FROM customers WHERE 1 = 1"
    args = []
    if name:
        sql_query += " AND name = %s"
        args.append(name)
    if city:
        sql_query += " AND city = %s"
        args.append(city)
    # ok: py-sqli-dynamic-query
    cursor.execute(sql_query, args)

    listing = "SELECT * FROM customers ORDER BY "
    listing += order
    # ruleid: py-sqli-dynamic-query
    cursor.execute(listing)

    report_sql = """
        SELECT c.id, sum(o.total)
        FROM customers c JOIN orders o ON o.customer_id = c.id
        WHERE c.city = '{city}'
        GROUP BY c.id
    """.format(city=city)
    # ruleid: py-sqli-dynamic-query
    cursor.execute(report_sql)


def count_rows(cursor, table_name, limit):
    # ALL_CAPS module constants are not user input.
    # ok: py-sqli-dynamic-query
    cursor.execute(f"SELECT count(*) FROM {USERS_TABLE}")

    # ok: py-sqli-dynamic-query
    cursor.execute("SELECT * FROM " + USERS_TABLE + " LIMIT %s", (limit,))

    # ok: py-sqli-dynamic-query
    cursor.execute("SELECT * FROM users LIMIT %d" % int(limit))

    # psycopg2.sql composes identifiers safely.
    # ok: py-sqli-dynamic-query
    cursor.execute(sql.SQL("SELECT count(*) FROM {}").format(sql.Identifier(table_name)))

    # ruleid: py-sqli-dynamic-query
    cursor.execute("SELECT count(*) FROM " + table_name)

    # sql.SQL() does not help when its template is itself formatted.
    # ruleid: py-sqli-dynamic-query
    cursor.execute(sql.SQL(f"SELECT count(*) FROM {table_name}"))


def purge_table(cursor, table, days):
    if not re.fullmatch(r"[a-z_][a-z0-9_]*", table):
        raise ValueError("bad table name")
    if not days.isdigit():
        return None
    # ok: py-sqli-dynamic-query
    cursor.execute(f"DELETE FROM {table} WHERE created < now() - interval '{days} days'")


def archive_user(session, model, username):
    # Django model metadata is defined in code.
    # ok: py-sqli-dynamic-query
    session.execute(f"DELETE FROM {model._meta.db_table} WHERE username = %s", [username])
    # ruleid: py-sqli-dynamic-query
    session.execute(text("UPDATE users SET archived = true WHERE username = '" + username + "'"))
    # A formatted log line never reaches the database.
    # ok: py-sqli-dynamic-query
    log_line = f"archiving {username}"
    session.execute(text("INSERT INTO audit (line) VALUES (:line)"), {"line": log_line})


def raw_django_lookup(slug):
    # ruleid: py-sqli-dynamic-query
    return Article.objects.raw("SELECT * FROM blog_article WHERE slug = '{}'".format(slug))


def lookup_by_filter(cur, filters):
    parts = []
    for column, value in filters.items():
        parts.append(f"{column} = '{value}'")
    # ruleid: py-sqli-dynamic-query
    cur.execute("SELECT * FROM t WHERE " + " AND ".join(parts))


def sort_listing(cur, sort_key):
    # The value comes from a constant allowlist map.
    column = SORT_COLUMNS[sort_key]
    # ok: py-sqli-dynamic-query
    cur.execute(f"SELECT * FROM users ORDER BY {column}")


# ===========================================================================
# SQL injection: command-line input (py-sqli-local-tainted)
# ===========================================================================


def cli_sql_main():
    conn = sqlite3.connect(sys.argv[1])
    # ruleid: py-sqli-local-tainted, py-sqli-dynamic-query
    conn.execute("DELETE FROM users WHERE name = '%s'" % sys.argv[2])
    # ok: py-sqli-local-tainted, py-sqli-dynamic-query
    conn.execute("DELETE FROM users WHERE name = ?", (sys.argv[2],))

    name = input("Customer name: ")
    # ruleid: py-sqli-local-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM customers WHERE name = '{name}'")
    # ok: py-sqli-local-tainted, py-sqli-dynamic-query
    conn.execute("SELECT * FROM customers WHERE name = ?", [name])

    parser = argparse.ArgumentParser()
    parser.add_argument("--query")
    parser.add_argument("--limit")
    args = parser.parse_args()
    # ruleid: py-sqli-local-tainted
    conn.execute(args.query)
    # ok: py-sqli-local-tainted, py-sqli-dynamic-query
    conn.execute(f"SELECT * FROM customers LIMIT {int(args.limit)}")
    # A migration runner executing the SQL file it was given.
    # ok: py-sqli-local-tainted
    conn.executescript(open(sys.argv[3]).read())


# ===========================================================================
# OS command injection: HTTP input (py-command-injection-tainted)
# ===========================================================================


@app.route("/net/ping")
def ping():
    host = request.args.get("host", "")
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    os.system("ping -c 1 " + host)

    # Argument list, no shell: the host is a single argv entry.
    # ok: py-command-injection-tainted, py-command-injection-dynamic-shell
    sp.run(["ping", "-c", "1", host], check=True, timeout=5)

    # ok: py-command-injection-tainted, py-command-injection-dynamic-shell
    sp.run(f"ping -c 1 {shlex.quote(host)}", shell=True, check=True)
    return "ok"


@app.route("/net/lookup", methods=["POST"])
def lookup():
    domain = request.form["domain"]
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    out = sp.run(f"nslookup {domain}", shell=True, capture_output=True, text=True)
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    whois = sp.getoutput("whois %s" % domain)
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    listing = popen("dig +short {}".format(domain)).read()
    return out.stdout + whois + listing


@app.route("/tools/run", methods=["POST"])
def run_tool():
    body = request.get_json()
    # ruleid: py-command-injection-tainted
    check_output(body["command"], shell=True)

    # The program itself is chosen by the client.
    # ruleid: py-command-injection-tainted
    Popen([body["tool"], "--version"])

    # ruleid: py-command-injection-tainted
    sp.run(shlex.split(body["cmdline"]))

    # An explicit shell with -c parses the whole string.
    # ruleid: py-command-injection-tainted
    sp.run(["bash", "-c", body["script"]])

    # ruleid: py-command-injection-tainted
    os.execvp(body["tool"], [body["tool"], "-h"])

    # Program looked up in a constant allowlist.
    # ok: py-command-injection-tainted
    sp.run([REPORT_TOOLS[body["tool"]], "--version"], check=True)

    # Fixed program, user value as an argument vector entry.
    cmd = ["git", "log", "--oneline", "--", body["path"]]
    # ok: py-command-injection-tainted
    sp.run(cmd, check=True)

    # ok: py-command-injection-tainted
    sp.run(["ls", "-l", "--"] + body["paths"], check=True)

    pip_cmd = [sys.executable, "-m", "pip", "download", "--no-deps", body["package"]]
    # ok: py-command-injection-tainted
    sp.run(pip_cmd, check=True)

    git_base = ["git", "-C", "/srv/repo"]
    checkout = git_base + ["checkout", "--", body["branch"]]
    # ok: py-command-injection-tainted
    sp.run(checkout, check=True)

    # A script argument is not parsed by the shell (no -c).
    # ok: py-command-injection-tainted
    sp.run(["bash", "/opt/app/cleanup.sh", body["path"]], check=True)

    # With shell=True only the first list item is a command; the rest become $0, $1.
    # ok: py-command-injection-tainted
    sp.run(["ls -l", body["path"]], shell=True)

    # ok: py-command-injection-tainted, py-command-injection-dynamic-shell
    run_shell(f"sleep {int(body['seconds'])}")
    return "ok"


@app.route("/convert/<filename>")
def convert(filename):
    # Flask route parameters come from the URL path.
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    run_shell("convert /srv/uploads/%s /srv/thumbs/%s.png" % (filename, filename))

    mode = request.args.get("mode", "fast")
    if mode not in ("fast", "best"):
        abort(400)
    # ok: py-command-injection-tainted, py-command-injection-dynamic-shell
    run_shell(f"optimize --{mode} /srv/thumbs/out.png")
    return "ok"


def django_disk_usage(request):
    directory = request.GET.get("dir", "/srv")
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    usage = sp.check_output("du -sh %s" % directory, shell=True)
    # ok: py-command-injection-tainted, py-command-injection-dynamic-shell
    usage = sp.check_output(["du", "-sh", directory])
    # ok: py-command-injection-tainted, py-command-injection-dynamic-shell
    usage = sp.check_output("du -sh /srv", shell=True)
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    size = int(sp.check_output("du -s " + request.GET["dir"] + " | cut -f1", shell=True))
    return HttpResponse(usage)


@api.post("/thumbnail")
async def thumbnail(path: str, width: int = 128):
    # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
    proc = await asyncio.create_subprocess_shell(f"convert {path} -resize {width} out.png")
    # ok: py-command-injection-tainted
    proc = await asyncio.create_subprocess_exec("convert", path, "-resize", str(width), "out.png")
    await proc.wait()
    return {}


class DiagnosticsHandler:
    def post(self):
        target = self.get_argument("target")
        # ruleid: py-command-injection-tainted, py-command-injection-dynamic-shell
        os.system("traceroute " + target)
        # ruleid: py-command-injection-tainted
        pty.spawn(self.get_argument("shell"))


# ===========================================================================
# OS command injection: unknown source (py-command-injection-dynamic-shell)
# ===========================================================================


def run_ping(host):
    # ruleid: py-command-injection-dynamic-shell
    return sp.run(f"ping -c 1 {host}", shell=True, capture_output=True)


def make_archive(archive, path):
    # ruleid: py-command-injection-dynamic-shell
    os.system("tar czf %s %s" % (archive, path))
    # ruleid: py-command-injection-dynamic-shell
    os.system(" ".join(["rm", "-rf", path]))
    command = "gzip -9 {}".format(archive)
    # ruleid: py-command-injection-dynamic-shell
    sp.check_call(command, shell=True)
    # ruleid: py-command-injection-dynamic-shell
    sp.run(["sh", "-c", f"chmod 600 {archive}"], check=True)
    # ok: py-command-injection-dynamic-shell
    sp.run(["tar", "czf", archive, path], check=True)
    # ok: py-command-injection-dynamic-shell
    os.system(f"tar czf {BACKUP_DIR}/latest.tgz /srv/data")
    # ok: py-command-injection-dynamic-shell
    sp.run(f"tar czf {shlex.quote(archive)} {shlex.quote(path)}", shell=True, check=True)
    # ok: py-command-injection-dynamic-shell
    print(f"archived {path} into {archive}")


def count_lines(path):
    # A cast around the call does not make the command safe.
    # ruleid: py-command-injection-dynamic-shell
    return int(sp.check_output(f"wc -l < {path}", shell=True))


def disk_free(mount):
    # ruleid: py-command-injection-dynamic-shell
    return os.popen("df -h " + mount).read()


def run_joined(argv):
    # Known limit: joining a list of unknown values is not treated as building a
    # command (only lists written inline are); the taint rules still cover it.
    # todoruleid: py-command-injection-dynamic-shell
    return os.system(" ".join(argv))


def restart(service):
    # A plain variable with no formatting is outside this rule's scope.
    # ok: py-command-injection-dynamic-shell
    return sp.call(service, shell=True)


# ===========================================================================
# OS command injection: command-line input (py-command-injection-local-tainted)
# ===========================================================================


def cli_cmd_main():
    # ruleid: py-command-injection-local-tainted, py-command-injection-dynamic-shell
    os.system("ping -c 3 " + sys.argv[1])
    # ruleid: py-command-injection-local-tainted
    sp.call(input("command> "), shell=True)
    parser = argparse.ArgumentParser()
    parser.add_argument("repo")
    opts = parser.parse_args()
    # ruleid: py-command-injection-local-tainted, py-command-injection-dynamic-shell
    sp.run(f"git clone {opts.repo}", shell=True, check=True)
    # ruleid: py-command-injection-local-tainted
    sp.run([sys.argv[2], "--help"])
    # ok: py-command-injection-local-tainted, py-command-injection-dynamic-shell
    sp.run(["git", "clone", "--", opts.repo], check=True)
    # ok: py-command-injection-local-tainted, py-command-injection-dynamic-shell
    os.system("ping -c 3 " + shlex.quote(sys.argv[1]))
    # ok: py-command-injection-local-tainted
    sp.run(["ls", "-l"], check=True)


# ===========================================================================
# Code injection: HTTP input (py-code-injection-tainted)
# ===========================================================================


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "0")
    # ruleid: py-code-injection-tainted, py-code-injection-dynamic-eval
    result = eval(expr)

    # Restricted globals do not make eval safe.
    # ruleid: py-code-injection-tainted, py-code-injection-dynamic-eval
    exec(request.form["code"], {"__builtins__": {}}, {})

    # ruleid: py-code-injection-tainted, py-code-injection-dynamic-eval
    code_obj = compile(request.get_data(as_text=True), "<request>", "exec")

    # ruleid: py-code-injection-tainted, py-code-injection-dynamic-eval
    builtins.eval(request.values["formula"])

    # Literal parsing, not execution.
    # ok: py-code-injection-tainted
    value = ast.literal_eval(request.args["data"])
    # ok: py-code-injection-tainted
    value = json.loads(request.data)
    # Parsing to an AST does not execute anything.
    # ok: py-code-injection-tainted, py-code-injection-dynamic-eval
    tree = compile(request.data, "<request>", "exec", flags=ast.PyCF_ONLY_AST)
    # re.compile is not the builtin compile().
    # ok: py-code-injection-tainted
    pattern = re.compile(request.args["pattern"])
    return str(result)


@app.route("/plugins/<name>")
def load_plugin(name):
    # ruleid: py-code-injection-tainted
    module = importlib.import_module(f"app.plugins.{name}")
    # ruleid: py-code-injection-tainted
    other = __import__(request.args["module"])

    # ok: py-code-injection-tainted
    fixed = importlib.import_module("app.plugins." + REPORT_TOOLS[request.args["tool"]])

    if name not in ALLOWED_PLUGINS:
        abort(404)
    # ok: py-code-injection-tainted
    module = importlib.import_module(f"app.plugins.{name}")
    return module.render()


def django_run_script(request):
    # ruleid: py-code-injection-tainted
    runpy.run_path(request.POST["script_path"])
    return HttpResponse()


@api.get("/eval")
def fastapi_eval(expression: str, precision: int = 2):
    # ruleid: py-code-injection-tainted, py-code-injection-dynamic-eval
    return {"value": round(eval(expression), precision)}


# ===========================================================================
# Code injection: unknown source (py-code-injection-dynamic-eval)
# ===========================================================================


def evaluate_rule(rule, context):
    # ruleid: py-code-injection-dynamic-eval
    return eval(rule, {"__builtins__": {}}, context)


def apply_formula(formula, namespace):
    # ruleid: py-code-injection-dynamic-eval
    exec(f"result = {formula}", namespace)
    return namespace["result"]


def load_template(source, filename):
    # ruleid: py-code-injection-dynamic-eval
    code = compile(source, filename, "exec")
    # Executing a code object that compile() produced above is reported there.
    # ok: py-code-injection-dynamic-eval
    exec(code, {})


def read_version():
    namespace = {}
    # setup.py idiom: executing a file shipped with the project.
    # ok: py-code-injection-dynamic-eval
    exec(open("mypkg/__version__.py").read(), namespace)
    with open("mypkg/_config.py") as fh:
        # ok: py-code-injection-dynamic-eval
        exec(fh.read(), namespace)
    # ok: py-code-injection-dynamic-eval
    exec(textwrap.dedent("""
        def helper():
            return 42
    """), namespace)
    # ok: py-code-injection-dynamic-eval
    total = eval("2 ** 10")
    return namespace


def run_snippet(snippet):
    # Being inside `with open(...)` does not make other code constant.
    with open("audit.log", "a") as log:
        log.write(snippet)
        # ruleid: py-code-injection-dynamic-eval
        exec(snippet)


def model_inference(model, frame):
    # Methods named eval (PyTorch, pandas) are not the builtin.
    # ok: py-code-injection-dynamic-eval
    model.eval()
    # ok: py-code-injection-dynamic-eval
    return frame.eval("total = price * qty")


# ===========================================================================
# Code injection: command-line input (py-code-injection-local-tainted)
# ===========================================================================


def repl():
    # ruleid: py-code-injection-local-tainted, py-code-injection-dynamic-eval
    print(eval(input(">>> ")))
    # ruleid: py-code-injection-local-tainted, py-code-injection-dynamic-eval
    exec(sys.stdin.read())
    parser = argparse.ArgumentParser()
    parser.add_argument("--expr")
    parser.add_argument("--backend")
    args = parser.parse_args()
    # ruleid: py-code-injection-local-tainted, py-code-injection-dynamic-eval
    code = compile(args.expr, "<cli>", "eval")
    # Picking a module by name on the command line is what the flag is for.
    # ok: py-code-injection-local-tainted
    backend = importlib.import_module(args.backend)
    # ok: py-code-injection-local-tainted
    config = ast.literal_eval(input("config> "))
    # ok: py-code-injection-local-tainted
    options = json.loads(sys.argv[2])
    # ok: py-code-injection-local-tainted
    backend = importlib.import_module(REPORT_TOOLS[sys.argv[3]])
    return backend, config, options, code


def profile_script():
    # Running a script the caller names is the purpose of a profiler; the
    # structural rule still lists it for review.
    with open(sys.argv[1]) as fh:
        # ok: py-code-injection-local-tainted
        # ruleid: py-code-injection-dynamic-eval
        code = compile(fh.read(), sys.argv[1], "exec")
    # Parsing to an AST does not execute anything.
    # ok: py-code-injection-local-tainted, py-code-injection-dynamic-eval
    tree = compile(sys.stdin.read(), "<stdin>", "exec", ast.PyCF_ONLY_AST)
    return code, tree


# ===========================================================================
# LDAP injection: HTTP input (py-ldap-injection-tainted)
# ===========================================================================


@app.route("/login", methods=["POST"])
def ldap_login():
    username = request.form["username"]
    conn = ldap.initialize("ldap://ldap.example.com")
    # ruleid: py-ldap-injection-tainted, py-ldap-injection-dynamic-filter
    results = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, f"(uid={username})")

    # ok: py-ldap-injection-tainted, py-ldap-injection-dynamic-filter
    results = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, f"(uid={escape_filter_chars(username)})")

    # ok: py-ldap-injection-tainted, py-ldap-injection-dynamic-filter
    results = conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, filter_format("(uid=%s)", [username]))

    # ruleid: py-ldap-injection-tainted, py-ldap-injection-dynamic-filter
    results = conn.search_ext_s(BASE_DN, ldap.SCOPE_SUBTREE, filterstr="(&(objectClass=person)(mail=%s))" % request.form["email"])

    # The base DN is built from input as well.
    # ruleid: py-ldap-injection-tainted, py-ldap-injection-dynamic-filter
    entry = conn.search_s(f"uid={username},{BASE_DN}", ldap.SCOPE_BASE)

    # ruleid: py-ldap-injection-tainted
    msgid = conn.search(BASE_DN, ldap.SCOPE_SUBTREE, request.args["filter"])
    return jsonify(results)


@app.route("/directory")
def directory_lookup():
    server = ldap3.Server("ldap://ldap.example.com")
    conn = ldap3.Connection(server, auto_bind=True)
    cn = request.args["cn"]
    # ruleid: py-ldap-injection-tainted, py-ldap-injection-dynamic-filter
    conn.search("dc=example,dc=com", "(cn=" + cn + ")", attributes=["mail"])
    # ok: py-ldap-injection-tainted, py-ldap-injection-dynamic-filter
    conn.search("dc=example,dc=com", "(cn=" + ldap3_escape(cn) + ")", attributes=["mail"])
    # ruleid: py-ldap-injection-tainted
    conn.search(search_base="dc=example,dc=com", search_filter=request.args["q"])
    # ok: py-ldap-injection-tainted
    conn.search("dc=example,dc=com", "(objectClass=person)", attributes=["cn"])
    # re.search has the same shape but is not LDAP.
    # ok: py-ldap-injection-tainted
    match = re.search(request.args["pattern"], "some text")
    return jsonify(conn.entries)


# ===========================================================================
# LDAP injection: unknown source (py-ldap-injection-dynamic-filter)
# ===========================================================================


def find_account(ldap_conn, login):
    # ruleid: py-ldap-injection-dynamic-filter
    return ldap_conn.search_s(BASE_DN, ldap.SCOPE_SUBTREE, "(sAMAccountName=%s)" % login)


def find_by_mail(server, email):
    with ldap3.Connection(server, auto_bind=True) as c:
        # ruleid: py-ldap-injection-dynamic-filter
        c.search(BASE_DN, f"(mail={email})")
        # ok: py-ldap-injection-dynamic-filter
        c.search(BASE_DN, f"(mail={ldap3_escape(email)})")
        return c.entries


def search_people(conn, name):
    # ruleid: py-ldap-injection-dynamic-filter
    conn.search(BASE_DN, "(cn=%s)" % name, SUBTREE, attributes=["mail"])
    # ok: py-ldap-injection-dynamic-filter
    conn.search(BASE_DN, "(cn=%s)" % ldap3_escape(name), SUBTREE)
    return conn.entries


def find_group_members(conn, group):
    # ruleid: py-ldap-injection-dynamic-filter
    conn.search(search_base=BASE_DN, search_filter="(&(objectClass=group)(cn=" + group + "))")
    # ok: py-ldap-injection-dynamic-filter
    conn.search(search_base=BASE_DN, search_filter="(objectClass=group)")
    # ok: py-ldap-injection-dynamic-filter
    conn.search(search_base=BASE_DN, search_filter=filter_format("(cn=%s)", [group]))
    # ok: py-ldap-injection-dynamic-filter
    matched = re.search(f"^{group}", "admins")
    return conn.entries

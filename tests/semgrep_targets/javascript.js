// Test targets for trinetra/rules/javascript.yaml, run with `semgrep --test`.
// Deliberately vulnerable. Never import or execute this file.
const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const https = require("https");
const axios = require("axios");
const jwt = require("jsonwebtoken");
const { exec, execFile } = require("child_process");

const app = express();

function codeInjection(input) {
  // ruleid: trinetra.js.code-injection
  eval(input);
  // ruleid: trinetra.js.code-injection
  const f = new Function("a", input);
  // ok: trinetra.js.code-injection
  eval("2 + 2");
  // ok: trinetra.js.code-injection
  setTimeout(() => console.log("tick"), 1000);
  return f;
}

function commandInjection(host) {
  // ruleid: trinetra.js.command-injection
  exec("ping -c 1 " + host);
  // ruleid: trinetra.js.command-injection
  exec(`nslookup ${host}`);
  // ok: trinetra.js.command-injection
  exec("uptime");
  // ok: trinetra.js.command-injection
  execFile("ping", ["-c", "1", host]);
}

function sqlInjection(db, id, name) {
  // ruleid: trinetra.js.sql-injection
  db.query("SELECT * FROM users WHERE id = " + id);
  // ruleid: trinetra.js.sql-injection
  db.query(`SELECT * FROM users WHERE name = '${name}'`);
  // ok: trinetra.js.sql-injection
  db.query("SELECT * FROM users WHERE id = ?", [id]);
  // ok: trinetra.js.sql-injection
  const label = "Hello " + name;
  return label;
}

function domXss(el, html) {
  // ruleid: trinetra.js.dom-xss
  el.innerHTML = html;
  // ruleid: trinetra.js.dom-xss
  document.write(html);
  // ok: trinetra.js.dom-xss
  el.innerHTML = "<b>static</b>";
  // ok: trinetra.js.dom-xss
  el.innerHTML = DOMPurify.sanitize(html);
  // ok: trinetra.js.dom-xss
  el.textContent = html;
}

function Comment({ body }) {
  // ruleid: trinetra.js.react-dangerously-set-inner-html
  const raw = <div dangerouslySetInnerHTML={{ __html: body }} />;
  // ok: trinetra.js.react-dangerously-set-inner-html
  const clean = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(body) }} />;
  return [raw, clean];
}

app.get("/go", (req, res) => {
  // ruleid: trinetra.js.express-open-redirect
  res.redirect(req.query.next);
});

app.get("/home", (req, res) => {
  // ok: trinetra.js.express-open-redirect
  res.redirect("/dashboard");
});

app.get("/file", (req, res) => {
  const name = req.query.name;
  // ruleid: trinetra.js.express-path-traversal
  res.sendFile(path.join(__dirname, "files", name));
});

app.get("/file-safe", (req, res) => {
  const name = path.basename(req.query.name);
  // ok: trinetra.js.express-path-traversal
  res.sendFile(path.join(__dirname, "files", name));
});

app.get("/proxy", async (req, res) => {
  // ruleid: trinetra.js.express-ssrf
  const r = await axios.get(req.query.url);
  // ok: trinetra.js.express-ssrf
  const s = await axios.get("https://api.example.com/status", { params: { q: req.query.q } });
  res.send(r.data + s.data);
});

function tls() {
  // ruleid: trinetra.js.tls-verification-disabled
  const agent = new https.Agent({ rejectUnauthorized: false });
  // ruleid: trinetra.js.tls-verification-disabled
  process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  // ok: trinetra.js.tls-verification-disabled
  const ok = new https.Agent({ keepAlive: true });
  return [agent, ok];
}

function tokens(token, key) {
  // ruleid: trinetra.js.jwt-verification-bypass
  const claims = jwt.decode(token);
  // ok: trinetra.js.jwt-verification-bypass
  const verified = jwt.verify(token, key, { algorithms: ["HS256"] });
  // ruleid: trinetra.js.weak-hash
  const digest = crypto.createHash("md5").update(token).digest("hex");
  // ok: trinetra.js.weak-hash
  const good = crypto.createHash("sha256").update(token).digest("hex");
  // ruleid: trinetra.js.insecure-random-token
  const resetToken = Math.random().toString(36).slice(2);
  // ok: trinetra.js.insecure-random-token
  const jitter = Math.random() * 100;
  return [claims, verified, digest, good, resetToken, jitter];
}

// ruleid: trinetra.js.hardcoded-secret
const DB_PASSWORD = "hunter2_placeholder";
// ruleid: trinetra.js.hardcoded-secret
const config = { clientSecret: "FAKE-9f8e7d6c5b4a" };
// ok: trinetra.js.hardcoded-secret
const API_KEY = process.env.API_KEY;
// ok: trinetra.js.hardcoded-secret
const PASSWORD_FIELD = "password_input";

module.exports = { app, fs, config, DB_PASSWORD, API_KEY, PASSWORD_FIELD };

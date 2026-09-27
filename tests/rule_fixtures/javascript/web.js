// Rule fixture for trinetra/brains/static/rules/javascript/web.yaml
// Minimal vulnerable and safe snippets for rule tests only. Not a working application.
'use strict';

const express = require('express');
const path = require('path');
const fs = require('fs');
const http = require('http');
const https = require('https');
const axios = require('axios');
const httpClient = require('axios');
const got = require('got');
const request = require('request');
const superagent = require('superagent');
const escapeHtml = require('escape-html');
const ejs = require('ejs');
const cors = require('cors');
const _ = require('lodash');
const Koa = require('koa');
const Router = require('@koa/router');
const fastify = require('fastify')();
const { Server } = require('socket.io');
const DOMPurify = require('dompurify');

const app = express();
const koa = new Koa();
const router = new Router();

const ROOT = path.join(__dirname, 'files');
const UPLOAD_DIR = path.join(__dirname, 'uploads');
const REPORT_DIR = '/var/app/reports';
const AVATAR_DIR = '/var/app/avatars';
const API_BASE = 'https://api.example.com/v1';
const ALLOWED_HOSTS = new Set(['api.example.com', 'cdn.example.com']);
const ALLOWED_REDIRECTS = ['/home', '/settings', '/billing'];
const ALLOWED_REPORTS = ['daily.csv', 'weekly.csv'];
const ALLOWED_ORIGINS = ['https://app.example.com', 'https://admin.example.com'];
const BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
const RESULTS_TEMPLATE = '<h1>Results for <%= q %></h1>';

// ===========================================================================
// Reflected XSS: js-xss-reflected-tainted
// ===========================================================================

app.get('/hello', (req, res) => {
  // ruleid: js-xss-reflected-tainted
  res.send('<h1>Hello ' + req.query.name + '</h1>');
});

app.get('/search', (req, res) => {
  const q = req.query.q;
  const html = `<p>Results for <b>${q}</b></p>`;
  // ruleid: js-xss-reflected-tainted
  res.status(200).send(html);
});

app.post('/comment', (req, res) => {
  const { author } = req.body;
  // ruleid: js-xss-reflected-tainted
  res.write(['<li class="author">', author, '</li>'].join(''));
  res.end();
});

app.get('/welcome', (req, res) => {
  const user = req.cookies.displayName;
  // ruleid: js-xss-reflected-tainted
  res.send('<span>Welcome back, '.concat(user, '</span>'));
});

http.createServer((req, res) => {
  res.writeHead(404, { 'Content-Type': 'text/html' });
  // ruleid: js-xss-reflected-tainted
  res.end(`<p>${req.url} was not found</p>`);
});

router.get('/koa/greet', (ctx) => {
  // ruleid: js-xss-reflected-tainted
  ctx.body = `<p>Hi ${ctx.query.name}</p>`;
});

fastify.get('/fastify/greet', async (request, reply) => {
  // ruleid: js-xss-reflected-tainted
  return reply.type('text/html').send(`<p>Hi ${request.query.name}</p>`);
});

app.get('/hello-safe', (req, res) => {
  // ok: js-xss-reflected-tainted
  res.send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
});

app.get('/api/echo', (req, res) => {
  // ok: js-xss-reflected-tainted
  res.json({ echo: req.query.msg });
});

app.post('/api/echo', (req, res) => {
  // ok: js-xss-reflected-tainted
  res.send({ received: req.body.msg });
});

app.get('/plain', (req, res) => {
  // ok: js-xss-reflected-tainted
  res.type('text/plain').send(req.query.msg);
});

app.get('/profile', (req, res) => {
  // ok: js-xss-reflected-tainted
  res.render('profile', { name: req.query.name });
});

app.get('/page', (req, res) => {
  // ok: js-xss-reflected-tainted
  res.send(`<p>Page ${parseInt(req.query.page, 10)}</p>`);
});

http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  // ok: js-xss-reflected-tainted
  res.end(JSON.stringify({ path: req.url }));
});

app.get('/results', (req, res) => {
  // ok: js-xss-reflected-tainted
  res.send(ejs.render(RESULTS_TEMPLATE, { q: req.query.q }));
});

fastify.get('/fastify/echo', async (request, reply) => {
  // ok: js-xss-reflected-tainted
  return reply.send(request.query.msg);
});

// ===========================================================================
// Reflected XSS from caller values: js-xss-reflected-dynamic-html
// ===========================================================================

function renderGreeting(res, name) {
  // ruleid: js-xss-reflected-dynamic-html
  res.send('<h1>Hello, ' + name + '</h1>');
}

function renderList(res, items) {
  let html = '<ul>';
  for (const item of items) {
    html += `<li>${item.title}</li>`;
  }
  html += '</ul>';
  // ruleid: js-xss-reflected-dynamic-html
  res.send(html);
}

function renderError(ctx, message) {
  // ruleid: js-xss-reflected-dynamic-html
  ctx.body = `<div class="error">${message}</div>`;
}

function renderGreetingSafe(res, name) {
  // ok: js-xss-reflected-dynamic-html
  res.send('<h1>Hello, ' + escapeHtml(name) + '</h1>');
}

function sendStatus(res, count) {
  // ok: js-xss-reflected-dynamic-html
  res.send('Processed ' + count + ' items');
}

function sendDebug(res, dump) {
  // ok: js-xss-reflected-dynamic-html
  res.type('text/plain').send('<pre>' + dump + '</pre>');
}

function renderBanner(res) {
  const TITLE = 'Welcome';
  // ok: js-xss-reflected-dynamic-html
  res.send('<h1>' + TITLE + '</h1>');
}

// ===========================================================================
// SSRF: js-ssrf-tainted
// ===========================================================================

app.get('/proxy', async (req, res) => {
  // ruleid: js-ssrf-tainted
  const upstream = await axios.get(req.query.url);
  res.json(upstream.data);
});

app.post('/webhooks/test', async (req, res) => {
  const target = req.body.webhookUrl;
  // ruleid: js-ssrf-tainted
  await httpClient.post(target, { ping: true });
  res.sendStatus(204);
});

app.get('/status', async (req, res) => {
  // ruleid: js-ssrf-tainted
  const r = await fetch(`https://${req.query.host}/api/status`);
  res.json(await r.json());
});

app.get('/feed', (req, res) => {
  // ruleid: js-ssrf-tainted
  http.get(req.query.feed, (feedRes) => feedRes.pipe(res));
});

app.get('/image', (req, res) => {
  // ruleid: js-ssrf-tainted
  request({ uri: req.query.image, encoding: null }).pipe(res);
});

app.get('/preview', async (req, res) => {
  const link = new URL(req.query.link);
  // ruleid: js-ssrf-tainted
  const page = await superagent.get(link.href);
  res.send({ length: page.text.length });
});

app.post('/ping', (req, res) => {
  // ruleid: js-ssrf-tainted
  https.request({ hostname: req.body.host, path: '/health' }).end();
  res.sendStatus(202);
});

app.get('/github', async (req, res) => {
  // ok: js-ssrf-tainted
  const r = await axios.get(`https://api.github.com/users/${req.query.user}`);
  res.json(r.data);
});

app.get('/items/:id', async (req, res) => {
  // ok: js-ssrf-tainted
  const r = await fetch(API_BASE + '/items/' + encodeURIComponent(req.params.id));
  res.json(await r.json());
});

app.get('/fetch', async (req, res) => {
  const target = new URL(req.query.url);
  if (!ALLOWED_HOSTS.has(target.hostname)) {
    return res.status(400).send('host not allowed');
  }
  // ok: js-ssrf-tainted
  const r = await got(target);
  res.json({ status: r.statusCode, body: r.body });
});

app.get('/orders/:id', async (req, res) => {
  // ok: js-ssrf-tainted
  const r = await axios.get(`${process.env.ORDERS_URL}/orders/${req.params.id}`);
  res.json(r.data);
});

// ===========================================================================
// SSRF from caller values: js-ssrf-dynamic-host
// ===========================================================================

async function checkHealth(host) {
  // ruleid: js-ssrf-dynamic-host
  return axios.get('http://' + host + ':8080/health');
}

function fetchAvatar(domain, user) {
  // ruleid: js-ssrf-dynamic-host
  return fetch(`https://${domain}/avatars/${user}.png`);
}

async function callPartner(partnerHost, payload) {
  const endpoint = `https://${partnerHost}/v2/orders`;
  // ruleid: js-ssrf-dynamic-host
  return got.post(endpoint, { json: payload });
}

function pingNode(hostname) {
  // ruleid: js-ssrf-dynamic-host
  return http.request({ hostname, port: 80, path: '/' });
}

async function getUser(id) {
  // ok: js-ssrf-dynamic-host
  return axios.get('https://api.example.com/users/' + id);
}

function download(url) {
  // ok: js-ssrf-dynamic-host
  return fetch(url);
}

function probePort(options) {
  // ok: js-ssrf-dynamic-host
  return portChecker.check({ host: options.host, port: options.port });
}

async function internalCall(route) {
  // ok: js-ssrf-dynamic-host
  return fetch(`http://${process.env.INTERNAL_HOST}/${route}`);
}

// ===========================================================================
// Path traversal: js-path-traversal-tainted
// ===========================================================================

app.get('/files/:file', (req, res) => {
  // ruleid: js-path-traversal-tainted
  fs.readFile(path.join(UPLOAD_DIR, req.params.file), (err, data) => res.end(data));
});

app.get('/docs', (req, res) => {
  // ruleid: js-path-traversal-tainted
  res.sendFile(path.join(__dirname, 'public', req.query.page));
});

app.get('/report', (req, res) => {
  // ruleid: js-path-traversal-tainted
  res.download(REPORT_DIR + '/' + req.query.name);
});

app.delete('/tmp', (req, res) => {
  // ruleid: js-path-traversal-tainted
  fs.unlinkSync(`./tmp/${req.body.filename}`);
  res.sendStatus(204);
});

app.get('/guides', (req, res) => {
  const rel = req.query.path;
  if (!rel.startsWith('guides/')) {
    return res.sendStatus(400);
  }
  // ruleid: js-path-traversal-tainted
  fs.createReadStream(path.join(ROOT, rel)).pipe(res);
});

app.get('/notes/:name', (req, res) => {
  const name = req.params.name.replace(/\.\.\//g, '');
  // ruleid: js-path-traversal-tainted
  res.send(fs.readFileSync(path.join(ROOT, 'notes', name), 'utf8'));
});

app.get('/static/:file', (req, res) => {
  // ok: js-path-traversal-tainted
  res.sendFile(req.params.file, { root: path.join(__dirname, 'public') });
});

app.get('/uploads/:file', (req, res) => {
  // ok: js-path-traversal-tainted
  fs.readFile(path.join(UPLOAD_DIR, path.basename(req.params.file)), (err, data) => res.end(data));
});

app.get('/browse', (req, res) => {
  const full = path.resolve(ROOT, req.query.path);
  if (!full.startsWith(ROOT + path.sep)) {
    return res.sendStatus(403);
  }
  // ok: js-path-traversal-tainted
  fs.createReadStream(full).pipe(res);
});

app.get('/raw', (req, res) => {
  const file = path.normalize(path.join(ROOT, req.query.file));
  if (file.slice(0, ROOT.length) !== ROOT) {
    return res.sendStatus(403);
  }
  // ok: js-path-traversal-tainted
  fs.createReadStream(file).pipe(res);
});

app.get('/export', (req, res) => {
  const target = path.join(ROOT, req.query.file);
  const rel = path.relative(ROOT, target);
  if (rel.startsWith('..') || path.isAbsolute(rel)) {
    return res.sendStatus(403);
  }
  // ok: js-path-traversal-tainted
  res.download(target);
});

app.get('/reports', (req, res) => {
  const { name } = req.query;
  if (!ALLOWED_REPORTS.includes(name)) {
    return res.sendStatus(404);
  }
  // ok: js-path-traversal-tainted
  res.download(path.join(REPORT_DIR, name));
});

app.get('/', (req, res) => {
  // ok: js-path-traversal-tainted
  res.sendFile(path.join(__dirname, 'views', 'index.html'));
});

// ===========================================================================
// Path traversal from caller values: js-path-traversal-dynamic-path
// ===========================================================================

function readUpload(name) {
  // ruleid: js-path-traversal-dynamic-path
  return fs.readFileSync(path.join(UPLOAD_DIR, name), 'utf8');
}

function deleteAvatar(userId, file) {
  // ruleid: js-path-traversal-dynamic-path
  fs.unlink(`${AVATAR_DIR}/${userId}/${file}`, () => {});
}

function loadTemplate(templateName) {
  const file = __dirname + '/templates/' + templateName + '.html';
  // ruleid: js-path-traversal-dynamic-path
  return fs.readFileSync(file, 'utf8');
}

function readUploadSafe(name) {
  // ok: js-path-traversal-dynamic-path
  return fs.readFileSync(path.join(UPLOAD_DIR, path.basename(name)), 'utf8');
}

function readConfig(configPath) {
  // ok: js-path-traversal-dynamic-path
  return fs.readFileSync(configPath, 'utf8');
}

function readInRoot(relPath) {
  const full = path.resolve(ROOT, relPath);
  if (!full.startsWith(ROOT + path.sep)) {
    throw new Error('path escapes root');
  }
  // ok: js-path-traversal-dynamic-path
  return fs.readFileSync(full);
}

// ===========================================================================
// Open redirect: js-open-redirect-tainted
// ===========================================================================

app.get('/login/callback', (req, res) => {
  // ruleid: js-open-redirect-tainted
  res.redirect(req.query.next);
});

app.post('/logout', (req, res) => {
  // ruleid: js-open-redirect-tainted
  res.redirect(302, req.body.returnTo);
});

app.get('/continue', (req, res) => {
  const url = req.query.url;
  if (url.startsWith('/')) {
    // ruleid: js-open-redirect-tainted
    return res.redirect(url);
  }
  res.redirect('/');
});

app.get('/jump', (req, res) => {
  // ruleid: js-open-redirect-tainted
  res.redirect('/' + req.query.path);
});

router.get('/koa/out', (ctx) => {
  // ruleid: js-open-redirect-tainted
  ctx.redirect(ctx.query.url);
});

http.createServer((req, res) => {
  const to = new URL(req.url, 'http://localhost').searchParams.get('to');
  // ruleid: js-open-redirect-tainted
  res.writeHead(302, { Location: to });
  res.end();
});

app.get('/users/:id/open', (req, res) => {
  // ok: js-open-redirect-tainted
  res.redirect('/profile/' + req.params.id);
});

app.get('/go', (req, res) => {
  if (ALLOWED_REDIRECTS.includes(req.query.next)) {
    // ok: js-open-redirect-tainted
    return res.redirect(req.query.next);
  }
  res.redirect('/home');
});

app.get('/find', (req, res) => {
  // ok: js-open-redirect-tainted
  res.redirect(`/search?q=${encodeURIComponent(req.query.q)}`);
});

app.get('/done', (req, res) => {
  // ok: js-open-redirect-tainted
  res.redirect('/dashboard');
});

// ===========================================================================
// Open redirect from caller values: js-open-redirect-dynamic-url
// ===========================================================================

function finishLogin(res, returnTo) {
  // ruleid: js-open-redirect-dynamic-url
  res.redirect(returnTo || '/');
}

function moved(res, target) {
  // ruleid: js-open-redirect-dynamic-url
  res.redirect(301, target);
}

function sendToPartner(res, partnerUrl, token) {
  // ruleid: js-open-redirect-dynamic-url
  res.redirect(`${partnerUrl}?token=${token}`);
}

function toProfile(res, userId) {
  // ok: js-open-redirect-dynamic-url
  res.redirect('/users/' + userId);
}

function safeReturn(res, returnTo) {
  if (!isLocalUrl(returnTo)) {
    return res.redirect('/');
  }
  // ok: js-open-redirect-dynamic-url
  res.redirect(returnTo);
}

function toHome(res) {
  // ok: js-open-redirect-dynamic-url
  res.redirect('/');
}

// ===========================================================================
// Prototype pollution: js-prototype-pollution-tainted
// ===========================================================================

const userSettings = {};
const store = {};

app.post('/settings', (req, res) => {
  // ruleid: js-prototype-pollution-tainted
  _.merge(userSettings, req.body);
  res.sendStatus(204);
});

app.post('/options', (req, res) => {
  const options = {};
  // ruleid: js-prototype-pollution-tainted
  _.defaultsDeep(options, req.body.options);
  res.json(options);
});

app.post('/config', (req, res) => {
  const config = {};
  // ruleid: js-prototype-pollution-tainted
  _.set(config, req.body.path, req.body.value);
  res.json(config);
});

app.put('/store/:section/:key', (req, res) => {
  // ruleid: js-prototype-pollution-tainted
  store[req.params.section][req.params.key] = req.body.value;
  res.sendStatus(204);
});

app.post('/prefs', (req, res) => {
  const prefs = JSON.parse(req.body.prefs);
  // ruleid: js-prototype-pollution-tainted
  merge(userSettings, prefs);
  res.sendStatus(204);
});

app.put('/safe-store/:section/:key', (req, res) => {
  const { section, key } = req.params;
  if (BLOCKED_KEYS.has(section) || BLOCKED_KEYS.has(key)) {
    return res.sendStatus(400);
  }
  // ok: js-prototype-pollution-tainted
  store[section][key] = req.body.value;
  res.sendStatus(204);
});

app.put('/registry/:ns/:key', (req, res) => {
  const registry = Object.create(null);
  // ok: js-prototype-pollution-tainted
  registry[req.params.ns][req.params.key] = req.body.value;
  res.sendStatus(204);
});

app.post('/theme', (req, res) => {
  const config = {};
  // ok: js-prototype-pollution-tainted
  _.set(config, 'ui.theme', req.body.theme);
  res.json(config);
});

app.put('/flags/:key', (req, res) => {
  // ok: js-prototype-pollution-tainted
  store.flags[req.params.key] = Boolean(req.body.enabled);
  res.sendStatus(204);
});

// ===========================================================================
// Prototype pollution: js-prototype-pollution-recursive-merge
// ===========================================================================

function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === 'object' && source[key] !== null) {
      if (!target[key]) target[key] = {};
      merge(target[key], source[key]);
    } else {
      // ruleid: js-prototype-pollution-recursive-merge
      target[key] = source[key];
    }
  }
  return target;
}

function deepAssign(dst, src) {
  Object.keys(src).forEach(function (k) {
    if (src[k] && typeof src[k] === 'object') {
      // ruleid: js-prototype-pollution-recursive-merge
      dst[k] = deepAssign(dst[k] || {}, src[k]);
    } else {
      // ruleid: js-prototype-pollution-recursive-merge
      dst[k] = src[k];
    }
  });
  return dst;
}

class ObjectUtils {
  static extendDeep(target, source) {
    for (const [key, value] of Object.entries(source)) {
      if (value && typeof value === 'object') {
        target[key] = target[key] || {};
        ObjectUtils.extendDeep(target[key], value);
      } else {
        // ruleid: js-prototype-pollution-recursive-merge
        target[key] = value;
      }
    }
    return target;
  }
}

function safeMerge(target, source) {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') continue;
    if (typeof source[key] === 'object' && source[key] !== null) {
      target[key] = target[key] || {};
      safeMerge(target[key], source[key]);
    } else {
      // ok: js-prototype-pollution-recursive-merge
      target[key] = source[key];
    }
  }
  return target;
}

function mergeChecked(target, source) {
  for (const key of Object.keys(source)) {
    if (BLOCKED_KEYS.has(key)) {
      continue;
    }
    if (typeof source[key] === 'object') {
      mergeChecked(target[key] || {}, source[key]);
    } else {
      // ok: js-prototype-pollution-recursive-merge
      target[key] = source[key];
    }
  }
}

function assignDefaults(target, source) {
  for (const key in source) {
    if (target[key] === undefined) {
      // ok: js-prototype-pollution-recursive-merge
      target[key] = source[key];
    }
  }
  return target;
}

// ===========================================================================
// Prototype pollution: js-prototype-pollution-prototype-assign
// ===========================================================================

function Plugin() {}
function Model() {}

function loadPluginDefaults(manifestText) {
  // ruleid: js-prototype-pollution-prototype-assign
  Object.assign(Plugin.prototype, JSON.parse(manifestText));
}

function applyOverrides(raw) {
  const parsed = JSON.parse(raw);
  // ruleid: js-prototype-pollution-prototype-assign
  Object.assign(Object.prototype, parsed);
}

async function loadRemoteDefaults(resp) {
  const defaults = await resp.json();
  // ruleid: js-prototype-pollution-prototype-assign
  _.merge(Model.prototype, defaults);
}

// ok: js-prototype-pollution-prototype-assign
Object.assign(Model.prototype, { save() { return true; }, toJSON() { return {}; } });

// ok: js-prototype-pollution-prototype-assign
Object.assign(Model.prototype, require('events').EventEmitter.prototype);

function hydrate(model, raw) {
  // ok: js-prototype-pollution-prototype-assign
  Object.assign(model, JSON.parse(raw));
}

// ===========================================================================
// CORS: js-cors-credentials-any-origin
// ===========================================================================

// ruleid: js-cors-credentials-any-origin
app.use(cors({ origin: true, credentials: true }));

// ruleid: js-cors-credentials-any-origin
app.use('/api', cors({ credentials: true, origin: '*' }));

// ruleid: js-cors-credentials-any-origin
app.use(cors({
  origin: (origin, callback) => callback(null, origin),
  credentials: true,
}));

const io = new Server(http.createServer(app), {
  // ruleid: js-cors-credentials-any-origin
  cors: { origin: /.*/, credentials: true },
});

// ruleid: js-cors-credentials-any-origin
fastify.register(require('@fastify/cors'), {
  origin: function (origin, cb) { cb(null, true); }, credentials: true,
});

const corsDelegate = (req, cb) => {
  // ruleid: js-cors-credentials-any-origin
  cb(null, { origin: req.header('Origin'), credentials: true });
};

// ok: js-cors-credentials-any-origin
app.use(cors({ origin: ALLOWED_ORIGINS, credentials: true }));

// ok: js-cors-credentials-any-origin
app.use('/public', cors({ origin: '*' }));

// ok: js-cors-credentials-any-origin
app.use(cors({
  origin: (origin, cb) => {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) cb(null, true);
    else cb(new Error('Not allowed by CORS'));
  },
  credentials: true,
}));

// ok: js-cors-credentials-any-origin
app.use(cors({ origin: true, credentials: false }));

// ===========================================================================
// CORS: js-cors-header-origin-reflection
// ===========================================================================

app.use((req, res, next) => {
  // ruleid: js-cors-header-origin-reflection
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

app.use('/v2', (req, res, next) => {
  const origin = req.get('origin');
  // ruleid: js-cors-header-origin-reflection
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Credentials', true);
  next();
});

app.use('/v3', function corsHeaders(req, res, next) {
  // ruleid: js-cors-header-origin-reflection
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Credentials': 'true',
  });
  next();
});

http.createServer((req, res) => {
  // ruleid: js-cors-header-origin-reflection
  res.writeHead(200, {
    'Access-Control-Allow-Origin': req.headers.origin || '*',
    'Access-Control-Allow-Credentials': 'true',
  });
  res.end();
});

app.use('/v4', (req, res, next) => {
  const origin = req.headers.origin;
  if (ALLOWED_ORIGINS.includes(origin)) {
    // ok: js-cors-header-origin-reflection
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Vary', 'Origin');
  }
  next();
});

app.use('/public-api', (req, res, next) => {
  // ok: js-cors-header-origin-reflection
  res.setHeader('Access-Control-Allow-Origin', '*');
  next();
});

app.use('/v6', (req, res, next) => {
  if (req.path.startsWith('/account')) {
    res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  } else {
    // ok: js-cors-header-origin-reflection
    res.setHeader('Access-Control-Allow-Origin', '*');
  }
  next();
});

app.use('/v5', (req, res, next) => {
  // ok: js-cors-header-origin-reflection
  res.setHeader('Access-Control-Allow-Origin', 'https://app.example.com');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  next();
});

// ===========================================================================
// Browser code: DOM XSS, javascript: URLs, postMessage
// ===========================================================================

function showGreeting() {
  const greeting = document.getElementById('greeting');
  // ruleid: js-dom-xss-tainted
  greeting.innerHTML = 'Hello ' + decodeURIComponent(location.hash.slice(1));
}

function showBanner() {
  const params = new URLSearchParams(window.location.search);
  const msg = params.get('msg');
  // ruleid: js-dom-xss-tainted
  document.querySelector('#banner').insertAdjacentHTML('beforeend', `<p>${msg}</p>`);
}

function backLink() {
  // ruleid: js-dom-xss-tainted
  document.write('<a href="' + document.referrer + '">Back</a>');
}

function showResults() {
  const params = new URLSearchParams(location.search);
  // ruleid: js-dom-xss-tainted
  $('#results').html('Results for ' + params.get('q'));
  // ruleid: js-dom-xss-tainted
  $(location.hash).addClass('active');
}

function restoreState(el) {
  // ruleid: js-dom-xss-tainted
  el.outerHTML = window.name;
}

// ruleid: js-postmessage-missing-origin-check
window.addEventListener('message', (event) => {
  const preview = document.getElementById('preview');
  // ruleid: js-dom-xss-tainted
  preview.innerHTML = event.data.html;
});

function showGreetingSafe() {
  // ok: js-dom-xss-tainted
  document.getElementById('greeting').textContent = 'Hello ' + location.hash.slice(1);
}

function showBio() {
  const params = new URLSearchParams(location.search);
  // ok: js-dom-xss-tainted
  document.getElementById('bio').innerHTML = DOMPurify.sanitize(params.get('bio'));
}

window.addEventListener('message', (event) => {
  if (event.origin !== 'https://widgets.example.com') {
    return;
  }
  // ok: js-dom-xss-tainted
  document.getElementById('widget').innerHTML = event.data.html;
});

function showQuery() {
  const params = new URLSearchParams(location.search);
  // ok: js-dom-xss-tainted
  $('#results').text('Results for ' + params.get('q'));
}

function showSpinner(el) {
  // ok: js-dom-xss-tainted
  el.innerHTML = '<p class="spinner">Loading...</p>';
}

// ===========================================================================
// DOM XSS from caller values: js-dom-xss-dynamic-html
// ===========================================================================

function renderComment(container, comment) {
  // ruleid: js-dom-xss-dynamic-html
  container.innerHTML = `<div class="comment">${comment.body}</div>`;
}

function showFlash(msg) {
  // ruleid: js-dom-xss-dynamic-html
  $('#flash').html('<strong>' + msg + '</strong>');
}

function appendRow(table, row) {
  // ruleid: js-dom-xss-dynamic-html
  table.insertAdjacentHTML('beforeend', '<tr><td>' + row.name + '</td></tr>');
}

function renderCommentSafe(container, comment) {
  // ok: js-dom-xss-dynamic-html
  container.innerHTML = DOMPurify.sanitize(comment.body);
}

function setLabel(el, label) {
  // ok: js-dom-xss-dynamic-html
  el.textContent = label;
}

function clearList(list) {
  // ok: js-dom-xss-dynamic-html
  list.innerHTML = '';
}

function focusItem(selector) {
  // ok: js-dom-xss-dynamic-html
  $(selector).focus();
}

// ===========================================================================
// javascript: URLs: js-dom-javascript-url-tainted
// ===========================================================================

function continueAfterLogin() {
  // ruleid: js-dom-javascript-url-tainted
  location.href = new URLSearchParams(location.search).get('next');
}

function jumpToHash() {
  // ruleid: js-dom-javascript-url-tainted
  window.location = decodeURIComponent(location.hash.substring(1));
}

function openPopup() {
  const params = new URLSearchParams(location.search);
  // ruleid: js-dom-javascript-url-tainted
  window.open(params.get('popup'), '_blank');
}

function buildLink(anchor) {
  const params = new URLSearchParams(location.search);
  // ruleid: js-dom-javascript-url-tainted
  anchor.setAttribute('href', params.get('url'));
}

function goSearch() {
  const params = new URLSearchParams(location.search);
  // ok: js-dom-javascript-url-tainted
  location.href = '/search?q=' + encodeURIComponent(params.get('q'));
}

function continueSafely() {
  const next = new URL(new URLSearchParams(location.search).get('next'), location.origin);
  if (next.origin !== location.origin) {
    return;
  }
  // ok: js-dom-javascript-url-tainted
  location.assign(next);
}

function openProduct() {
  const params = new URLSearchParams(location.search);
  // ok: js-dom-javascript-url-tainted
  location.href = `/products/${params.get('id')}`;
}

function selectTab() {
  const params = new URLSearchParams(location.search);
  // ok: js-dom-javascript-url-tainted
  location.hash = params.get('tab');
}

// ===========================================================================
// postMessage: js-postmessage-missing-origin-check
// ===========================================================================

// ruleid: js-postmessage-missing-origin-check
window.addEventListener('message', (event) => {
  handleCommand(event.data.command, event.data.args);
});

// ruleid: js-postmessage-missing-origin-check
window.onmessage = function (e) {
  localStorage.setItem('token', e.data.token);
};

function onEmbedMessage(msg) {
  updateCart(msg.data.items);
}
// ruleid: js-postmessage-missing-origin-check
window.addEventListener('message', onEmbedMessage);

// ok: js-postmessage-missing-origin-check
window.addEventListener('message', function (e) {
  if (e.origin !== 'https://checkout.example.com') return;
  updateCart(e.data.items);
});

const trustedHandler = (e) => {
  if (!ALLOWED_ORIGINS.includes(e.origin)) {
    return;
  }
  handleCommand(e.data.command);
};
// ok: js-postmessage-missing-origin-check
window.addEventListener('message', trustedHandler);

const worker = new Worker('/js/worker.js');
// ok: js-postmessage-missing-origin-check
worker.addEventListener('message', (e) => renderStats(e.data));

const socket = new WebSocket('wss://live.example.com/feed');
// ok: js-postmessage-missing-origin-check
socket.onmessage = function (e) { renderStats(JSON.parse(e.data)); };

module.exports = { app, koa, io, corsDelegate, merge, deepAssign, ObjectUtils };

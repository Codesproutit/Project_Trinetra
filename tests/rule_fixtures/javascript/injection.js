// Trinetra rule fixture: JavaScript injection rules (rules/javascript/injection.yaml).
// Minimal vulnerable snippets for authorized rule testing, not production code.
// Annotations follow Semgrep's --test syntax: the comment marks the next line.
'use strict';

const fs = require('fs');
const path = require('path');
const util = require('util');
const express = require('express');
const superagent = require('superagent');
const mysql = require('mysql2');
const { Pool } = require('pg');
const knex = require('knex')({ client: 'pg' });
const { Sequelize, QueryTypes } = require('sequelize');
const pgFormat = require('pg-format');
const { sql } = require('slonik');
const Database = require('better-sqlite3');
const cp = require('child_process');
const { exec, execFile, spawn } = require('child_process');
const { execSync: runSync } = require('node:child_process');
const shell = require('shelljs');
const shellescape = require('shell-escape');
const vm = require('vm');
const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const _ = require('lodash');
const mongoose = require('mongoose');
const { MongoClient } = require('mongodb');
const mongoSanitize = require('mongo-sanitize');
const serialize = require('node-serialize');
const funcster = require('funcster');
const { unserialize: phpUnserialize } = require('php-serialize');
const Router = require('@koa/router');
const fastify = require('fastify')();

const app = express();
const router = new Router();
const connection = mysql.createConnection({ host: 'localhost', user: 'app', database: 'shop' });
const pool = new Pool();
const sqlite = new Database('app.db');
const sequelize = new Sequelize('sqlite::memory:');
const db = new MongoClient('mongodb://localhost:27017').db('shop');
const User = mongoose.model('User', new mongoose.Schema({ username: String, password: String }));
const Session = mongoose.model('Session', new mongoose.Schema({ user: String }));
const Product = mongoose.model('Product', new mongoose.Schema({ price: Number }));
const execAsync = util.promisify(cp.exec);

// =============================================================================
// SQL injection
// =============================================================================

app.get('/products', (req, res) => {
  const category = req.query.category;
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  connection.query("SELECT * FROM products WHERE category = '" + category + "'", (err, rows) => res.json(rows));
});

app.get('/users/:id', async (req, res) => {
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const { rows } = await pool.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
  res.json(rows);
});

app.post('/search', async (req, res) => {
  let sql = 'SELECT id, name FROM products WHERE 1=1';
  if (req.body.name) {
    sql += " AND name LIKE '%" + req.body.name + "%'";
  }
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const [rows] = await connection.promise().execute(sql);
  res.json(rows);
});

app.get('/orders', async (req, res) => {
  const { sort } = req.query;
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const orders = await knex('orders').select('*').orderByRaw(`${sort} DESC`);
  res.json(orders);
});

app.get('/reports', async (req, res) => {
  // ruleid: js-sqli-tainted
  const rows = await sequelize.query(req.query.report, { type: QueryTypes.SELECT });
  res.json(rows);
});

app.get('/audit', (req, res) => {
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  connection.query({ sql: 'SELECT * FROM audit WHERE actor = "' + req.get('X-User') + '"', timeout: 4000 }, (e, r) => res.json(r));
});

app.get('/invoices', async (req, res) => {
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const rows = await sequelize.models.Invoice.findAll({ where: sequelize.literal(`customer_ref = '${req.query.ref}'`) });
  res.json(rows);
});

fastify.get('/fastify/items', async (request, reply) => {
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  return pool.query("SELECT * FROM items WHERE owner = '" + request.query.owner + "'");
});

router.post('/koa/orders', async (ctx) => {
  const { status } = ctx.request.body;
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  ctx.body = await pool.query('SELECT * FROM orders WHERE status = '.concat("'", status, "'"));
});

const hapiRoute = {
  method: 'POST',
  path: '/hapi/notes',
  handler: async (request, h) => {
    // ruleid: js-sqli-tainted, js-sqli-dynamic
    const [rows] = await connection.promise().query('SELECT * FROM notes WHERE tag = ' + request.payload.tag);
    return h.response(rows);
  },
};

app.get('/accounts', async (req, res) => {
  // ok: js-sqli-tainted, js-nosqli-tainted
  const account = await sequelize.models.Account.findOne({ where: { email: req.query.email } });
  res.json(account);
});

exports.petsHandler = async (event) => {
  const { name } = JSON.parse(event.body);
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const result = await pool.query(`SELECT * FROM pets WHERE name = '${name}'`);
  return { statusCode: 200, body: JSON.stringify(result.rows) };
};

app.get('/notes/:id', (req, res) => {
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const note = sqlite.prepare(`SELECT * FROM notes WHERE id = ${req.params.id}`).get();
  res.json(note);
});

app.get('/products/safe', (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  connection.query('SELECT * FROM products WHERE category = ?', [req.query.category], (err, rows) => res.json(rows));
});

app.get('/users/:id/safe', async (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  const { rows } = await pool.query({ text: 'SELECT * FROM users WHERE id = $1', values: [req.params.id] });
  res.json(rows);
});

app.get('/page', async (req, res) => {
  const limit = parseInt(req.query.limit, 10) || 20;
  // ok: js-sqli-tainted, js-sqli-dynamic
  const { rows } = await pool.query(`SELECT * FROM items ORDER BY id LIMIT ${limit}`);
  res.json(rows);
});

app.get('/sorted', async (req, res) => {
  const SORTABLE = ['name', 'price', 'created_at'];
  const column = SORTABLE.includes(req.query.sort) ? req.query.sort : 'name';
  // ok: js-sqli-tainted, js-sqli-dynamic
  const [rows] = await connection.promise().query(`SELECT * FROM products ORDER BY ${column}`);
  res.json(rows);
});

app.post('/bulk', async (req, res) => {
  const ids = req.body.ids;
  const placeholders = ids.map(() => '?').join(', ');
  // ok: js-sqli-tainted, js-sqli-dynamic
  const [rows] = await connection.promise().query(`SELECT * FROM products WHERE id IN (${placeholders})`, ids);
  res.json(rows);
});

app.get('/by-email', (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  connection.query('SELECT * FROM users WHERE email = ' + connection.escape(req.query.email), (e, r) => res.json(r));
});

app.get('/pg-format', async (req, res) => {
  const sql = pgFormat('SELECT * FROM %I WHERE owner = %L', 'documents', req.query.owner);
  // ok: js-sqli-tainted
  const { rows } = await pool.query(sql);
  res.json(rows);
});

app.get('/notes/:id/safe', (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  const note = sqlite.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  res.json(note);
});

app.get('/slonik', async (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  const rows = await pool.query(sql`SELECT * FROM users WHERE email = ${req.query.email}`);
  res.json(rows);
});

app.get('/knex', async (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  const rows = await knex('users').whereRaw('lower(email) = lower(?)', [req.query.email]);
  res.json(rows);
});

app.get('/knex/where', async (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic, js-nosqli-tainted
  const users = await knex('users').where('email', req.query.email).first();
  res.json(users);
});

app.get('/proxy', async (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  const upstream = await superagent.get('https://api.example.com/v1/items').query(req.query);
  res.json(upstream.body);
});

app.get('/reports/by-name', async (req, res) => {
  // ok: js-sqli-tainted, js-sqli-dynamic
  const rows = await sequelize.query('SELECT * FROM reports WHERE name = :name', { replacements: { name: req.query.name } });
  res.json(rows);
});

// Data-access helpers: the caller is unknown, so only the structural rule applies.
async function findUserByEmail(email) {
  // ruleid: js-sqli-dynamic
  const [rows] = await connection.promise().query("SELECT * FROM users WHERE email = '" + email + "'");
  return rows[0];
}

function deleteSessions(userId, client) {
  const sql = util.format("DELETE FROM sessions WHERE user_id = '%s'", userId);
  // ruleid: js-sqli-dynamic
  return client.query(sql);
}

function countBy(table, column, value) {
  // ruleid: js-sqli-dynamic
  return knex.raw(['SELECT COUNT(*) FROM', table, 'WHERE', column, '= ?'].join(' '), [value]);
}

function searchNotes(owner, term) {
  // ruleid: js-sqli-dynamic
  return pool.query("SELECT * FROM notes WHERE owner = $1 AND body LIKE '%" + term + "%' AND deleted = " + owner.flag);
}

function orderBy(column, direction) {
  if (!/^[a-z_]+$/.test(column)) throw new Error('bad column');
  // validated with a regex first: the structural rule cannot see the check
  // todook: js-sqli-dynamic
  return pool.query(`SELECT * FROM products ORDER BY ${column} ${direction === 'desc' ? 'DESC' : 'ASC'}`);
}

function rawBody(maxKb) {
  // ok: js-sqli-dynamic
  return express.raw({ type: 'application/octet-stream', limit: maxKb + 'kb' });
}

function runQuery(sql, params) {
  // ok: js-sqli-dynamic
  return pool.query(sql, params);
}

const TABLE = 'users';
function byId(id) {
  // ok: js-sqli-dynamic
  return pool.query('SELECT * FROM ' + TABLE + ' WHERE id = $1', [id]);
}

function updateMany(ids, status) {
  const params = ids.map((_id, i) => `$${i + 2}`).join(', ');
  // ok: js-sqli-dynamic
  return pool.query(`UPDATE orders SET status = $1 WHERE id IN (${params})`, [status, ...ids]);
}

// =============================================================================
// OS command injection
// =============================================================================

app.get('/ping', (req, res) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  exec(`ping -c 1 ${req.query.host}`, (err, stdout) => res.send(stdout));
});

app.post('/convert', (req, res) => {
  const target = req.body.file;
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  runSync('convert ' + target + ' /tmp/out.png');
  res.sendStatus(204);
});

app.get('/git/log', async (req, res) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  const { stdout } = await execAsync(`git log --oneline ${req.query.branch}`);
  res.type('text').send(stdout);
});

app.get('/tool', (req, res) => {
  // ruleid: js-command-injection-tainted
  const child = spawn(req.query.tool, ['--version']);
  child.stdout.pipe(res);
});

app.get('/archive', (req, res) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  execFile('tar', ['-czf', '/tmp/a.tgz', req.query.dir], { shell: true }, () => res.sendStatus(200));
});

app.post('/hook', (req, res) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  cp.spawn('sh', ['-c', req.body.script]);
  res.sendStatus(202);
});

app.get('/du', (req, res) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  shell.exec('du -sh ' + req.query.path, { silent: true }, (code, out) => res.send(out));
});

router.post('/koa/lookup', async (ctx) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  ctx.body = cp.execSync(`nslookup ${ctx.request.body.domain}`).toString();
});

exports.thumbnail = async (event) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  cp.execSync(`convert ${event.queryStringParameters.src} -resize 64x64 /tmp/t.png`);
  return { statusCode: 204 };
};

app.get('/whois', (req, res) => {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  require('child_process').exec('whois ' + req.query.domain, (err, out) => res.send(out));
});

app.get('/grep', (req, res) => {
  const opts = { shell: true, cwd: '/srv/docs' };
  // shell option passed through a variable: not tracked
  // todoruleid: js-command-injection-tainted
  spawn('grep', ['-rn', req.query.term], opts).stdout.pipe(res);
});

app.get('/ls', (req, res) => {
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  const child = spawn('ls', ['-la', req.query.dir]);
  child.stdout.pipe(res);
});

app.get('/identify', (req, res) => {
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  execFile('identify', ['-format', '%wx%h', req.query.file], (err, out) => res.send(out));
});

app.get('/status', (req, res) => {
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  exec('git status --porcelain', { cwd: req.query.repo }, (err, out) => res.send(out));
});

app.get('/wc', (req, res) => {
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  exec('wc -l ' + shellescape([req.query.file]), (err, out) => res.send(out));
});

app.get('/git/sub', (req, res) => {
  const allowed = ['status', 'log', 'diff'];
  const sub = allowed.includes(req.query.sub) ? req.query.sub : 'status';
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  exec('git ' + sub, (err, out) => res.send(out));
});

app.get('/spawn/noshell', (req, res) => {
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  spawn('grep', ['-rn', req.query.term, '/srv/docs'], { shell: false }).stdout.pipe(res);
});

// Helpers with unknown callers: structural rule only.
function compressLogs(dir) {
  // ruleid: js-command-injection-dynamic
  return cp.execSync(`tar -czf logs.tgz ${dir}`);
}

function runUserHook(command) {
  // ruleid: js-command-injection-dynamic
  exec(command, { timeout: 5000 });
}

const restartService = (name) => {
  // ruleid: js-command-injection-dynamic
  spawn('systemctl restart ' + name, { shell: true });
};

function listLogs() {
  const DIR = '/var/log';
  // ok: js-command-injection-dynamic
  return cp.execSync('ls -la ' + DIR);
}

function build(target) {
  // ok: js-command-injection-dynamic
  return spawn('make', [target], { cwd: '/srv/app' });
}

function diskUsage() {
  // ok: js-command-injection-dynamic
  return runSync('df -h /');
}

// CLI entry point: process.argv is attacker-controlled only when another
// service builds the argument list, hence the low-confidence rule.
const cliArgs = process.argv.slice(2);
// ruleid: js-command-injection-argv, js-command-injection-dynamic
cp.execSync('npm install ' + process.argv[2], { stdio: 'inherit' });
// ruleid: js-command-injection-argv
spawn(cliArgs[0], cliArgs.slice(1), { stdio: 'inherit' });
// ruleid: js-command-injection-argv, js-command-injection-dynamic
exec(`git checkout ${cliArgs[1]}`);
// ok: js-command-injection-argv
spawn(process.execPath, [process.argv[1], '--worker'], { stdio: 'inherit' });
// ok: js-command-injection-argv
cp.fork(process.argv[1], ['--child']);
// ok: js-command-injection-argv
execFile('git', ['checkout', cliArgs[1]]);

// =============================================================================
// Code injection
// =============================================================================

const products = [];

app.post('/calc', (req, res) => {
  // ruleid: js-code-injection-tainted, js-code-injection-dynamic
  const result = eval(req.body.expression);
  res.json({ result });
});

app.get('/filter', (req, res) => {
  // ruleid: js-code-injection-tainted, js-code-injection-dynamic
  const predicate = new Function('item', 'return ' + req.query.expr);
  res.json(products.filter(predicate));
});

app.post('/sandbox', (req, res) => {
  const context = { result: null };
  // ruleid: js-code-injection-tainted, js-code-injection-dynamic
  vm.runInNewContext(req.body.code, context, { timeout: 100 });
  res.json(context);
});

app.post('/script', (req, res) => {
  // ruleid: js-code-injection-tainted, js-code-injection-dynamic
  const script = new vm.Script(`(function () { return ${req.body.fn}; })()`);
  res.json(script.runInThisContext());
});

app.get('/remind', (req, res) => {
  // ruleid: js-code-injection-tainted, js-code-injection-dynamic
  setTimeout('notify("' + req.query.msg + '")', 1000);
  res.sendStatus(202);
});

app.post('/parse', (req, res) => {
  // ok: js-code-injection-tainted, js-code-injection-dynamic
  const data = JSON.parse(req.body.payload);
  res.json(data);
});

app.get('/delay', (req, res) => {
  const ms = Number(req.query.ms);
  // ok: js-code-injection-tainted, js-code-injection-dynamic
  setTimeout(() => res.send('done'), ms);
});

app.get('/config', (req, res) => {
  // ok: js-code-injection-tainted, js-code-injection-dynamic
  const cfg = vm.runInNewContext('({ theme: "dark", pageSize: 20 })');
  res.json({ cfg, page: req.query.page });
});

app.get('/label', (req, res) => {
  // ok: js-code-injection-tainted, js-code-injection-dynamic
  const label = new Function('return ' + JSON.stringify(req.query.label))();
  res.send(label);
});

// ok: js-code-injection-tainted, js-code-injection-dynamic
const getGlobal = new Function('return this');

function debounce(fn, wait) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    // ok: js-code-injection-dynamic
    timer = setTimeout(fn, wait, ...args);
  };
}

function compileRule(expression) {
  // ruleid: js-code-injection-dynamic
  return eval('(' + expression + ')');
}

function makeGetter(propertyPath) {
  // ruleid: js-code-injection-dynamic
  return new Function('obj', `return obj.${propertyPath};`);
}

function schedule(taskName) {
  // ruleid: js-code-injection-dynamic
  setInterval('runTask("' + taskName + '")', 60000);
}

// =============================================================================
// NoSQL injection (MongoDB / Mongoose)
// =============================================================================

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  // ruleid: js-nosqli-tainted
  const user = await User.findOne({ username, password });
  if (!user) return res.sendStatus(401);
  return res.json({ id: user.id });
});

app.get('/api/users', async (req, res) => {
  // ruleid: js-nosqli-tainted
  const users = await User.find(req.query).limit(50);
  res.json(users);
});

app.post('/api/users/search', async (req, res) => {
  // ruleid: js-nosqli-tainted, js-nosqli-where-dynamic
  const users = await db.collection('users').find({ $where: "this.username.startsWith('" + req.body.prefix + "')" }).toArray();
  res.json(users);
});

app.delete('/api/sessions', async (req, res) => {
  // ruleid: js-nosqli-tainted
  await Session.deleteMany({ user: req.cookies.uid });
  res.sendStatus(204);
});

router.get('/koa/users', async (ctx) => {
  // ruleid: js-nosqli-tainted
  ctx.body = await User.find({ role: ctx.query.role });
});

app.post('/login/typed', async (req, res) => {
  if (typeof req.body.username !== 'string' || typeof req.body.password !== 'string') {
    return res.sendStatus(400);
  }
  // a typeof guard makes this safe, but taint tracking is not path-sensitive
  // todook: js-nosqli-tainted
  const user = await User.findOne({ username: req.body.username, password: req.body.password });
  return res.json({ ok: Boolean(user) });
});

app.post('/login/safe', async (req, res) => {
  // ok: js-nosqli-tainted
  const user = await User.findOne({ username: String(req.body.username), password: { $eq: req.body.password } });
  res.json({ ok: Boolean(user) });
});

app.get('/api/users/:id', async (req, res) => {
  // ok: js-nosqli-tainted
  const user = await User.findOne({ _id: req.params.id });
  res.json(user);
});

app.get('/api/products', async (req, res) => {
  // ok: js-nosqli-tainted
  const items = await Product.find({ price: { $lte: Number(req.query.max) } });
  res.json(items);
});

app.post('/api/clean', async (req, res) => {
  // ok: js-nosqli-tainted
  const user = await User.findOne(mongoSanitize(req.body));
  res.json(user);
});

app.get('/api/cart', (req, res) => {
  const cart = { items: [] };
  // ok: js-nosqli-tainted
  const item = cart.items.find((i) => i.sku === req.query.sku);
  res.json(item);
});

function findByExpression(expr) {
  // ruleid: js-nosqli-where-dynamic
  return User.find({ $where: expr });
}

function olderThan(age) {
  // ruleid: js-nosqli-where-dynamic
  return User.find().$where(`this.age > ${age}`);
}

function balanced() {
  // ok: js-nosqli-where-dynamic
  return User.find({ $where: 'this.credits > this.debits' });
}

function balancedFn() {
  // ok: js-nosqli-where-dynamic
  return User.find({ $where: function () { return this.credits > this.debits; } });
}

function balancedExpr() {
  // ok: js-nosqli-where-dynamic
  return User.find({ $expr: { $gt: ['$credits', '$debits'] } });
}

// =============================================================================
// Server-side template injection
// =============================================================================

app.get('/greet', (req, res) => {
  // ruleid: js-ssti-tainted, js-ssti-dynamic
  res.send(ejs.render('<h1>Hello ' + req.query.name + '</h1>'));
});

app.post('/preview', (req, res) => {
  // ruleid: js-ssti-tainted
  const fn = pug.compile(req.body.template);
  res.send(fn({ user: req.user }));
});

app.post('/email/preview', (req, res) => {
  // ruleid: js-ssti-tainted
  const tpl = Handlebars.compile(req.body.source);
  res.send(tpl({}));
});

app.get('/banner', (req, res) => {
  // ruleid: js-ssti-tainted, js-ssti-dynamic
  res.send(nunjucks.renderString(`<div class="banner">${req.query.text}</div>`, {}));
});

app.get('/lodash', (req, res) => {
  // ruleid: js-ssti-tainted
  const compiled = _.template(req.query.tpl);
  res.send(compiled({ user: 'guest' }));
});

app.get('/greet/safe', (req, res) => {
  // ok: js-ssti-tainted, js-ssti-dynamic
  res.send(ejs.render('<h1>Hello <%= name %></h1>', { name: req.query.name }));
});

app.get('/dashboard', (req, res) => {
  // whole request object as view locals lets an attacker set engine options
  // (ejs outputFunctionName, CVE-2022-29078); needs a dedicated sink model
  // todoruleid: js-ssti-tainted
  res.render('dashboard', req.query);
});

app.get('/profile', (req, res) => {
  // ok: js-ssti-tainted, js-ssti-dynamic
  res.render('profile', { user: req.query.user });
});

app.get('/page/:slug', (req, res) => {
  const source = fs.readFileSync(path.join(__dirname, 'views', 'page.pug'), 'utf8');
  // ok: js-ssti-tainted, js-ssti-dynamic
  res.send(pug.render(source, { slug: req.params.slug }));
});

app.get('/docs', (req, res) => {
  // nunjucks.render() takes a template file name, not template source
  // ok: js-ssti-tainted, js-ssti-dynamic
  res.send(nunjucks.render(req.query.page + '.njk', { q: req.query.q }));
});

function renderWelcome(user) {
  // ruleid: js-ssti-dynamic
  return ejs.render(`<p>Welcome back, ${user.displayName}!</p>`);
}

function buildEmail(subject, body) {
  const source = '<h2>' + subject + '</h2><div>{{body}}</div>';
  // ruleid: js-ssti-dynamic
  return Handlebars.compile(source)({ body });
}

function renderFooter(year) {
  // ok: js-ssti-dynamic
  return ejs.render('<footer>&copy; <%= year %></footer>', { year });
}

// =============================================================================
// Insecure deserialization
// =============================================================================

app.post('/session/restore', (req, res) => {
  // ruleid: js-insecure-deserialization-tainted, js-insecure-deserialization
  const session = serialize.unserialize(req.cookies.session);
  res.json(session);
});

app.post('/import', (req, res) => {
  const payload = Buffer.from(req.body.data, 'base64').toString();
  // ruleid: js-insecure-deserialization-tainted, js-insecure-deserialization
  const obj = funcster.deepDeserialize(JSON.parse(payload));
  res.json(obj);
});

app.post('/session/restore/safe', (req, res) => {
  // ok: js-insecure-deserialization-tainted, js-insecure-deserialization
  const session = JSON.parse(req.cookies.session);
  res.json(session);
});

app.get('/session/export', (req, res) => {
  // ok: js-insecure-deserialization-tainted, js-insecure-deserialization
  res.send(serialize.serialize({ user: req.query.user }));
});

app.post('/legacy/php', (req, res) => {
  // ok: js-insecure-deserialization-tainted, js-insecure-deserialization
  res.json(phpUnserialize(req.body.data));
});

function loadCache(raw) {
  // ruleid: js-insecure-deserialization
  return serialize.unserialize(raw);
}

// ok: js-insecure-deserialization
const DEFAULTS = serialize.unserialize('{"theme":"dark"}');

module.exports = { app, router, fastify, hapiRoute, getGlobal, debounce, DEFAULTS };

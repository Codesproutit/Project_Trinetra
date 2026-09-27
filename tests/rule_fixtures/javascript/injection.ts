// Trinetra rule fixture: TypeScript injection rules (rules/javascript/injection.yaml).
// Minimal vulnerable snippets for authorized rule testing, not production code.
// Covers NestJS, Next.js (app router and pages API), TypeORM, Prisma and ES imports.
import { Body, Controller, Get, Param, ParseIntPipe, Post, Query } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { DataSource, Repository, Brackets } from 'typeorm';
import { CommandBus } from '@nestjs/cqrs';
import type { Pool } from 'mysql2/promise';
import { PrismaClient } from '@prisma/client';
import { NextRequest, NextResponse } from 'next/server';
import type { NextApiRequest, NextApiResponse } from 'next';
import { exec as run, execFile, spawnSync } from 'node:child_process';
import * as childProcess from 'child_process';
import cp = require('child_process');
import cpDefault from 'child_process';
import { promisify } from 'util';
import * as vm from 'node:vm';
import { Script } from 'node:vm';
import postgres from 'postgres';
import ejs from 'ejs';
import * as Handlebars from 'handlebars';
import nunjucks from 'nunjucks';
import template from 'lodash/template';
import { readFileSync } from 'fs';
import { Model } from 'mongoose';
import serializeJs from 'serialize-to-js';
import { unserialize } from 'node-serialize';
import sanitize from 'mongo-sanitize';

interface User { id: number; email: string; name: string; city: string }
interface FilterDto { city: string; status: string }
interface LoginDto { email: string; password: string }
class CreateUserCommand { constructor(readonly name: string, readonly email: string) {} }

const prisma = new PrismaClient();
const sql = postgres(process.env.DATABASE_URL ?? '');
const execP = promisify(run);

// =============================================================================
// NestJS controller: SQL (TypeORM) and NoSQL (Mongoose)
// =============================================================================

@Controller('users')
export class UsersController {
  constructor(
    private readonly dataSource: DataSource,
    private readonly users: Repository<User>,
    @InjectModel('User') private readonly userModel: Model<User>,
    private readonly commandBus: CommandBus,
    private readonly pool: Pool,
  ) {}

  @Post()
  async create(@Body() dto: LoginDto) {
    // ok: js-sqli-tainted
    return this.commandBus.execute(new CreateUserCommand(dto.email, dto.email));
  }

  @Get('by-city')
  async byCity(@Query('city') city: string) {
    // ruleid: js-sqli-tainted, js-sqli-dynamic
    const [rows] = await this.pool.execute(`SELECT * FROM users WHERE city = '${city}'`);
    return rows;
  }

  @Get('by-city-safe')
  async byCitySafe(@Query('city') city: string) {
    // ok: js-sqli-tainted, js-sqli-dynamic
    const [rows] = await this.pool.execute('SELECT * FROM users WHERE city = ?', [city]);
    return rows;
  }

  @Post('find-typeorm')
  async findTypeorm(@Body() dto: LoginDto) {
    // ok: js-nosqli-tainted, js-sqli-tainted
    return this.users.findOne({ where: { email: dto.email } });
  }

  @Get('search')
  async search(@Query('q') q: string) {
    // ruleid: js-sqli-tainted, js-sqli-dynamic
    return this.dataSource.query(`SELECT * FROM users WHERE name ILIKE '%${q}%'`);
  }

  @Get('sorted')
  async sorted(@Query('sort') sort: string) {
    // ruleid: js-sqli-tainted, js-sqli-dynamic
    return this.users.createQueryBuilder('u').where('u.active = :active', { active: true }).orderBy(`u.${sort}`, 'ASC').getMany();
  }

  @Post('filter')
  async filter(@Body() dto: FilterDto) {
    const qb = this.users.createQueryBuilder('u');
    // ruleid: js-sqli-tainted, js-sqli-dynamic
    qb.andWhere("u.city = '" + dto.city + "'");
    return qb.getMany();
  }

  @Get(':id')
  async findOne(@Param('id', ParseIntPipe) id: number) {
    // ok: js-sqli-tainted, js-sqli-dynamic
    return this.dataSource.query(`SELECT * FROM users WHERE id = ${id}`);
  }

  @Get('by-email')
  async byEmail(@Query('email') email: string) {
    // ok: js-sqli-tainted, js-sqli-dynamic
    return this.users.createQueryBuilder('u').where('u.email = :email', { email }).getOne();
  }

  @Post('filter-safe')
  async filterSafe(@Body() dto: FilterDto) {
    const qb = this.users.createQueryBuilder('u');
    // ok: js-sqli-tainted, js-sqli-dynamic
    qb.where(new Brackets((w) => w.where('u.city = :city', { city: dto.city }).orWhere('u.status = :status', { status: dto.status })));
    return qb.getMany();
  }

  @Post('login')
  async login(@Body() body: LoginDto) {
    // ruleid: js-nosqli-tainted
    return this.userModel.findOne({ email: body.email, password: body.password });
  }

  @Get('list')
  async list(@Query() query: Record<string, unknown>) {
    // ruleid: js-nosqli-tainted
    return this.userModel.find(query).limit(20);
  }

  @Post('login-safe')
  async loginSafe(@Body() body: LoginDto) {
    // ok: js-nosqli-tainted
    return this.userModel.findOne({ email: { $eq: body.email }, password: { $eq: body.password } });
  }

  @Get('profile/:id')
  async profile(@Param('id') id: string) {
    // ok: js-nosqli-tainted
    return this.userModel.findOne({ _id: id });
  }

  @Get('clean')
  async clean(@Query() query: Record<string, unknown>) {
    // ok: js-nosqli-tainted
    return this.userModel.find(sanitize(query));
  }
}

// =============================================================================
// Next.js app router: SQL (Prisma), code and template injection
// =============================================================================

export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('name');
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM "User" WHERE name = '${name}'`);
  return NextResponse.json(rows);
}

export async function OPTIONS(request: NextRequest, { params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM "Post" WHERE slug = '${slug}'`);
  return NextResponse.json(rows);
}

export async function handleSearch(request: NextRequest) {
  const term = request.nextUrl.searchParams.get('term');
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  const rows = await sql.unsafe(`SELECT * FROM articles WHERE title ILIKE '%${term}%'`);
  return NextResponse.json(rows);
}

export async function handleSearchSafe(request: NextRequest) {
  const term = request.nextUrl.searchParams.get('term');
  // ok: js-sqli-tainted, js-sqli-dynamic
  const rows = await sql`SELECT * FROM articles WHERE title ILIKE ${'%' + term + '%'}`;
  return NextResponse.json(rows);
}

export async function POST(request: Request) {
  const { email } = await request.json();
  // ok: js-sqli-tainted, js-sqli-dynamic
  const rows = await prisma.$queryRaw`SELECT * FROM "User" WHERE email = ${email}`;
  return Response.json(rows);
}

export async function DELETE(request: NextRequest) {
  const id = request.nextUrl.searchParams.get('id');
  // ok: js-sqli-tainted, js-sqli-dynamic
  await prisma.$executeRawUnsafe('DELETE FROM "Session" WHERE id = $1', id);
  return new Response(null, { status: 204 });
}

export async function PUT(request: NextRequest) {
  const { formula } = await request.json();
  // ruleid: js-code-injection-tainted, js-code-injection-dynamic
  const value = vm.runInNewContext(formula, { Math });
  return NextResponse.json({ value });
}

export async function PATCH(request: NextRequest) {
  const body = await request.json();
  // ruleid: js-ssti-tainted
  const html = template(body.layout)({ user: body.user });
  // ruleid: js-ssti-tainted, js-ssti-dynamic
  const block = nunjucks.renderString('{% extends "base.njk" %}' + body.block, {});
  return new NextResponse(html + block);
}

export async function HEAD(request: NextRequest) {
  const tenant = request.headers.get('x-tenant');
  // ruleid: js-sqli-tainted, js-sqli-dynamic
  await prisma.$executeRawUnsafe('SET search_path TO ' + tenant);
  return new Response(null, { status: 200 });
}

// =============================================================================
// Next.js pages API: OS command injection
// =============================================================================

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  const { stdout } = await execP(`dig +short ${req.query.domain}`);
  res.status(200).send(stdout);
}

export function lookupHost(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  run('nslookup ' + req.query.host, (err, out) => res.send(out));
}

export function thumbnail(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  const r = spawnSync('convert', [String(req.query.src), 'thumb.png'], { shell: '/bin/bash' });
  res.send(r.stdout);
}

export function version(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-command-injection-tainted
  execFile(req.query.bin as string, ['--version'], (e, out) => res.send(out));
}

export function traceroute(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-command-injection-tainted, js-command-injection-dynamic
  cpDefault.exec(`traceroute ${req.query.target}`, (e, out) => res.send(out));
}

export function gitShow(req: NextApiRequest, res: NextApiResponse) {
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  execFile('git', ['show', '--stat', String(req.query.sha)], (e, out) => res.send(out));
}

export function sequence(req: NextApiRequest, res: NextApiResponse) {
  const n: number = Number(req.query.n);
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  childProcess.exec(`seq 1 ${n}`, (e, out) => res.send(out));
}

export function uptime(req: NextApiRequest, res: NextApiResponse) {
  // ok: js-command-injection-tainted, js-command-injection-dynamic
  cp.exec('uptime', { env: { LANG: String(req.query.lang) } }, (e, out) => res.send(out));
}

// Helpers with unknown callers: structural rules only.
export function backup(dbName: string): void {
  // ruleid: js-command-injection-dynamic
  cp.execSync(`pg_dump ${dbName} > /backups/nightly.sql`);
}

export function purge(days: number): void {
  // ok: js-command-injection-dynamic
  cp.execSync(`find /tmp/uploads -mtime +${days} -delete`);
}

// ruleid: js-command-injection-argv
childProcess.execSync(process.argv[3]);

// =============================================================================
// NestJS: code, template and deserialization
// =============================================================================

@Controller('rules')
export class RulesController {
  @Post('evaluate')
  evaluate(@Body('expr') expr: string) {
    // ruleid: js-code-injection-tainted, js-code-injection-dynamic
    return eval(expr);
  }

  @Post('evaluate-safe')
  evaluateSafe(@Body('value') value: string) {
    // ok: js-code-injection-tainted, js-code-injection-dynamic
    return new Function('return ' + JSON.stringify(value))();
  }

  @Post('render')
  render(@Body('template') tpl: string, @Body('data') data: Record<string, unknown>) {
    // ruleid: js-ssti-tainted
    return ejs.render(tpl, data);
  }

  @Post('render-safe')
  renderSafe(@Body('name') name: string) {
    // ok: js-ssti-tainted, js-ssti-dynamic
    return ejs.render('<p>Hello <%= name %></p>', { name });
  }

  @Get('invoice')
  invoice(@Query('customer') customer: string) {
    const source = readFileSync('/srv/templates/invoice.hbs', 'utf8');
    // ok: js-ssti-tainted, js-ssti-dynamic
    return Handlebars.compile(source)({ customer });
  }

  @Post('restore')
  restore(@Body('state') state: string) {
    // ruleid: js-insecure-deserialization-tainted, js-insecure-deserialization
    return unserialize(state);
  }

  @Post('restore-safe')
  restoreSafe(@Body('state') state: string) {
    // ok: js-insecure-deserialization-tainted, js-insecure-deserialization
    return JSON.parse(state);
  }
}

export function restorePrefs(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-insecure-deserialization-tainted, js-insecure-deserialization
  const prefs = serializeJs.deserialize(req.cookies.prefs as string);
  res.json(prefs);
}

export function exportPrefs(req: NextApiRequest, res: NextApiResponse) {
  // ok: js-insecure-deserialization-tainted, js-insecure-deserialization
  res.send(serializeJs.serialize({ theme: req.query.theme }));
}

// Structural cases with typed parameters.
export function compileFormula(formula: string): number {
  // ruleid: js-code-injection-dynamic
  return new Function('x', `return ${formula};`)(1);
}

export function runPlugin(source: string, sandbox: Record<string, unknown>) {
  // ruleid: js-code-injection-dynamic
  return new Script(source, { filename: 'plugin.js' }).runInNewContext(sandbox);
}

export function formatTotal(total: number): string {
  // ok: js-code-injection-dynamic
  return eval(`(${total}).toFixed(2)`);
}

export function greeting(user: User): string {
  // ruleid: js-ssti-dynamic
  return ejs.render('<p>Hi ' + user.name + ', you have <%= count %> messages</p>', { count: 3 });
}

export function badge(level: number): string {
  // ok: js-ssti-dynamic
  return ejs.render(`<span class="lvl-${level}"><%= label %></span>`, { label: 'Gold' });
}

export function whereClause(expr: string) {
  // ruleid: js-nosqli-where-dynamic
  return { $where: `function () { return ${expr}; }` };
}

export function readCache(raw: Buffer) {
  // ruleid: js-insecure-deserialization
  return unserialize(raw.toString('utf8'));
}

export function findLegacy(dataSource: DataSource, email: string) {
  // ruleid: js-sqli-dynamic
  return dataSource.query("SELECT * FROM users WHERE email = '" + email + "'");
}

export function findLegacySafe(dataSource: DataSource, email: string) {
  // ok: js-sqli-dynamic
  return dataSource.query('SELECT * FROM users WHERE email = $1', [email]);
}

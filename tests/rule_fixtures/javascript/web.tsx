// Rule fixture for trinetra/brains/static/rules/javascript/web.yaml (TypeScript / React / Next.js / NestJS)
// Minimal vulnerable and safe snippets for rule tests only. Not a working application.
import React, { Component, useEffect, useRef } from 'react';
import { useRouter } from 'next/router';
import { redirect, useSearchParams } from 'next/navigation';
import { NextRequest, NextResponse } from 'next/server';
import type { NextApiRequest, NextApiResponse } from 'next';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { join } from 'path';
import DOMPurify from 'dompurify';
import nodeFetch from 'node-fetch';
import ax from 'axios';
import { merge } from 'lodash';
import { marked } from 'marked';
import escapeHtml from 'escape-html';
import { Body, Controller, Get, Param, Post, Query, Res } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { HttpService } from '@nestjs/axios';
import type { Response } from 'express';

const API_BASE = 'https://api.example.com/v2';
const POSTS_DIR = path.join(process.cwd(), 'posts');
const UPLOADS = '/srv/uploads';
const ALLOWED_ORIGINS = ['https://app.example.com'];
const DEFAULT_PREFS = { theme: 'light', pageSize: 20 };
const ICON_SVG = '<svg viewBox="0 0 10 10"><circle cx="5" cy="5" r="4"/></svg>';
const CHANGELOG_MD = '# Changelog\n\n- first release';

type PageProps = { searchParams: { q?: string; next?: string } };
type MarkdownProps = { html: string };
type PreviewProps = { markdown: string };
type TitleProps = { text: string };

// ===========================================================================
// Next.js pages API routes
// ===========================================================================

export function helloHandler(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-xss-reflected-tainted
  res.status(200).send(`<div>Hello ${req.query.name}</div>`);
}

export function helloJsonHandler(req: NextApiRequest, res: NextApiResponse) {
  // ok: js-xss-reflected-tainted
  res.status(200).json({ greeting: `Hello ${req.query.name}` });
}

export async function webhookHandler(req: NextApiRequest, res: NextApiResponse) {
  const callback: string = req.body.callbackUrl;
  // ruleid: js-ssrf-tainted
  await nodeFetch(callback, { method: 'POST', body: JSON.stringify({ ok: true }) });
  // ruleid: js-ssrf-tainted
  await ax.post(req.body.webhook, { event: 'test' });
  // ok: js-ssrf-tainted
  const rates = await ax.get('https://api.example.com/rates');
  res.status(200).json(rates.data);
}

export function returnHandler(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-open-redirect-tainted
  res.redirect(307, req.query.returnTo as string);
}

export function orderHandler(req: NextApiRequest, res: NextApiResponse) {
  // ok: js-open-redirect-tainted
  res.redirect(307, `/orders/${req.query.id}`);
}

export function corsHandler(req: NextApiRequest, res: NextApiResponse) {
  // ruleid: js-cors-header-origin-reflection
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin ?? '*');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.status(200).json({ ok: true });
}

// ===========================================================================
// Next.js App Router route handlers, middleware and server components
// ===========================================================================

export async function GET(request: NextRequest) {
  const target = request.nextUrl.searchParams.get('url');
  // ruleid: js-ssrf-tainted
  const upstream = await fetch(target!);
  return new Response(upstream.body);
}

export async function searchRoute(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  // ok: js-ssrf-tainted
  const r = await fetch(`${API_BASE}/search?q=${encodeURIComponent(q)}`);
  return NextResponse.json(await r.json());
}

export async function contentRoute(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('file');
  // ruleid: js-path-traversal-tainted
  const body = await readFile(path.join(process.cwd(), 'content', name ?? ''), 'utf8');
  // ok: js-path-traversal-tainted
  const about = await readFile(path.join(process.cwd(), 'content', 'about.md'), 'utf8');
  return NextResponse.json({ body, about });
}

export function middleware(request: NextRequest) {
  if (request.nextUrl.pathname.startsWith('/login/done')) {
    // ruleid: js-open-redirect-tainted
    return NextResponse.redirect(new URL(request.nextUrl.searchParams.get('callbackUrl') ?? '/', request.url));
  }
  if (!request.cookies.get('session')) {
    // ok: js-open-redirect-tainted
    return NextResponse.redirect(new URL('/login', request.url));
  }
  const response = NextResponse.next();
  const origin = request.headers.get('origin');
  // ruleid: js-cors-header-origin-reflection
  response.headers.set('Access-Control-Allow-Origin', origin ?? '*');
  response.headers.set('Access-Control-Allow-Credentials', 'true');
  return response;
}

export function apiCors(request: NextRequest) {
  const origin = request.headers.get('origin');
  const response = NextResponse.next();
  if (origin && ALLOWED_ORIGINS.includes(origin)) {
    // ok: js-cors-header-origin-reflection
    response.headers.set('Access-Control-Allow-Origin', origin);
    response.headers.set('Access-Control-Allow-Credentials', 'true');
  }
  return response;
}

export function publicCors() {
  // ok: js-cors-header-origin-reflection
  return NextResponse.json({ ok: true }, { headers: { 'Access-Control-Allow-Origin': '*' } });
}

export function LoginDone({ searchParams }: PageProps) {
  // ruleid: js-open-redirect-tainted, js-open-redirect-dynamic-url
  redirect(searchParams.next ?? '/');
}

export function OrderDone({ searchParams }: PageProps) {
  // ok: js-open-redirect-tainted, js-open-redirect-dynamic-url
  redirect(`/orders?highlight=${encodeURIComponent(searchParams.q ?? '')}`);
}

// ===========================================================================
// Server helpers (caller-supplied values)
// ===========================================================================

export function renderRow(res: Response, label: string): void {
  // ruleid: js-xss-reflected-dynamic-html
  res.write(`<tr><td>${label}</td></tr>`);
}

export function renderRowSafe(res: Response, label: string): void {
  // ok: js-xss-reflected-dynamic-html
  res.write(`<tr><td>${escapeHtml(label)}</td></tr>`);
}

export async function getTenantConfig(tenant: string) {
  // ruleid: js-ssrf-dynamic-host
  return ax.get(`https://${tenant}.internal.example.com/config`);
}

export async function getRates(currency: string) {
  // ok: js-ssrf-dynamic-host
  return ax.get(`https://api.example.com/rates/${currency}`);
}

export async function loadPost(slug: string): Promise<string> {
  // ruleid: js-path-traversal-dynamic-path
  return readFile(path.join(POSTS_DIR, `${slug}.md`), 'utf8');
}

export async function loadPostSafe(slug: string): Promise<string> {
  // ok: js-path-traversal-dynamic-path
  return readFile(path.join(POSTS_DIR, `${path.basename(slug)}.md`), 'utf8');
}

export function toOrders(res: NextApiResponse, orderId: string) {
  // ok: js-open-redirect-dynamic-url
  res.redirect(`/orders/${orderId}`);
}

export function deepMerge<T extends Record<string, any>>(target: T, source: Partial<T>): T {
  for (const key in source) {
    const value = source[key];
    if (value && typeof value === 'object') {
      deepMerge(target[key], value as any);
    } else {
      // ruleid: js-prototype-pollution-recursive-merge
      target[key] = value as any;
    }
  }
  return target;
}

export function deepMergeGuarded<T extends Record<string, any>>(target: T, source: Partial<T>): T {
  for (const key in source) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
      continue;
    }
    const value = source[key];
    if (value && typeof value === 'object') {
      deepMergeGuarded(target[key], value as any);
    } else {
      // ok: js-prototype-pollution-recursive-merge
      target[key] = value as any;
    }
  }
  return target;
}

// ===========================================================================
// NestJS
// ===========================================================================

@Controller('search')
export class SearchController {
  private prefs: Record<string, unknown> = {};

  constructor(private readonly httpService: HttpService) {}

  @Get()
  search(@Query('q') q: string, @Res() res: Response) {
    // ruleid: js-xss-reflected-tainted, js-xss-reflected-dynamic-html
    res.send(`<p>Results for ${q}</p>`);
  }

  @Get('safe')
  searchSafe(@Query('q') q: string, @Res() res: Response) {
    // ok: js-xss-reflected-tainted, js-xss-reflected-dynamic-html
    res.send(`<p>Results for ${escapeHtml(q)}</p>`);
  }

  @Get('proxy')
  proxy(@Query('url') url: string) {
    // ruleid: js-ssrf-tainted
    return this.httpService.get(url);
  }

  @Get('files/:name')
  getFile(@Param('name') name: string, @Res() res: Response) {
    // ruleid: js-path-traversal-tainted, js-path-traversal-dynamic-path
    return res.sendFile(join(UPLOADS, name));
  }

  @Get('static/:name')
  getStatic(@Param('name') name: string, @Res() res: Response) {
    // ok: js-path-traversal-tainted, js-path-traversal-dynamic-path
    return res.sendFile(name, { root: UPLOADS });
  }

  @Post('prefs')
  updatePrefs(@Body() body: Record<string, unknown>) {
    // ruleid: js-prototype-pollution-tainted
    merge(this.prefs, body);
    return this.prefs;
  }

  @Post('prefs/reset')
  resetPrefs() {
    // ok: js-prototype-pollution-tainted
    merge(this.prefs, DEFAULT_PREFS);
    return this.prefs;
  }
}

export async function bootstrap() {
  const app = await NestFactory.create(SearchController);
  // ruleid: js-cors-credentials-any-origin
  app.enableCors({ origin: true, credentials: true });
  // ok: js-cors-credentials-any-origin
  app.enableCors({ origin: ALLOWED_ORIGINS, credentials: true });
  await app.listen(3000);
}

// ===========================================================================
// React components: DOM XSS
// ===========================================================================

export function Message() {
  const searchParams = useSearchParams();
  // ruleid: js-dom-xss-tainted
  const unsafe = <div dangerouslySetInnerHTML={{ __html: searchParams.get('message') ?? '' }} />;
  // ok: js-dom-xss-tainted
  const text = <p>{searchParams.get('message')}</p>;
  // ok: js-dom-xss-tainted
  const clean = <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(searchParams.get('bio') ?? '') }} />;
  return <div>{unsafe}{text}{clean}</div>;
}

export function PageContent() {
  const router = useRouter();
  const content = router.query.content as string;
  return (
    // ruleid: js-dom-xss-tainted
    <article dangerouslySetInnerHTML={{ __html: content }} />
  );
}

export default function SearchPage({ searchParams }: PageProps) {
  return (
    // ruleid: js-dom-xss-tainted, js-dom-xss-dynamic-html
    <div dangerouslySetInnerHTML={{ __html: `Results for ${searchParams.q}` }} />
  );
}

export function HashBanner() {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    // ruleid: js-dom-xss-tainted
    ref.current!.innerHTML = decodeURIComponent(window.location.hash.slice(1));
  }, []);
  return <div ref={ref} />;
}

export function Changelog() {
  // ok: js-dom-xss-tainted, js-dom-xss-dynamic-html
  return <div dangerouslySetInnerHTML={{ __html: marked.parse(CHANGELOG_MD) as string }} />;
}

export function EmbeddedWidget() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      // ruleid: js-dom-xss-tainted
      box.current!.innerHTML = event.data.html;
    };
    // ruleid: js-postmessage-missing-origin-check
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, []);
  return <div ref={box} />;
}

export function TrustedWidget() {
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const onMessage = (event: MessageEvent) => {
      if (event.origin !== 'https://widgets.example.com') {
        return;
      }
      // ok: js-dom-xss-tainted
      box.current!.innerHTML = event.data.html;
    };
    // ok: js-postmessage-missing-origin-check
    window.addEventListener('message', onMessage);
    return () => window.removeEventListener('message', onMessage);
  }, []);
  return <div ref={box} />;
}

// ===========================================================================
// React components: raw HTML from props (js-dom-xss-dynamic-html)
// ===========================================================================

export function Markdown({ html }: MarkdownProps) {
  // ruleid: js-dom-xss-dynamic-html
  return <div className="md" dangerouslySetInnerHTML={{ __html: html }} />;
}

export const Preview = (props: PreviewProps) => (
  // ruleid: js-dom-xss-dynamic-html
  <div dangerouslySetInnerHTML={{ __html: marked.parse(props.markdown) as string }} />
);

export class LegacyNotice extends Component<{ content: string }> {
  render() {
    // ruleid: js-dom-xss-dynamic-html
    return <section dangerouslySetInnerHTML={{ __html: this.props.content }} />;
  }
}

export function Title({ text }: TitleProps) {
  // ok: js-dom-xss-dynamic-html
  return <h1>{text}</h1>;
}

export const SafeMarkdown = ({ html }: MarkdownProps) => (
  // ok: js-dom-xss-dynamic-html
  <div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />
);

export const Icon = () => (
  // ok: js-dom-xss-dynamic-html
  <span dangerouslySetInnerHTML={{ __html: ICON_SVG }} />
);

// ===========================================================================
// React components: navigation (js-dom-javascript-url-tainted)
// ===========================================================================

export function AfterLogin() {
  const router = useRouter();
  useEffect(() => {
    // ruleid: js-dom-javascript-url-tainted
    router.push(router.query.returnUrl as string);
  }, [router]);
  return null;
}

export function ExternalRedirect() {
  const searchParams = useSearchParams();
  useEffect(() => {
    // ruleid: js-dom-javascript-url-tainted
    window.location.href = searchParams.get('redirect') ?? '/';
  }, [searchParams]);
  return null;
}

export function OrderLink() {
  const router = useRouter();
  useEffect(() => {
    // ok: js-dom-javascript-url-tainted
    router.push(`/orders/${router.query.id}`);
  }, [router]);
  return null;
}

export function GoHome() {
  useEffect(() => {
    // ok: js-dom-javascript-url-tainted
    window.location.href = '/';
  }, []);
  return null;
}

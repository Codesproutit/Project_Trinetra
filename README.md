# Project Trinetra

A deterministic-first, AI-augmented, self-evolving application security testing platform.

Trinetra runs proven open-source engines first, sends only what they can't settle to an AI
cognitive pass, and grows a per-discipline rule brain over time. It targets **API, Web, and
Android** first (Desktop, Infra, and iOS are planned). Modes: black-, grey-, and white-box.

> ⚠️ **Authorized testing only.** Trinetra is for security testing you are authorized to
> perform. Every scan is gated by a signed scope manifest, enforced in code.

## What's in this release (Phase 1 MVP)

This is the first working slice — the foundation plus a runnable SAST + SCA scan:

- **Scope & authorization gate** — a signed manifest bounds every scan; a rate limiter caps
  request volume. Enforced in code, not by discipline.
- **Common `Finding` schema** — the contract every engine and the AI layer speak, with a
  stable fingerprint for strict dedup.
- **SAST** — Semgrep adapter (wraps `semgrep --sarif`, normalizes to `Finding`).
- **SCA** — dependency manifest parsing + OSV.dev vulnerability lookup (NVD + GitHub Advisory).
- **Reporting** — SARIF 2.1.0 output, ready for GitHub code scanning.
- **BYOK provider layer** — the Anthropic (Claude) adapter behind a generic interface;
  OpenAI/Gemini/local plug in next. (The AI cognitive pass itself lands in a later phase.)

## What's new (Phase 2 — DAST core)

Dynamic scanning of a running target, feeding the same `Finding` schema, dedup, and SARIF:

- **DAST** — OWASP ZAP adapter (spider → active scan → alerts over the ZAP REST API) and a
  Nuclei adapter (template checks, JSONL output). Both are `input_kind="target"` engines.
- **OAST** — an out-of-band listener that mints a unique callback host per injection point and
  correlates received DNS/HTTP callbacks into **confirmed** blind-vuln findings (blind
  SSRF/RCE/SQLi, CWE-918). Pluggable backend; a null backend keeps it inert when no interaction
  server is configured.
- **`--target <url>` mode** — the orchestrator routes by `input_kind`, so a URL scan runs only
  the dynamic engines (and never a SAST engine), and a source scan never touches the network.
- **Graceful degradation** — if the ZAP daemon or the `nuclei` binary isn't present, that engine
  reports *skipped* instead of crashing the run.
- **Deny-by-default for network targets** — a `--target` scan is refused unless you pass
  `--scope` pointing at a signed engagement manifest.

Later phases add the IAST bridge, the AI cognitive pass, the Android track, and the
self-evolving learner with a Docker validation gate.

## What's new (Phase 3 — IAST bridge)

The bridge fuses the static and dynamic layers, so a code-level candidate and runtime proof
land in **one** finding:

- **Verification queue** — every injectable static sink (SQLi, command injection, SSRF, XXE,
  code injection, XSS…) becomes a prioritized task for the dynamic scan, tagged with the
  vulnerability class to probe.
- **Out-of-band hooks** — blind classes (SSRF, blind RCE/SQLi) get an OAST callback minted per
  sink, so an out-of-band hit ties straight back to the exact code location.
- **Confirmation** — after the dynamic scan runs, a static candidate whose class the scan
  confirmed is upgraded from *theoretical* to **confirmed**, with the dynamic evidence attached.
  That is the IAST result: reachable, exploitable, and pinned to a line of code.
- **Grey-box run** — pass both `--path` and `--target` to run SAST, then DAST, then the
  correlation in one pass. Source-only and target-only modes are unchanged.

Later phases add the AI cognitive pass, the Android track, and the self-evolving learner with a
Docker validation gate.

## Prerequisites

- **Python 3.12+**
- **Docker + Compose** — later phases pull pinned engine images; Phase 1's Semgrep can also run
  from a local `pip install semgrep`.
- **An LLM API key** — BYOK, entered at pre-flight. Not needed for the Phase 1 deterministic scan.

## Quickstart

```bash
pip install -e ".[dev]"

# Scan the bundled deliberately-vulnerable sample:
python -m trinetra scan --path examples/vulnerable-python --discipline web

# Enforce a signed scope manifest:
python -m trinetra scan --path ./target --scope examples/scope.example.yaml

# DAST: scan a running target you are authorized to test (requires --scope):
python -m trinetra scan --target http://localhost:3000 --scope examples/scope.example.yaml

# IAST (grey-box): SAST + DAST in one pass, correlating static sinks with runtime proof:
python -m trinetra scan --path ./target --target http://localhost:3000 \
    --scope examples/scope.example.yaml
```

DAST engines (ZAP, Nuclei) run against a live URL, so they need the pinned engine
container/daemon present; without it they report *skipped*. Point `--target` only at systems
your scope manifest authorizes.

The scan writes a SARIF report and a `findings.json` under `.trinetra/runs/<timestamp>/`.

Copy `.env.example` to `.env` for your API key. **Never commit `.env` or any real key** — this
is a public repo and `.gitignore` already excludes secrets and scan output.

## Development

```bash
ruff check .
pytest
```

Tests are hermetic — no network or external binaries required (engine output and the OSV lookup
are exercised through fixtures and an injected HTTP client).

## License

Apache-2.0. Wrapped engines keep their own licenses; see each adapter.

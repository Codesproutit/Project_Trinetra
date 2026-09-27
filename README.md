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

Later phases add the DAST core (ZAP/Nuclei), the OAST listener, the IAST bridge, the AI
cognitive pass, the Android track, and the self-evolving learner with a Docker validation gate.

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
```

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

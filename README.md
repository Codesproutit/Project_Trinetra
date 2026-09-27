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

## What's new (Phase 4 — AI cognitive pass)

An optional AI layer that reads what the deterministic engines flag and cuts the noise — the
tool's judgement layer, kept honest by a strict gate:

- **Strict dedup gate** — only findings still marked *theoretical* (not dynamically confirmed),
  from a deterministic engine, and severe enough to matter are sent to the LLM. Anything already
  settled or IAST-confirmed is never re-reviewed, so the expensive pass stays cheap.
- **Cognitive reviewer** — for each selected finding the LLM decides true/false positive and
  refines severity, exploitability, and remediation. A confirmed false positive is dropped; a
  reply that doesn't parse is kept (dropping a real bug is the costly mistake, not the reverse).
- **BYOK + tiered routing** — reaches the model through the vendor-neutral provider router
  (Anthropic first), which tracks tokens per model.
- **Cost accounting** — every run reports the LLM spend in dollars.
- **Opt-in and graceful** — off by default; enable with `--ai`. Without a reachable API key the
  pass is skipped with a clear message, never a crash.

> The AI pass needs your own API key (BYOK) to run live — set `ANTHROPIC_API_KEY` and install
> `trinetra[llm]`. The logic and cost accounting are fully tested against a stand-in provider.

Later phases add the Android track and the self-evolving learner with a Docker validation gate.

## What's new (Phase 5 — Android track)

Static analysis of an Android app, feeding the same finding schema, dedup, AI pass and SARIF:

- **Manifest analysis** — flags the classic `AndroidManifest.xml` misconfigurations: debuggable
  release builds (CWE-489), cleartext traffic (CWE-319), backups allowed (CWE-530), components
  exported without a permission guard (CWE-926), and a too-low `minSdkVersion` (CWE-1104).
- **Hardcoded-secret scan** — finds cloud keys (Google, AWS) and generic credentials shipped
  inside the APK's resources and decompiled code (CWE-798).
- **`--apk <file>` lane** — Android is its own discipline; the analyzer runs as an `apk`-kind
  engine and its findings flow through the same pipeline.

> The analysis runs on **decoded** text. A production APK stores its manifest as compiled binary
> XML, so scanning one needs `apktool` present (the adapter uses it when installed and skips the
> manifest with a clear message when it isn't). The dynamic side — live traffic capture via
> mitmproxy/Frida on a device or emulator — is a later increment; this phase is the static core.

Later phases add the self-evolving learner with a Docker validation gate, and audit reporting.

## What's new (Phase 6 — self-evolving loop)

The tool learns: a novel, dynamically-confirmed finding can become a permanent detection rule —
but only after it proves itself, so precision is measured, never assumed.

- **Per-discipline brains** — each discipline (web, api, android) owns its own rule store. A
  pattern learned from an APK never leaks into web rules. A brain also remembers what it has
  learned (`knows()`), so the same issue is never re-learned.
- **Rule synthesis** — a *confirmed*, *novel* finding is turned into a candidate detection rule
  scoped to its discipline.
- **The Docker fixture gate** — before a rule joins a brain it must **fire on the vulnerable
  fixture and stay silent on the remediated one**. This is the honest version of the goal:
  *measured precision on a versioned corpus*, never "zero false positives."
- **Fail-closed** — the gate needs Semgrep in a container to run. When it isn't available the
  loop promotes *nothing*: an unvalidated rule never enters a brain. Enable with `--learn`.

> The loop's logic — synthesis, the brain store, the gate, promotion — is fully built and tested
> against a stand-in rule runner. Actually validating and promoting rules live needs Semgrep +
> Docker present; without them `--learn` runs and reports that nothing was promoted, by design.

Later phases add audit-grade reporting (CERT-In/CREST) and the live dashboard.

## What's new (Phase 7 — audit reporting + dashboard)

Turns findings into a report you can hand to a client or auditor, with tamper-evident evidence:

- **Evidence chain-of-custody** — each finding's request/response, OAST token and steps are
  captured and hashed (SHA-256). The hash is what a report cites; change any evidence field and
  the hash changes, so a reviewer can re-verify it.
- **Report templates** — `--report exec`, `--report cert-in`, `--report crest` render an
  executive summary or a structured CERT-In / CREST engagement report (Markdown, converts cleanly
  to PDF/HTML). Repeatable, written alongside the SARIF in the run directory.
- **Live activity model + manual replay** — the data layer behind a live scan view: a
  category-wise activity log, and a `fork()` that clones a captured request with a tweaked
  payload for manual re-testing (without mutating the original).

> The report templates organize real findings and their evidence hashes; they are structural
> layouts, not a legal certification of compliance. The live browser dashboard ships as an
> optional extra (`trinetra[dashboard]`, FastAPI); its activity/replay core is built and tested
> here, the running server is opt-in.

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

# Android: statically analyze an APK (manifest flaws + hardcoded secrets):
python -m trinetra scan --apk ./app.apk

# Write an auditor-ready report alongside the SARIF:
python -m trinetra scan --path ./target --report exec --report cert-in
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

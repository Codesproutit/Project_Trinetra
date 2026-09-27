"""The scan pipeline.

Runs the engines for a scan, applies strict dedup (so the AI pass — added in a
later phase — never re-reviews a settled finding), persists the run, and emits
SARIF.

Modes, routed by which inputs are given:
  - source (`source_path`): SAST + SCA against a local checkout.
  - target (`target_url`): DAST against a running URL, plus an OAST poll.
  - iast (both): run SAST, derive verification tasks from the static sinks, run
    DAST against the target, then correlate — upgrading static candidates the
    dynamic scan confirmed from THEORETICAL to CONFIRMED.

The AI cognitive pass and learner hook in at the marked point as later phases
land.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from trinetra.config import Settings, load_settings
from trinetra.engines.base import EngineRegistry
from trinetra.engines.base import registry as default_registry
from trinetra.engines.oast import NullOastBackend, OastListener
from trinetra.iast.bridge import correlate, derive_tasks, mint_oast_callbacks
from trinetra.models.finding import Finding
from trinetra.models.scope import (
    OutOfScopeError,
    Scope,
    ScopeManifest,
    ScopeRules,
    Target,
)
from trinetra.orchestrator.run_store import RunStore
from trinetra.orchestrator.scope_guard import ScopeGuard
from trinetra.reporting.sarif import write_sarif

logger = logging.getLogger(__name__)


class OutOfScopeErrorNoManifest(OutOfScopeError):
    """Raised when a network target scan is requested without a scope manifest."""

    def __init__(self) -> None:
        super().__init__(
            "A network target scan requires a signed scope manifest. "
            "Pass --scope pointing at your authorized engagement."
        )


@dataclass
class RunConfig:
    # source_path => SAST/SCA; target_url => DAST; both => IAST (grey-box).
    source_path: str | None = None
    target_url: str | None = None
    disciplines: list[str] = field(default_factory=lambda: ["web"])
    engines: list[str] | None = None  # None => all engines matching the disciplines
    scope_manifest: str | None = None

    def __post_init__(self) -> None:
        if not self.source_path and not self.target_url:
            raise ValueError("Provide source_path, target_url, or both (IAST).")

    @property
    def mode(self) -> str:
        if self.source_path and self.target_url:
            return "iast"
        return "source" if self.source_path else "target"

    @property
    def runs_source(self) -> bool:
        return self.source_path is not None

    @property
    def runs_target(self) -> bool:
        return self.target_url is not None


@dataclass
class RunResult:
    findings: list[Finding]
    sarif_path: Path
    run_dir: Path
    skipped_engines: list[str] = field(default_factory=list)
    failed_engines: list[str] = field(default_factory=list)
    iast_confirmed: int = 0  # static findings upgraded by dynamic confirmation
    verification_tasks: int = 0  # static sinks queued for dynamic verification


def dedup(findings: list[Finding]) -> list[Finding]:
    """Strict dedup by fingerprint; on collision keep the higher-severity finding."""
    order = ["info", "low", "medium", "high", "critical"]
    kept: dict[str, Finding] = {}
    for f in findings:
        existing = kept.get(f.fingerprint)
        if existing is None or order.index(f.severity) > order.index(existing.severity):
            kept[f.fingerprint] = f
    return list(kept.values())


class Pipeline:
    def __init__(
        self,
        settings: Settings | None = None,
        engine_registry: EngineRegistry | None = None,
        oast: OastListener | None = None,
    ):
        self.settings = settings or load_settings()
        self.registry = engine_registry or default_registry
        # NullOastBackend never yields interactions, so target/iast mode without a
        # real interaction server degrades to "no OAST findings" rather than failing.
        self.oast = oast or OastListener(backend=NullOastBackend())

    def _build_guard(self, cfg: RunConfig) -> ScopeGuard:
        if cfg.scope_manifest:
            return ScopeGuard.load(cfg.scope_manifest)
        if cfg.runs_target:
            # Deny-by-default: a network target is never auto-authorized.
            raise OutOfScopeErrorNoManifest()
        # Local source-scan mode: authorize only the given path, nothing networked.
        resolved = str(Path(cfg.source_path).resolve())
        manifest = ScopeManifest(
            engagement="local-source-scan",
            authorized_by="local operator",
            in_scope=ScopeRules(url_globs=[resolved, f"{resolved}/*"]),
            rate_limit_rps=self.settings.default_rps,
        )
        return ScopeGuard(Scope(manifest))

    def _assert_scope(self, cfg: RunConfig, guard: ScopeGuard) -> None:
        # The network target is what an engagement authorizes; a local source path
        # is the operator's own checkout. In source-only mode the auto-manifest
        # authorizes that path.
        if cfg.runs_target:
            parsed = urlparse(cfg.target_url)
            guard.assert_in_scope(Target(url=cfg.target_url, host=parsed.hostname))
        else:
            guard.assert_in_scope(Target(path=str(Path(cfg.source_path).resolve())))

    def _run_engines(self, cfg: RunConfig, input_kind: str, scan_input: str) -> _EngineOutcome:
        findings: list[Finding] = []
        skipped: list[str] = []
        failed: list[str] = []
        for discipline in cfg.disciplines:
            for engine in self.registry.select(discipline, input_kind):
                if cfg.engines and engine.name not in cfg.engines:
                    continue
                if not engine.available():
                    skipped.append(engine.name)
                    continue
                try:
                    findings.extend(engine.scan(scan_input, discipline=discipline))
                except Exception:  # noqa: BLE001 - one engine's failure must not abort the scan
                    logger.exception("Engine %s failed; continuing", engine.name)
                    failed.append(engine.name)
        return _EngineOutcome(findings, skipped, failed)

    def run(self, cfg: RunConfig) -> RunResult:
        guard = self._build_guard(cfg)
        self._assert_scope(cfg, guard)

        skipped: list[str] = []
        failed: list[str] = []

        static_findings: list[Finding] = []
        if cfg.runs_source:
            out = self._run_engines(cfg, "source", cfg.source_path)
            static_findings, skipped, failed = out.findings, out.skipped, out.failed

        # IAST: derive the verification queue from the static sinks and mint OAST
        # callbacks for the blind ones before the dynamic scan runs.
        tasks = derive_tasks(static_findings) if cfg.mode == "iast" else []
        if tasks:
            mint_oast_callbacks(tasks, self.oast)

        dynamic_findings: list[Finding] = []
        if cfg.runs_target:
            out = self._run_engines(cfg, "target", cfg.target_url)
            dynamic_findings = out.findings
            skipped += out.skipped
            failed += out.failed
            if self.oast.available():
                try:
                    dynamic_findings.extend(
                        self.oast.poll_and_correlate(discipline=cfg.disciplines[0])
                    )
                except Exception:  # noqa: BLE001 - OAST poll failure must not abort the scan
                    logger.exception("OAST poll failed; continuing")
                    failed.append("oast")

        # IAST bridge: upgrade static candidates the dynamic scan confirmed.
        iast_confirmed = 0
        if cfg.mode == "iast":
            result = correlate(static_findings, dynamic_findings, tasks=tasks)
            static_findings = result.findings
            iast_confirmed = result.confirmed_count

        findings = dedup(static_findings + dynamic_findings)
        # >>> Later phases hook in here: AI cognitive pass -> learner.

        store = RunStore(self.settings.run_dir)
        store.write_findings(findings)
        sarif_path = write_sarif(findings, store.path / "trinetra.sarif")
        return RunResult(
            findings=findings,
            sarif_path=sarif_path,
            run_dir=store.path,
            skipped_engines=sorted(set(skipped)),
            failed_engines=sorted(set(failed)),
            iast_confirmed=iast_confirmed,
            verification_tasks=len(tasks),
        )


@dataclass
class _EngineOutcome:
    findings: list[Finding]
    skipped: list[str]
    failed: list[str]

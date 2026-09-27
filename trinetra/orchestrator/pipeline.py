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

from trinetra.ai import AiReviewer, needs_review
from trinetra.config import Settings, load_settings
from trinetra.engines.base import EngineRegistry
from trinetra.engines.base import registry as default_registry
from trinetra.engines.oast import NullOastBackend, OastListener
from trinetra.iast.bridge import correlate, derive_tasks, mint_oast_callbacks
from trinetra.learner import Learner
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
from trinetra.telemetry.cost import router_cost

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
    # source_path => SAST/SCA; target_url => DAST; both => IAST (grey-box);
    # apk_path => Android static (its own lane, not combined with source/target).
    source_path: str | None = None
    target_url: str | None = None
    apk_path: str | None = None
    disciplines: list[str] = field(default_factory=lambda: ["web"])
    engines: list[str] | None = None  # None => all engines matching the disciplines
    scope_manifest: str | None = None

    def __post_init__(self) -> None:
        if self.apk_path and (self.source_path or self.target_url):
            raise ValueError("apk_path is its own lane; don't combine it with source/target.")
        if not self.source_path and not self.target_url and not self.apk_path:
            raise ValueError("Provide source_path, target_url, both (IAST), or apk_path.")
        if self.apk_path and self.disciplines == ["web"]:
            self.disciplines = ["android"]

    @property
    def mode(self) -> str:
        if self.apk_path:
            return "android"
        if self.source_path and self.target_url:
            return "iast"
        return "source" if self.source_path else "target"

    @property
    def runs_source(self) -> bool:
        return self.source_path is not None

    @property
    def runs_target(self) -> bool:
        return self.target_url is not None

    @property
    def runs_apk(self) -> bool:
        return self.apk_path is not None


@dataclass
class RunResult:
    findings: list[Finding]
    sarif_path: Path
    run_dir: Path
    skipped_engines: list[str] = field(default_factory=list)
    failed_engines: list[str] = field(default_factory=list)
    iast_confirmed: int = 0  # static findings upgraded by dynamic confirmation
    verification_tasks: int = 0  # static sinks queued for dynamic verification
    ai_reviewed: int = 0  # findings sent through the AI cognitive pass
    ai_dropped: int = 0  # confirmed false positives the AI removed
    cost_usd: float = 0.0  # LLM spend for this run
    rules_promoted: int = 0  # new brain rules learned this run


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
        reviewer: AiReviewer | None = None,
        learner: Learner | None = None,
    ):
        self.settings = settings or load_settings()
        self.registry = engine_registry or default_registry
        # NullOastBackend never yields interactions, so target/iast mode without a
        # real interaction server degrades to "no OAST findings" rather than failing.
        self.oast = oast or OastListener(backend=NullOastBackend())
        # The AI cognitive pass is opt-in (BYOK). None => deterministic-only run.
        self.reviewer = reviewer
        # The self-evolving learner is opt-in. None => no rule promotion.
        self.learner = learner

    def _build_guard(self, cfg: RunConfig) -> ScopeGuard:
        if cfg.scope_manifest:
            return ScopeGuard.load(cfg.scope_manifest)
        if cfg.runs_target:
            # Deny-by-default: a network target is never auto-authorized.
            raise OutOfScopeErrorNoManifest()
        # Local scan mode (source or APK): authorize only the given local path.
        resolved = str(Path(cfg.source_path or cfg.apk_path).resolve())
        manifest = ScopeManifest(
            engagement="local-scan",
            authorized_by="local operator",
            in_scope=ScopeRules(url_globs=[resolved, f"{resolved}/*"]),
            rate_limit_rps=self.settings.default_rps,
        )
        return ScopeGuard(Scope(manifest))

    def _assert_scope(self, cfg: RunConfig, guard: ScopeGuard) -> None:
        # The network target is what an engagement authorizes; a local source path
        # or APK file is the operator's own artifact.
        if cfg.runs_target:
            parsed = urlparse(cfg.target_url)
            guard.assert_in_scope(Target(url=cfg.target_url, host=parsed.hostname))
        else:
            guard.assert_in_scope(Target(path=str(Path(cfg.source_path or cfg.apk_path).resolve())))

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

        # Android lane: static APK analysis feeds the same schema/dedup/AI pass.
        if cfg.runs_apk:
            out = self._run_engines(cfg, "apk", cfg.apk_path)
            static_findings += out.findings
            skipped += out.skipped
            failed += out.failed

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

        # AI cognitive pass (opt-in, BYOK): review only the deterministic,
        # still-theoretical findings the dedup gate selects — never re-review a
        # settled or confirmed finding. Enriches survivors, drops confirmed FPs.
        ai_reviewed = 0
        ai_dropped = 0
        cost_usd = 0.0
        if self.reviewer is not None:
            if self.reviewer.available():
                to_review = needs_review(findings)
                try:
                    outcome = self.reviewer.review(to_review)
                    reviewed_fps = {f.fingerprint for f in to_review}
                    findings = [
                        f for f in findings if f.fingerprint not in reviewed_fps
                    ] + outcome.findings
                    findings = dedup(findings)
                    ai_reviewed = outcome.reviewed
                    ai_dropped = outcome.dropped
                except Exception:  # noqa: BLE001 - AI failure must not lose deterministic results
                    logger.exception("AI cognitive pass failed; keeping deterministic findings")
                    failed.append("ai_reviewer")
                cost_usd = router_cost(self.reviewer.router).usd
            else:
                skipped.append("ai_reviewer")

        # Self-evolving loop (opt-in): novel CONFIRMED findings become candidate
        # rules, gated by the sandbox validator, promoted into the discipline brain.
        rules_promoted = 0
        if self.learner is not None:
            try:
                outcome = self.learner.observe(findings)
                rules_promoted = len(outcome.promoted)
            except Exception:  # noqa: BLE001 - learning must not fail the scan
                logger.exception("Learner failed; scan results unaffected")
                failed.append("learner")

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
            ai_reviewed=ai_reviewed,
            ai_dropped=ai_dropped,
            cost_usd=cost_usd,
            rules_promoted=rules_promoted,
        )


@dataclass
class _EngineOutcome:
    findings: list[Finding]
    skipped: list[str]
    failed: list[str]

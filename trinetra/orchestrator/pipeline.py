"""The scan pipeline.

Runs the engines for a scan, applies strict dedup (so the AI pass — added in a
later phase — never re-reviews a settled finding), persists the run, and emits
SARIF.

Two modes, routed by each engine's `input_kind`:
  - source mode (`source_path`): SAST + SCA against a local checkout.
  - target mode (`target_url`): DAST against a running URL, plus an OAST poll to
    correlate blind (out-of-band) hits.

The AI cognitive pass, IAST bridge, and learner hook in at the marked point as
later phases land.
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


@dataclass
class RunConfig:
    # Exactly one of source_path / target_url is set. source_path => SAST/SCA
    # (input_kind="source"); target_url => DAST (input_kind="target").
    source_path: str | None = None
    target_url: str | None = None
    disciplines: list[str] = field(default_factory=lambda: ["web"])
    engines: list[str] | None = None  # None => all engines matching the disciplines
    scope_manifest: str | None = None

    def __post_init__(self) -> None:
        if bool(self.source_path) == bool(self.target_url):
            raise ValueError("Provide exactly one of source_path or target_url.")

    @property
    def input_kind(self) -> str:
        return "source" if self.source_path else "target"

    @property
    def scan_input(self) -> str:
        return self.source_path or self.target_url  # type: ignore[return-value]


@dataclass
class RunResult:
    findings: list[Finding]
    sarif_path: Path
    run_dir: Path
    skipped_engines: list[str] = field(default_factory=list)
    failed_engines: list[str] = field(default_factory=list)


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
        # NullOastBackend never yields interactions, so target mode without a real
        # interaction server degrades to "no OAST findings" rather than failing.
        self.oast = oast or OastListener(backend=NullOastBackend())

    def _build_guard(self, cfg: RunConfig) -> ScopeGuard:
        if cfg.scope_manifest:
            return ScopeGuard.load(cfg.scope_manifest)
        if cfg.input_kind == "target":
            # Deny-by-default: a network target is never auto-authorized. The
            # operator must point at a signed engagement manifest.
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

    def _scan_target(self, cfg: RunConfig) -> Target:
        if cfg.input_kind == "source":
            return Target(path=str(Path(cfg.source_path).resolve()))
        parsed = urlparse(cfg.target_url)
        return Target(url=cfg.target_url, host=parsed.hostname)

    def run(self, cfg: RunConfig) -> RunResult:
        guard = self._build_guard(cfg)
        guard.assert_in_scope(self._scan_target(cfg))

        findings: list[Finding] = []
        skipped: list[str] = []
        failed: list[str] = []
        for discipline in cfg.disciplines:
            for engine in self.registry.select(discipline, cfg.input_kind):
                if cfg.engines and engine.name not in cfg.engines:
                    continue
                if not engine.available():
                    skipped.append(engine.name)
                    continue
                try:
                    findings.extend(engine.scan(cfg.scan_input, discipline=discipline))
                except Exception:  # noqa: BLE001 - one engine's failure must not abort the scan
                    logger.exception("Engine %s failed; continuing", engine.name)
                    failed.append(engine.name)

        # DAST mode: pull any out-of-band callbacks that engines triggered and
        # correlate them into confirmed blind-vuln findings.
        if cfg.input_kind == "target" and self.oast.available():
            try:
                findings.extend(self.oast.poll_and_correlate(discipline=cfg.disciplines[0]))
            except Exception:  # noqa: BLE001 - OAST poll failure must not abort the scan
                logger.exception("OAST poll failed; continuing")
                failed.append("oast")

        findings = dedup(findings)
        # >>> Later phases hook in here: strict-dedup gate -> AI cognitive pass ->
        # >>> IAST bridge confirmation -> learner.

        store = RunStore(self.settings.run_dir)
        store.write_findings(findings)
        sarif_path = write_sarif(findings, store.path / "trinetra.sarif")
        return RunResult(
            findings=findings,
            sarif_path=sarif_path,
            run_dir=store.path,
            skipped_engines=sorted(set(skipped)),
            failed_engines=sorted(set(failed)),
        )


class OutOfScopeErrorNoManifest(OutOfScopeError):
    """Raised when a network target scan is requested without a scope manifest."""

    def __init__(self) -> None:
        super().__init__(
            "A network target scan requires a signed scope manifest. "
            "Pass --scope pointing at your authorized engagement."
        )

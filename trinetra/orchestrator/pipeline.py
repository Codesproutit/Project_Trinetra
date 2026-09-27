"""The scan pipeline.

Phase 1 runs the deterministic engines, applies strict dedup (so the AI pass —
added in a later phase — never re-reviews a settled finding), persists the run,
and emits SARIF. The AI cognitive pass, IAST bridge, and learner hook in at the
marked points as later phases land.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path

from trinetra.config import Settings, load_settings
from trinetra.engines.base import EngineRegistry
from trinetra.engines.base import registry as default_registry
from trinetra.models.finding import Finding
from trinetra.models.scope import Scope, ScopeManifest, ScopeRules, Target
from trinetra.orchestrator.run_store import RunStore
from trinetra.orchestrator.scope_guard import ScopeGuard
from trinetra.reporting.sarif import write_sarif

logger = logging.getLogger(__name__)


@dataclass
class RunConfig:
    source_path: str
    disciplines: list[str] = field(default_factory=lambda: ["web"])
    engines: list[str] | None = None  # None => all engines matching the disciplines
    scope_manifest: str | None = None


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
    ):
        self.settings = settings or load_settings()
        self.registry = engine_registry or default_registry

    def _build_guard(self, cfg: RunConfig) -> ScopeGuard:
        if cfg.scope_manifest:
            return ScopeGuard.load(cfg.scope_manifest)
        # Local source-scan mode: authorize only the given path, nothing networked.
        resolved = str(Path(cfg.source_path).resolve())
        manifest = ScopeManifest(
            engagement="local-source-scan",
            authorized_by="local operator",
            in_scope=ScopeRules(url_globs=[resolved, f"{resolved}/*"]),
            rate_limit_rps=self.settings.default_rps,
        )
        return ScopeGuard(Scope(manifest))

    def run(self, cfg: RunConfig) -> RunResult:
        guard = self._build_guard(cfg)
        guard.assert_in_scope(Target(path=str(Path(cfg.source_path).resolve())))

        findings: list[Finding] = []
        skipped: list[str] = []
        failed: list[str] = []
        for discipline in cfg.disciplines:
            for engine in self.registry.for_discipline(discipline):
                if cfg.engines and engine.name not in cfg.engines:
                    continue
                if not engine.available():
                    skipped.append(engine.name)
                    continue
                try:
                    findings.extend(engine.scan(cfg.source_path, discipline=discipline))
                except Exception:  # noqa: BLE001 - one engine's failure must not abort the scan
                    logger.exception("Engine %s failed; continuing", engine.name)
                    failed.append(engine.name)

        findings = dedup(findings)
        # >>> Later phases hook in here: strict-dedup gate -> AI cognitive pass ->
        # >>> IAST bridge confirmation -> learner. Phase 1 stops at deterministic.

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

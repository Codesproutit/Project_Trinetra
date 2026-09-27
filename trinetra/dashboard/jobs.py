"""Scan jobs for the control panel.

A scan can take a while, so the UI starts one and polls for progress. This module
holds the request shape, one job's state, and a thread-backed manager. It never
imports FastAPI: the pipeline call is injected, so the whole flow is testable with
a fake runner and no web server.
"""

from __future__ import annotations

import logging
import threading
import traceback
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from tempfile import mkdtemp
from typing import Any

from pydantic import BaseModel, Field, model_validator

from trinetra.orchestrator.pipeline import Pipeline, RunConfig, RunResult

logger = logging.getLogger(__name__)


class ScopeForm(BaseModel):
    """The fields the UI collects instead of asking for hand-written scope YAML."""

    engagement: str = "local engagement"
    authorized_by: str = "local operator"
    host: str = ""
    valid_until: str | None = None
    rate_limit_rps: float = 5.0
    out_of_scope: list[str] = Field(default_factory=list)

    def to_manifest_dict(self) -> dict[str, Any]:
        host = self.host.strip()
        return {
            "engagement": self.engagement,
            "authorized_by": self.authorized_by,
            "valid_until": self.valid_until or None,
            "in_scope": {"hosts": [host] if host else [], "url_globs": _host_globs(host)},
            "out_of_scope": [g for g in self.out_of_scope if g.strip()],
            "rate_limit_rps": self.rate_limit_rps,
        }


def _host_globs(host: str) -> list[str]:
    """Authorize http/https on the given host only. Empty host authorizes nothing."""
    if not host:
        return []
    return [f"https://{host}/*", f"http://{host}/*", f"https://{host}", f"http://{host}"]


class ScanRequest(BaseModel):
    """One scan the operator asked the panel to run."""

    mode: str  # source | dependencies | target | apk
    path: str | None = None  # source_path for source/dependencies, apk file for apk
    target_url: str | None = None
    disciplines: list[str] = Field(default_factory=lambda: ["web"])
    ai: bool = False
    learn: bool = False
    reports: list[str] = Field(default_factory=list)
    scope: ScopeForm | None = None

    @model_validator(mode="after")
    def _check(self) -> ScanRequest:
        if self.mode in {"source", "dependencies", "apk"} and not self.path:
            raise ValueError(f"{self.mode} scan needs a path")
        if self.mode == "target":
            if not self.target_url:
                raise ValueError("web scan needs a target URL")
            if not (self.scope and self.scope.host.strip()):
                raise ValueError("web scan needs an authorized host in the scope form")
        if self.mode not in {"source", "dependencies", "target", "apk"}:
            raise ValueError(f"unknown scan mode: {self.mode}")
        return self

    def to_run_config(self, scope_path: str | None) -> RunConfig:
        # "dependencies" is a source scan limited to the SCA engine.
        if self.mode == "dependencies":
            return RunConfig(source_path=self.path, disciplines=self.disciplines, engines=["sca"])
        if self.mode == "source":
            return RunConfig(source_path=self.path, disciplines=self.disciplines)
        if self.mode == "apk":
            return RunConfig(apk_path=self.path, disciplines=["android"])
        return RunConfig(
            target_url=self.target_url,
            disciplines=self.disciplines,
            scope_manifest=scope_path,
        )


@dataclass
class ScanJob:
    id: str
    request: ScanRequest
    status: str = "queued"  # queued | running | done | error | refused
    message: str = ""
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    findings: list[dict] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    run_dir: str | None = None
    sarif_path: str | None = None
    report_paths: list[str] = field(default_factory=list)

    def public(self) -> dict[str, Any]:
        d = asdict(self)
        d["request"] = self.request.model_dump()
        return d


def _summarize(result: RunResult) -> dict[str, Any]:
    counts: dict[str, int] = {}
    for f in result.findings:
        counts[str(f.severity)] = counts.get(str(f.severity), 0) + 1
    return {
        "total": len(result.findings),
        "by_severity": counts,
        "skipped_engines": result.skipped_engines,
        "failed_engines": result.failed_engines,
        "ai_reviewed": result.ai_reviewed,
        "ai_dropped": result.ai_dropped,
        "cost_usd": round(result.cost_usd, 4),
        "rules_promoted": result.rules_promoted,
        "iast_confirmed": result.iast_confirmed,
    }


# A runner turns a request into a RunResult. Injected so tests need no real engines.
Runner = Callable[[ScanRequest, str | None], RunResult]


def default_runner(request: ScanRequest, scope_path: str | None) -> RunResult:
    """Run the real pipeline. AI and learner are opt-in, exactly as the CLI wires them."""
    from trinetra.cli import _build_learner, _build_reviewer  # local import: avoids cycle

    cfg = request.to_run_config(scope_path)
    pipeline = Pipeline(
        reviewer=_build_reviewer() if request.ai else None,
        learner=_build_learner(cfg.disciplines) if request.learn else None,
    )
    return pipeline.run(cfg)


class JobManager:
    """Runs scans on background threads and keeps their state for polling."""

    def __init__(self, runner: Runner | None = None, report_writer: Callable | None = None):
        self._runner = runner or default_runner
        # Injected so a test can assert reports without importing the render module.
        if report_writer is None:
            from trinetra.reporting.render import write_reports as report_writer
        self._report_writer = report_writer
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._seq = 0

    def _new_id(self) -> str:
        with self._lock:
            self._seq += 1
            return f"scan-{self._seq:04d}"

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self) -> list[ScanJob]:
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.id, reverse=True)

    def submit(self, request: ScanRequest, *, block: bool = False) -> ScanJob:
        job = ScanJob(id=self._new_id(), request=request)
        with self._lock:
            self._jobs[job.id] = job
        if block:  # synchronous path for tests
            self._run(job)
        else:
            threading.Thread(target=self._run, args=(job,), daemon=True).start()
        return job

    def _run(self, job: ScanJob) -> None:
        job.status = "running"
        scope_path = None
        try:
            if job.request.mode == "target" and job.request.scope is not None:
                scope_path = self._write_scope(job.request.scope)
            result = self._runner(job.request, scope_path)
            job.findings = [f.model_dump(mode="json") for f in result.findings]
            job.summary = _summarize(result)
            job.run_dir = str(result.run_dir)
            job.sarif_path = str(result.sarif_path)
            if job.request.reports:
                paths = self._report_writer(
                    result.findings, result.run_dir, job.request.reports
                )
                job.report_paths = [str(p) for p in paths]
            job.status = "done"
            job.message = f"Found {job.summary['total']} issue(s)."
        except Exception as exc:  # noqa: BLE001 - surface any failure to the UI, don't crash the server
            # An authorization refusal is expected input error, not a server fault.
            job.status = "refused" if type(exc).__name__.endswith("ScopeError") else "error"
            job.message = str(exc) or exc.__class__.__name__
            logger.warning("Scan %s %s: %s\n%s", job.id, job.status, job.message,
                           traceback.format_exc())

    @staticmethod
    def _write_scope(scope: ScopeForm) -> str:
        import yaml  # optional dependency, same as scope_guard's loader

        d = Path(mkdtemp(prefix="trinetra-scope-"))
        path = d / "scope.yaml"
        path.write_text(yaml.safe_dump(scope.to_manifest_dict()), encoding="utf-8")
        return str(path)

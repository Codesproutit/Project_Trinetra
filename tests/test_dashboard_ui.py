"""Tests for the local control panel: environment probe, job manager, and the API.

The FastAPI tests are skipped when the web extras are not installed; the job
manager and environment tests are pure and always run. No real engine, network,
LLM or web server is used: a fake runner stands in for the pipeline.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from trinetra.dashboard import environment as envmod
from trinetra.dashboard.jobs import JobManager, ScanRequest, ScopeForm
from trinetra.models.finding import Finding, Location, Severity
from trinetra.orchestrator.pipeline import RunResult


def _result(tmp_path: Path, findings=None, **kw) -> RunResult:
    return RunResult(
        findings=findings if findings is not None else [],
        sarif_path=tmp_path / "trinetra.sarif",
        run_dir=tmp_path,
        **kw,
    )


def _finding(sev=Severity.HIGH, **kw) -> Finding:
    base = dict(discipline="web", source="semgrep", title="SQL injection",
                severity=sev, cwe="CWE-89", location=Location(file="app/db.py", line=6))
    base.update(kw)
    return Finding(**base)


# ----- environment probe -----

def test_probe_reports_needs_when_tool_absent(monkeypatch):
    monkeypatch.setattr(envmod.shutil, "which", lambda _b: None)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    env = envmod.probe_environment()
    assert env["semgrep"].available is False and "semgrep" in env["semgrep"].needs
    assert env["ai"].available is False and "ANTHROPIC_API_KEY" in env["ai"].needs
    assert env["dependencies"].available is True  # OSV needs no local tool


def test_mode_readiness_blocks_target_without_zap_or_nuclei(monkeypatch):
    monkeypatch.setattr(envmod.shutil, "which", lambda _b: None)
    modes = envmod.mode_readiness()
    assert modes["target"].ready is False and modes["target"].blockers
    assert modes["source"].ready is False  # no semgrep
    assert modes["dependencies"].ready is True


def test_mode_readiness_source_ready_when_semgrep_present(monkeypatch):
    monkeypatch.setattr(
        envmod.shutil, "which", lambda b: "/usr/bin/semgrep" if b == "semgrep" else None
    )
    assert envmod.mode_readiness()["source"].ready is True


# ----- request validation -----

def test_source_scan_requires_a_path():
    with pytest.raises(ValueError, match="needs a path"):
        ScanRequest(mode="source")


def test_target_scan_requires_url_and_authorized_host():
    with pytest.raises(ValueError, match="target URL"):
        ScanRequest(mode="target", scope=ScopeForm(host="h.example"))
    with pytest.raises(ValueError, match="authorized host"):
        ScanRequest(mode="target", target_url="https://h.example")


def test_unknown_mode_rejected():
    with pytest.raises(ValueError, match="unknown scan mode"):
        ScanRequest(mode="banana", path="x")


def test_dependencies_mode_limits_to_the_sca_engine():
    cfg = ScanRequest(mode="dependencies", path="proj").to_run_config(None)
    assert cfg.engines == ["sca"] and cfg.source_path == "proj"


def test_apk_mode_sets_android_discipline():
    cfg = ScanRequest(mode="apk", path="a.apk").to_run_config(None)
    assert cfg.apk_path == "a.apk" and cfg.disciplines == ["android"]


def test_scope_form_authorizes_only_the_given_host():
    d = ScopeForm(host="app.example").to_manifest_dict()
    assert d["in_scope"]["hosts"] == ["app.example"]
    assert all("app.example" in g for g in d["in_scope"]["url_globs"])
    assert ScopeForm(host="").to_manifest_dict()["in_scope"]["url_globs"] == []


# ----- job manager (synchronous path) -----

def test_job_runs_and_summarizes(tmp_path):
    findings = [_finding(), _finding(sev=Severity.LOW, location=Location(file="a.py", line=2))]
    jm = JobManager(runner=lambda req, sp: _result(tmp_path, findings, skipped_engines=["zap"]),
                    report_writer=lambda f, d, r: [Path(d) / "report-exec.md"])
    job = jm.submit(ScanRequest(mode="source", path="proj", reports=["exec"]), block=True)
    assert job.status == "done"
    assert job.summary["total"] == 2
    assert job.summary["by_severity"] == {"high": 1, "low": 1}
    assert job.summary["skipped_engines"] == ["zap"]
    assert job.report_paths and job.report_paths[0].endswith("report-exec.md")
    assert job.findings[0]["title"] == "SQL injection"


def test_job_marks_refused_on_scope_error(tmp_path):
    class OutOfScopeError(Exception):
        pass

    def boom(req, sp):
        raise OutOfScopeError("target not authorized")

    jm = JobManager(runner=boom)
    job = jm.submit(ScanRequest(mode="source", path="p"), block=True)
    assert job.status == "refused"
    assert "not authorized" in job.message


def test_job_marks_error_and_never_raises(tmp_path):
    def boom(req, sp):
        raise RuntimeError("semgrep exploded")

    jm = JobManager(runner=boom)
    job = jm.submit(ScanRequest(mode="source", path="p"), block=True)
    assert job.status == "error" and "exploded" in job.message


def test_target_job_writes_a_scope_file_the_runner_receives(tmp_path):
    seen = {}

    def runner(req, scope_path):
        seen["path"] = scope_path
        return _result(tmp_path)

    jm = JobManager(runner=runner)
    req = ScanRequest(mode="target", target_url="https://app.example",
                      scope=ScopeForm(host="app.example", rate_limit_rps=3))
    job = jm.submit(req, block=True)
    assert job.status == "done"
    assert seen["path"] and Path(seen["path"]).is_file()
    import yaml
    manifest = yaml.safe_load(Path(seen["path"]).read_text())
    assert manifest["in_scope"]["hosts"] == ["app.example"]
    assert manifest["rate_limit_rps"] == 3


# ----- FastAPI layer (skipped without the extras) -----

server = pytest.importorskip("trinetra.dashboard.server")
fastapi_installed = server.available()
needs_web = pytest.mark.skipif(not fastapi_installed, reason="fastapi/uvicorn not installed")


def _client(tmp_path, runner=None):
    from fastapi.testclient import TestClient

    jm = JobManager(runner=runner or (lambda req, sp: _result(tmp_path, [_finding()])),
                    report_writer=lambda f, d, r: [])
    return TestClient(server.create_app(job_manager=jm)), jm


@needs_web
def test_api_environment_lists_capabilities_and_modes(tmp_path):
    client, _ = _client(tmp_path)
    body = client.get("/api/environment").json()
    keys = {c["key"] for c in body["capabilities"]}
    assert {"semgrep", "ai", "docker"} <= keys
    assert set(body["modes"]) == {"source", "dependencies", "target", "apk"}


@needs_web
def test_api_scan_flow_start_and_poll(tmp_path):
    client, _ = _client(tmp_path)
    started = client.post("/api/scan", json={"mode": "source", "path": "proj"})
    assert started.status_code == 202
    job_id = started.json()["id"]
    got = client.get(f"/api/scan/{job_id}")
    assert got.status_code == 200
    assert got.json()["status"] in {"queued", "running", "done"}


@needs_web
def test_api_rejects_invalid_request(tmp_path):
    client, _ = _client(tmp_path)
    assert client.post("/api/scan", json={"mode": "source"}).status_code == 422


@needs_web
def test_api_missing_job_is_404(tmp_path):
    client, _ = _client(tmp_path)
    assert client.get("/api/scan/scan-9999").status_code == 404


@needs_web
def test_api_file_only_serves_scan_outputs(tmp_path):
    sarif = tmp_path / "trinetra.sarif"
    sarif.write_text("{}", encoding="utf-8")
    client, _ = _client(tmp_path, runner=lambda req, sp: _result(tmp_path, [_finding()]))
    client.post("/api/scan", json={"mode": "source", "path": "p"})
    # A path no scan produced is refused.
    assert client.get("/api/file", params={"path": "/etc/passwd"}).status_code == 403
    # The scan's own SARIF is allowed.
    assert client.get("/api/file", params={"path": str(sarif)}).status_code == 200


@needs_web
def test_index_page_is_served(tmp_path):
    client, _ = _client(tmp_path)
    r = client.get("/")
    assert r.status_code == 200 and "Trinetra" in r.text

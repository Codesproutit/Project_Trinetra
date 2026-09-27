import json

import pytest

from trinetra.config import Settings
from trinetra.engines.base import EngineRegistry
from trinetra.engines.oast import Interaction, OastListener
from trinetra.models.finding import Finding, Location, Severity
from trinetra.models.scope import OutOfScopeError
from trinetra.orchestrator.pipeline import Pipeline, RunConfig, dedup


class _FakeEngine:
    name = "fake"
    disciplines = ["web"]
    input_kind = "source"

    def __init__(self, findings):
        self._findings = findings

    def available(self):
        return True

    def scan(self, target, *, discipline="web"):
        return list(self._findings)


class _FakeTargetEngine(_FakeEngine):
    name = "faketarget"
    input_kind = "target"

    def __init__(self, findings):
        super().__init__(findings)
        self.scanned = None

    def scan(self, target, *, discipline="web"):
        self.scanned = target
        return list(self._findings)


def _write_scope(tmp_path, host):
    manifest = {
        "engagement": "test",
        "authorized_by": "tester",
        "in_scope": {"hosts": [host]},
        "rate_limit_rps": 0,
    }
    p = tmp_path / "scope.json"
    p.write_text(json.dumps(manifest))
    return str(p)


class _FakeBackend:
    domain = "oast.test"

    def __init__(self, interactions):
        self._q = list(interactions)

    def register(self):
        return None

    def poll(self):
        out, self._q = self._q, []
        return out


def test_dedup_keeps_higher_severity():
    a = Finding(discipline="web", source="semgrep", title="X", rule_id="r", severity=Severity.LOW)
    b = Finding(discipline="web", source="zap", title="X", rule_id="r", severity=Severity.HIGH)
    result = dedup([a, b])
    assert len(result) == 1
    assert result[0].severity == Severity.HIGH


def test_pipeline_runs_engine_and_writes_sarif(tmp_path):
    findings = [
        Finding(
            discipline="web",
            source="fake",
            title="SQLi",
            severity=Severity.CRITICAL,
            rule_id="sqli",
            cwe="CWE-89",
            location=Location(file="a.py", line=1),
        )
    ]
    reg = EngineRegistry()
    reg.register(_FakeEngine(findings))
    settings = Settings(run_dir=tmp_path / "runs")

    src = tmp_path / "src"
    src.mkdir()
    pipeline = Pipeline(settings=settings, engine_registry=reg)
    result = pipeline.run(RunConfig(source_path=str(src), disciplines=["web"]))

    assert len(result.findings) == 1
    assert result.sarif_path.exists()
    sarif = json.loads(result.sarif_path.read_text())
    assert sarif["runs"][0]["results"][0]["ruleId"] == "sqli"


def test_pipeline_survives_engine_error(tmp_path):
    class _Broken(_FakeEngine):
        name = "broken"

        def scan(self, target, *, discipline="web"):
            raise RuntimeError("network down")

    reg = EngineRegistry()
    reg.register(_Broken([]))
    settings = Settings(run_dir=tmp_path / "runs")
    src = tmp_path / "src"
    src.mkdir()
    result = Pipeline(settings=settings, engine_registry=reg).run(
        RunConfig(source_path=str(src), disciplines=["web"])
    )
    # Run completes and still writes SARIF even though the engine blew up.
    assert "broken" in result.failed_engines
    assert result.sarif_path.exists()


def test_pipeline_skips_unavailable_engine(tmp_path):
    class _Unavailable(_FakeEngine):
        name = "down"

        def available(self):
            return False

    reg = EngineRegistry()
    reg.register(_Unavailable([]))
    settings = Settings(run_dir=tmp_path / "runs")
    src = tmp_path / "src"
    src.mkdir()
    result = Pipeline(settings=settings, engine_registry=reg).run(
        RunConfig(source_path=str(src), disciplines=["web"])
    )
    assert "down" in result.skipped_engines


def test_runconfig_requires_exactly_one_input():
    with pytest.raises(ValueError):
        RunConfig()
    with pytest.raises(ValueError):
        RunConfig(source_path="x", target_url="http://y/")


def test_target_mode_requires_scope_manifest(tmp_path):
    reg = EngineRegistry()
    reg.register(_FakeTargetEngine([]))
    settings = Settings(run_dir=tmp_path / "runs")
    pipeline = Pipeline(settings=settings, engine_registry=reg)
    with pytest.raises(OutOfScopeError):
        pipeline.run(RunConfig(target_url="http://testapp.local/", disciplines=["web"]))


def test_source_mode_skips_target_engines_and_vice_versa(tmp_path):
    reg = EngineRegistry()
    src_engine = _FakeEngine(
        [Finding(discipline="web", source="fake", title="S", rule_id="s", severity=Severity.LOW)]
    )
    tgt_engine = _FakeTargetEngine(
        [Finding(discipline="web", source="faketarget", title="T", rule_id="t",
                 severity=Severity.HIGH)]
    )
    reg.register(src_engine)
    reg.register(tgt_engine)
    settings = Settings(run_dir=tmp_path / "runs")
    src = tmp_path / "src"
    src.mkdir()

    # Source mode: only the source engine runs.
    result = Pipeline(settings=settings, engine_registry=reg).run(
        RunConfig(source_path=str(src), disciplines=["web"])
    )
    assert {f.source for f in result.findings} == {"fake"}
    assert tgt_engine.scanned is None

    # Target mode (with scope): only the target engine runs, scanned the URL.
    scope = _write_scope(tmp_path, "testapp.local")
    result = Pipeline(settings=settings, engine_registry=reg).run(
        RunConfig(target_url="http://testapp.local/", disciplines=["web"], scope_manifest=scope)
    )
    assert {f.source for f in result.findings} == {"faketarget"}
    assert tgt_engine.scanned == "http://testapp.local/"


def test_target_mode_polls_oast_and_merges_findings(tmp_path):
    reg = EngineRegistry()
    reg.register(_FakeTargetEngine([]))
    settings = Settings(run_dir=tmp_path / "runs")
    backend = _FakeBackend([])
    listener = OastListener(backend=backend)
    _, host = listener.new_callback("GET /ssrf?url=")
    backend._q = [Interaction(token=host, protocol="http", remote_addr="10.0.0.1")]

    scope = _write_scope(tmp_path, "testapp.local")
    result = Pipeline(settings=settings, engine_registry=reg, oast=listener).run(
        RunConfig(target_url="http://testapp.local/", disciplines=["web"], scope_manifest=scope)
    )
    assert any(f.source == "oast" and f.cwe == "CWE-918" for f in result.findings)

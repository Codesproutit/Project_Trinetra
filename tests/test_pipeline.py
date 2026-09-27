import json

from trinetra.config import Settings
from trinetra.engines.base import EngineRegistry
from trinetra.models.finding import Finding, Location, Severity
from trinetra.orchestrator.pipeline import Pipeline, RunConfig, dedup


class _FakeEngine:
    name = "fake"
    disciplines = ["web"]

    def __init__(self, findings):
        self._findings = findings

    def available(self):
        return True

    def scan(self, target, *, discipline="web"):
        return list(self._findings)


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

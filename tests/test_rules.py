"""Tests for the bundled rulesets and the Semgrep adapter's command/config handling.

The `semgrep --test` check needs Semgrep installed and is skipped otherwise; the
rest are pure and always run.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from trinetra.engines.sast.semgrep import (
    BUNDLED,
    SemgrepAdapter,
    build_command,
    learned_rules_document,
    parse_semgrep_sarif,
    resolve_configs,
)
from trinetra.models.rule import Rule
from trinetra.rules import BUNDLED_RULES_DIR

TARGETS = Path(__file__).parent / "semgrep_targets"
ROOT = Path(__file__).parent.parent


def test_bundled_rulesets_ship_with_a_test_target_each():
    rulesets = sorted(p.stem for p in BUNDLED_RULES_DIR.glob("*.yaml"))
    assert rulesets == ["javascript", "python", "secrets"]
    targets = {p.stem for p in TARGETS.iterdir()}
    assert set(rulesets) <= targets


def test_every_bundled_rule_has_a_positive_test_case():
    annotated = "\n".join(p.read_text(encoding="utf-8") for p in TARGETS.iterdir())
    for ruleset in BUNDLED_RULES_DIR.glob("*.yaml"):
        for line in ruleset.read_text(encoding="utf-8").splitlines():
            if line.startswith("  - id: "):
                rule_id = line.split("id: ", 1)[1].strip()
                if rule_id.startswith("trinetra.secrets.") and rule_id not in annotated:
                    continue  # provider key formats we cannot safely commit a sample of
                assert f"ruleid: {rule_id}" in annotated, f"{rule_id} has no ruleid: case"


def test_bundled_keyword_resolves_to_shipped_rules():
    assert resolve_configs(None) == [str(BUNDLED_RULES_DIR)]
    assert resolve_configs(BUNDLED) == [str(BUNDLED_RULES_DIR)]
    assert resolve_configs([BUNDLED, "p/owasp-top-ten"]) == [
        str(BUNDLED_RULES_DIR),
        "p/owasp-top-ten",
    ]


def test_adapter_keeps_legacy_single_config_keyword():
    assert SemgrepAdapter(config="auto").configs == ["auto"]
    assert SemgrepAdapter().configs == [str(BUNDLED_RULES_DIR)]


def test_command_disables_metrics_unless_registry_auto_requires_it():
    offline = build_command(["rules/"], "src")
    assert "--metrics=off" in offline
    assert offline[-3:] == ["--config", "rules/", "src"]
    assert "--metrics=off" not in build_command(["auto"], "src")
    multi = build_command(["a", "b"], "src")
    assert multi.count("--config") == 2


def test_learned_rules_skip_unrunnable_and_seed_only_patterns():
    good = Rule(id="t.web.learned.a", discipline="web", languages=["python"],
                pattern="dangerous_call($X)")
    seed = Rule(id="t.web.learned.b", discipline="web", languages=["python"],
                pattern="python.lang.security.sqli")
    no_lang = Rule(id="t.web.learned.c", discipline="web", pattern="f($X)")
    doc = learned_rules_document([good, seed, no_lang])
    assert [r["id"] for r in doc["rules"]] == ["t.web.learned.a"]
    assert learned_rules_document([seed]) is None
    assert learned_rules_document([]) is None


def test_owasp_category_is_extracted_from_rule_tags():
    sarif = {
        "runs": [{
            "tool": {"driver": {"rules": [{
                "id": "trinetra.python.sql-injection",
                "properties": {"tags": [
                    "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                    "OWASP-A03:2021 - Injection",
                ]},
            }]}},
            "results": [{"ruleId": "trinetra.python.sql-injection", "level": "error",
                         "message": {"text": "SQL injection"}}],
        }]
    }
    f = parse_semgrep_sarif(sarif)[0]
    assert f.cwe == "CWE-89"
    assert f.owasp == "A03:2021 - Injection"


needs_semgrep = pytest.mark.skipif(shutil.which("semgrep") is None, reason="semgrep not installed")


@needs_semgrep
def test_bundled_rules_pass_semgrep_unit_tests(tmp_path):
    # `semgrep --test` pairs rules with targets by file stem in one directory.
    for p in list(BUNDLED_RULES_DIR.glob("*.yaml")) + list(TARGETS.iterdir()):
        shutil.copy(p, tmp_path / p.name)
    proc = subprocess.run(
        ["semgrep", "--test", "--metrics=off", "--disable-version-check", str(tmp_path)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
        env={**__import__("os").environ, "PYTHONUTF8": "1"}, check=False,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "All tests passed" in proc.stdout + proc.stderr


@needs_semgrep
def test_bundled_scan_of_vulnerable_sample_finds_every_planted_issue():
    findings = SemgrepAdapter().scan(str(ROOT / "examples" / "vulnerable-python"))
    found = {(f.rule_id.rsplit(".", 1)[-1], Path(f.location.file).name) for f in findings}
    expected = {
        ("hardcoded-secret", "config.py"),
        ("sql-injection", "db.py"),
        ("command-injection-shell", "exec.py"),
        ("web-path-traversal", "web.py"),
        ("web-ssrf", "web.py"),
        ("web-open-redirect", "web.py"),
        ("web-reflected-xss", "web.py"),
        ("insecure-deserialization", "web.py"),
        ("flask-debug-enabled", "web.py"),
    }
    assert expected <= found, sorted(expected - found)
    secrets = [f for f in findings if f.rule_id.endswith("hardcoded-secret")]
    assert len(secrets) == 2  # API_KEY and DB_PASSWORD (the old anchored regex missed this)
    assert all(f.cwe and f.owasp for f in findings)
    json.dumps([f.model_dump() for f in findings])  # serializable for the run store


def test_local_rule_titles_use_the_message_headline():
    from trinetra.engines.sast.semgrep import _headline

    assert _headline("SQL injection: the query is built with ...") == "SQL injection"
    assert _headline("Flask debug mode is on. The debugger ...") == "Flask debug mode is on"
    assert _headline("short message") == "short message"

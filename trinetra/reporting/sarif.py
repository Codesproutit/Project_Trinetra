"""SARIF 2.1.0 output.

SARIF is the interchange format GitHub code scanning and most security tooling
consume, so it is Trinetra's first-class report. One tool `run` per invocation,
one `rule` per distinct rule_id, one `result` per finding.
"""

from __future__ import annotations

import json
from pathlib import Path

from trinetra import __version__
from trinetra.models.finding import Finding

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"


def findings_to_sarif(findings: list[Finding]) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for f in findings:
        rule_id = f.rule_id or f.fingerprint[:12]
        if rule_id not in rules:
            rule: dict = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "properties": {"tags": [t for t in [f.cwe, f.owasp, f.source] if t]},
            }
            if f.references:
                rule["helpUri"] = f.references[0]
            rules[rule_id] = rule

        result: dict = {
            "ruleId": rule_id,
            "level": f.sarif_level,
            "message": {"text": f.description or f.title},
            "properties": {
                "discipline": f.discipline,
                "engine_layer": str(f.engine_layer),
                "severity": str(f.severity),
                "confidence": str(f.confidence),
                "cwe": f.cwe,
                "fingerprint": f.fingerprint,
            },
        }
        if f.location.file or f.location.route:
            region = {"startLine": f.location.line} if f.location.line else {}
            result["locations"] = [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.location.file or f.location.route},
                        **({"region": region} if region else {}),
                    }
                }
            ]
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Trinetra",
                        "version": __version__,
                        "informationUri": "https://github.com/Codesproutit/Project_Trinetra",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_sarif(findings: list[Finding], path: str | Path) -> Path:
    out = Path(path)
    out.write_text(json.dumps(findings_to_sarif(findings), indent=2))
    return out

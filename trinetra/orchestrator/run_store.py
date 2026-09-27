"""Persist a scan run: config snapshot, findings, and (later) evidence.

A run is a self-contained, reproducible record — which is also what makes a
finding re-derivable for an audit.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from trinetra.models.finding import Finding


class RunStore:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.run_id = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
        self.path = self.root / self.run_id
        self.path.mkdir(parents=True, exist_ok=True)

    def write_findings(self, findings: list[Finding]) -> Path:
        out = self.path / "findings.json"
        out.write_text(json.dumps([f.model_dump(mode="json") for f in findings], indent=2))
        return out

    def write_text(self, name: str, content: str) -> Path:
        out = self.path / name
        out.write_text(content)
        return out

"""Trinetra's bundled, offline Semgrep rulesets.

Each YAML file here is a Semgrep config; the directory as a whole is what
`--semgrep-config bundled` (the default) runs. Every rule has positive and
negative cases in tests/semgrep_targets/, checked by `semgrep --test`.
"""

from pathlib import Path

BUNDLED_RULES_DIR = Path(__file__).parent

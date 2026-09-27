"""What can actually run on this machine.

The control panel must be honest: an engine whose external tool is missing should
show a clear "needs X" state, never look like it ran and found nothing. This module
probes for those tools once so the UI can grey out or annotate each option.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Capability:
    key: str
    label: str
    available: bool
    needs: str = ""  # what to install/set when unavailable; empty when available


def _has(binary: str) -> bool:
    return shutil.which(binary) is not None


def _anthropic_key() -> bool:
    return bool(os.getenv("ANTHROPIC_API_KEY"))


def probe_environment() -> dict[str, Capability]:
    """Probe the external tools each scan mode/option depends on."""
    caps = [
        Capability(
            "semgrep",
            "Source-code scanning (Semgrep)",
            _has("semgrep"),
            "" if _has("semgrep") else "Install Semgrep: pip install semgrep",
        ),
        Capability(
            "dependencies",
            "Dependency scanning (OSV)",
            True,  # pure HTTP to api.osv.dev; needs network but no local tool
            "",
        ),
        Capability(
            "zap",
            "Web scanning (OWASP ZAP)",
            _has("zap.sh") or _has("zap"),
            "" if (_has("zap.sh") or _has("zap")) else "Install OWASP ZAP and put it on PATH",
        ),
        Capability(
            "nuclei",
            "Web templates (Nuclei)",
            _has("nuclei"),
            "" if _has("nuclei") else "Install Nuclei and put it on PATH",
        ),
        Capability(
            "apktool",
            "Android APK decoding (apktool)",
            _has("apktool"),
            "" if _has("apktool") else "Install apktool to scan release APKs",
        ),
        Capability(
            "ai",
            "AI review pass (Anthropic API key)",
            _anthropic_key(),
            "" if _anthropic_key() else "Set ANTHROPIC_API_KEY, then install trinetra[llm]",
        ),
        Capability(
            "docker",
            "Self-learning sandbox (Docker)",
            _has("docker"),
            "" if _has("docker") else "Install Docker to let the learner validate new rules",
        ),
    ]
    return {c.key: c for c in caps}


@dataclass
class ModeReadiness:
    """Whether a scan mode can run, and what it still needs if not."""

    mode: str
    ready: bool
    blockers: list[str] = field(default_factory=list)


def mode_readiness(env: dict[str, Capability] | None = None) -> dict[str, ModeReadiness]:
    """Map each scan mode to whether its required tools are present."""
    env = env or probe_environment()

    def need(*keys: str) -> list[str]:
        return [env[k].needs for k in keys if not env[k].available and env[k].needs]

    return {
        "source": ModeReadiness("source", env["semgrep"].available, need("semgrep")),
        # OSV needs only network; treat as always runnable, warn about network in the UI.
        "dependencies": ModeReadiness("dependencies", True, []),
        "target": ModeReadiness(
            "target",
            env["zap"].available or env["nuclei"].available,
            need("zap", "nuclei") or ["Install ZAP or Nuclei to scan a live web target"],
        ),
        # Basic manifest/secret scan works; apktool adds depth on release APKs.
        "apk": ModeReadiness("apk", True, []),
    }

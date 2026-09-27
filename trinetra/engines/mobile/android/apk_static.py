"""Android static analysis — APK teardown.

An APK is a ZIP. Two things in it carry most of the low-hanging risk:

  * **AndroidManifest.xml** — declares debuggability, cleartext traffic, backup
    policy, and which components are exported to other apps. Misconfigurations
    here are classic mobile findings.
  * **Resources / decompiled code** — hardcoded API keys and secrets shipped
    inside the app.

The analysis functions are pure and operate on decoded text, so they are fully
unit-tested without a device or the Android toolchain. The adapter wires them to
a real APK: it reads a *text* manifest directly, and for a production APK whose
manifest is compiled binary XML it uses `apktool` when present, degrading with a
clear message when it isn't (rather than crashing or pretending it scanned).
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

from trinetra.models.finding import (
    Confidence,
    EngineLayer,
    Finding,
    Location,
    Severity,
)

logger = logging.getLogger(__name__)

_ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
_BINARY_AXML_MAGIC = b"\x03\x00\x08\x00"
_COMPONENTS = ("activity", "activity-alias", "service", "receiver", "provider")
_TEXT_SUFFIXES = (".xml", ".java", ".kt", ".smali", ".json", ".properties", ".txt")

# (regex, label, severity). Cloud provider keys are high-confidence & high impact.
_SECRET_PATTERNS: list[tuple[re.Pattern, str, Severity]] = [
    (re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "Google API key", Severity.HIGH),
    (re.compile(r"AKIA[0-9A-Z]{16}"), "AWS access key id", Severity.HIGH),
    (
        re.compile(
            r"(?i)(api[_-]?key|secret|token|password)[\"']?\s*[=:]\s*[\"']([^\"']{8,})[\"']"
        ),
        "Hardcoded credential",
        Severity.MEDIUM,
    ),
]


def _attr(el: ET.Element, name: str) -> str | None:
    return el.get(f"{_ANDROID_NS}{name}") or el.get(name)


def _is_true(val: str | None) -> bool:
    return (val or "").strip().lower() == "true"


def analyze_manifest(manifest_xml: str, *, discipline: str = "android") -> list[Finding]:
    """Flag insecure AndroidManifest.xml settings from decoded (text) XML."""
    findings: list[Finding] = []
    root = ET.fromstring(manifest_xml)  # noqa: S314 - local, operator-supplied APK
    app = root.find("application")

    def add(title, cwe, sev, rule, desc, remediation=""):
        findings.append(
            Finding(
                discipline=discipline,
                source="apk_static",
                engine_layer=EngineLayer.DETERMINISTIC,
                title=title,
                description=desc,
                severity=sev,
                confidence=Confidence.THEORETICAL,
                cwe=cwe,
                rule_id=rule,
                location=Location(file="AndroidManifest.xml"),
                remediation=remediation,
            )
        )

    if app is not None:
        if _is_true(_attr(app, "debuggable")):
            add(
                "Application is debuggable", "CWE-489", Severity.HIGH,
                "android-debuggable",
                "android:debuggable=\"true\" ships a debuggable build to production.",
                "Set android:debuggable to false (or remove it) in release builds.",
            )
        if _is_true(_attr(app, "usesCleartextTraffic")):
            add(
                "Cleartext traffic permitted", "CWE-319", Severity.MEDIUM,
                "android-cleartext",
                "android:usesCleartextTraffic=\"true\" allows unencrypted HTTP.",
                "Disable cleartext traffic and use HTTPS with a network security config.",
            )
        if _is_true(_attr(app, "allowBackup")):
            add(
                "Application backups allowed", "CWE-530", Severity.LOW,
                "android-allowbackup",
                "android:allowBackup=\"true\" lets app data be extracted via adb backup.",
                "Set android:allowBackup to false unless backups are required.",
            )
        for comp in _COMPONENTS:
            for el in app.findall(comp):
                exported = _is_true(_attr(el, "exported"))
                has_perm = bool(_attr(el, "permission"))
                if exported and not has_perm:
                    name = _attr(el, "name") or comp
                    add(
                        f"Exported {comp} without permission: {name}", "CWE-926",
                        Severity.MEDIUM, "android-exported-no-permission",
                        f"{comp} '{name}' is exported with no permission guard, so any "
                        "app on the device can invoke it.",
                        "Set android:exported=\"false\" or guard it with a signature permission.",
                    )

    uses_sdk = root.find("uses-sdk")
    if uses_sdk is not None:
        min_sdk = _attr(uses_sdk, "minSdkVersion")
        if min_sdk and min_sdk.isdigit() and int(min_sdk) < 24:
            add(
                f"Low minSdkVersion ({min_sdk})", "CWE-1104", Severity.LOW,
                "android-low-minsdk",
                f"minSdkVersion {min_sdk} keeps the app on Android versions missing modern "
                "platform hardening.",
                "Raise minSdkVersion to a currently-supported API level.",
            )
    return findings


def scan_secrets(files: dict[str, str], *, discipline: str = "android") -> list[Finding]:
    """Flag hardcoded secrets in decoded resource/source text, keyed by path."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for path, text in files.items():
        for line_no, line in enumerate(text.splitlines(), start=1):
            for pattern, label, sev in _SECRET_PATTERNS:
                if not pattern.search(line):
                    continue
                key = f"{path}:{line_no}:{label}"
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        discipline=discipline,
                        source="apk_static",
                        engine_layer=EngineLayer.DETERMINISTIC,
                        title=f"{label} hardcoded in app",
                        description=f"A {label.lower()} appears hardcoded in {path}.",
                        severity=sev,
                        confidence=Confidence.THEORETICAL,
                        cwe="CWE-798",
                        rule_id="android-hardcoded-secret",
                        location=Location(file=path, line=line_no),
                        remediation="Move secrets out of the APK; use a secured backend or "
                        "the Android Keystore.",
                    )
                )
    return findings


class ApkStaticAdapter:
    name = "apk_static"
    disciplines = ["android"]
    input_kind = "apk"

    def __init__(self, apktool: str = "apktool"):
        self.apktool = apktool

    def available(self) -> bool:
        # Pure-Python zip + text analysis always runs. A compiled (binary) manifest
        # additionally needs apktool, handled per-APK in scan().
        return True

    def scan(self, apk_path: str, *, discipline: str = "android") -> list[Finding]:
        findings: list[Finding] = []
        with zipfile.ZipFile(apk_path) as zf:
            findings.extend(self._scan_manifest(zf, apk_path, discipline))
            findings.extend(self._scan_files(zf, discipline))
        return findings

    def _scan_manifest(self, zf: zipfile.ZipFile, apk_path: str, discipline: str) -> list[Finding]:
        try:
            raw = zf.read("AndroidManifest.xml")
        except KeyError:
            logger.warning("APK has no AndroidManifest.xml")
            return []
        if raw[:4] == _BINARY_AXML_MAGIC:
            decoded = self._decode_binary_manifest(apk_path)
            if decoded is None:
                logger.warning(
                    "AndroidManifest.xml is compiled binary XML and apktool is not "
                    "installed; skipping manifest analysis. Install apktool to scan "
                    "production APKs."
                )
                return []
            raw = decoded.encode()
        return analyze_manifest(raw.decode("utf-8", errors="replace"), discipline=discipline)

    def _decode_binary_manifest(self, apk_path: str) -> str | None:
        if shutil.which(self.apktool) is None:
            return None
        with tempfile.TemporaryDirectory() as td:
            out = Path(td) / "decoded"
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                [self.apktool, "d", "-f", "-o", str(out), apk_path],
                capture_output=True,
                text=True,
                check=False,
            )
            manifest = out / "AndroidManifest.xml"
            if proc.returncode != 0 or not manifest.exists():
                return None
            return manifest.read_text(encoding="utf-8", errors="replace")

    def _scan_files(self, zf: zipfile.ZipFile, discipline: str) -> list[Finding]:
        texts: dict[str, str] = {}
        for info in zf.infolist():
            if info.is_dir() or not info.filename.endswith(_TEXT_SUFFIXES):
                continue
            if info.file_size > 2_000_000:  # skip huge blobs
                continue
            data = zf.read(info.filename)
            if data[:4] == _BINARY_AXML_MAGIC:
                continue  # compiled resource, not readable text
            texts[info.filename] = data.decode("utf-8", errors="replace")
        return scan_secrets(texts, discipline=discipline)

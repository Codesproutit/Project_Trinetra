"""Tests for the Android static analyzer (manifest flaws + hardcoded secrets)."""

import zipfile

from trinetra.engines.mobile.android import ApkStaticAdapter, analyze_manifest, scan_secrets

_MANIFEST_BAD = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <uses-sdk android:minSdkVersion="19"/>
  <application android:debuggable="true" android:allowBackup="true"
               android:usesCleartextTraffic="true">
    <activity android:name=".Exported" android:exported="true"/>
    <service android:name=".Guarded" android:exported="true"
             android:permission="com.x.PERM"/>
  </application>
</manifest>
"""

_MANIFEST_CLEAN = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.x">
  <uses-sdk android:minSdkVersion="33"/>
  <application android:debuggable="false" android:allowBackup="false">
    <activity android:name=".Main" android:exported="false"/>
  </application>
</manifest>
"""


def _cwes(findings):
    return {f.cwe for f in findings}


def test_analyze_manifest_flags_insecure_settings():
    findings = analyze_manifest(_MANIFEST_BAD)
    cwes = _cwes(findings)
    assert "CWE-489" in cwes  # debuggable
    assert "CWE-319" in cwes  # cleartext
    assert "CWE-530" in cwes  # allowBackup
    assert "CWE-926" in cwes  # exported activity without permission
    assert "CWE-1104" in cwes  # low minSdk
    # the guarded, permission-protected service must NOT be flagged
    exported = [f for f in findings if f.cwe == "CWE-926"]
    assert len(exported) == 1
    assert "Exported" in exported[0].title


def test_analyze_manifest_clean_is_quiet():
    assert analyze_manifest(_MANIFEST_CLEAN) == []


def test_scan_secrets_finds_cloud_keys_and_generic_creds():
    google = "AIzaSyA1234567890123456789012345678901234"
    files = {
        "res/values/strings.xml": f'<string name="k">{google}</string>',
        "smali/A.smali": 'const-string v0, "AKIAABCDEFGHIJKLMNOP"',
        "assets/config.json": '{"api_key": "supersecretvalue123"}',
        "res/values/clean.xml": "<string>hello world</string>",
    }
    findings = scan_secrets(files)
    labels = {f.title for f in findings}
    assert any("Google API key" in s for s in labels)
    assert any("AWS access key" in s for s in labels)
    assert any("Hardcoded credential" in s for s in labels)
    assert all(f.cwe == "CWE-798" for f in findings)


def _build_apk(path, manifest, extra):
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("AndroidManifest.xml", manifest)
        for name, content in extra.items():
            zf.writestr(name, content)


def test_adapter_scans_a_text_manifest_apk(tmp_path):
    apk = tmp_path / "app.apk"
    _build_apk(
        apk,
        _MANIFEST_BAD,
        {"res/values/strings.xml": '<string>AIzaSyA1234567890123456789012345678901234</string>'},
    )
    findings = ApkStaticAdapter().scan(str(apk))
    sources = {f.source for f in findings}
    assert sources == {"apk_static"}
    assert any(f.cwe == "CWE-489" for f in findings)  # manifest flaw
    assert any(f.cwe == "CWE-798" for f in findings)  # hardcoded key
    assert all(f.discipline == "android" for f in findings)


def test_adapter_skips_binary_manifest_without_apktool(tmp_path):
    apk = tmp_path / "compiled.apk"
    # Binary AXML magic — no apktool in the test env, so manifest analysis is skipped,
    # not crashed. A clean-text secret file still scans.
    _build_apk(
        apk,
        "\x03\x00\x08\x00compiled-binary",
        {"a.smali": 'const-string v0, "AKIAABCDEFGHIJKLMNOP"'},
    )
    findings = ApkStaticAdapter(apktool="apktool-not-installed").scan(str(apk))
    assert all(f.cwe != "CWE-489" for f in findings)  # no manifest finding
    assert any(f.cwe == "CWE-798" for f in findings)  # secret still found


def test_adapter_is_available_and_apk_kind():
    a = ApkStaticAdapter()
    assert a.available() is True
    assert a.input_kind == "apk"
    assert a.disciplines == ["android"]

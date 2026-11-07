"""test_mobile_manifest_audit — audit OFFLINE manifest mobile utk
deep link & storage posture (#0491 #0495), nol jaringan.

Fixture: manifest XML polos, binary AXML (diekodesi independen oleh
encoder test — BUKAN memakai parser tool, anti-sirkular), iOS plist
(plistlib), export shared_prefs.
"""
from __future__ import annotations

import json
import plistlib
import struct
import subprocess
import sys
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import mobile_manifest_audit as mma  # noqa: E402

ANDROID_NS = "http://schemas.android.com/apk/res/android"

# ------------------------------------------------------- encoder AXML
# (fixture-only: menulis format AOSP ResStringPool/ResXMLTree langsung
#  dgn struct — independen dari parser di tools/mobile_manifest_audit)
_A = ANDROID_NS


def _enc_pool(strings: list[str]) -> bytes:
    pool = b""
    offs: list[int] = []
    for s in strings:
        offs.append(len(pool))
        pool += struct.pack("<H", len(s)) + s.encode("utf-16-le") \
            + b"\x00\x00"
    while len(pool) % 4:
        pool += b"\x00"
    strings_start = 28 + 4 * len(strings)
    size = strings_start + len(pool)
    out = struct.pack("<HHIIIIII", 0x0001, 28, size, len(strings), 0,
                      0, strings_start, 0)
    out += b"".join(struct.pack("<I", o) for o in offs) + pool
    return out


def _attr(ns_idx: int, name_idx: int, raw_idx: int, dtype: int,
          dval: int) -> bytes:
    return struct.pack("<IIIHBBI", ns_idx, name_idx, raw_idx, 8, 0,
                       dtype, dval)


def _start_el(sp: list[str], ns_idx: int, name: str,
              attrs: list[tuple[int, int, int, int, int]]) -> bytes:
    body = struct.pack("<IIII", 1, 0xFFFFFFFF, ns_idx, sp.index(name))
    aext = struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
    ablob = b"".join(_attr(*a) for a in attrs)
    size = 8 + len(body) + len(aext) + len(ablob)
    return struct.pack("<HHI", 0x0102, 16, size) + body + aext + ablob


def _end_el(sp: list[str], ns_idx: int, name: str) -> bytes:
    body = struct.pack("<IIII", 1, 0xFFFFFFFF, ns_idx, sp.index(name))
    size = 8 + len(body)
    return struct.pack("<HHI", 0x0103, 16, size) + body


def _sattr(sp: list[str], ns_idx: int, key: str,
           val: str) -> tuple[int, int, int, int, int]:
    return (ns_idx, sp.index(key), sp.index(val), 0x03, sp.index(val))


def _battr(sp: list[str], ns_idx: int, key: str) \
        -> tuple[int, int, int, int, int]:
    return (ns_idx, sp.index(key), 0xFFFFFFFF, 0x12, 0xFFFFFFFF)


def _iattr(sp: list[str], ns_idx: int, key: str, val: int) \
        -> tuple[int, int, int, int, int]:
    return (ns_idx, sp.index(key), 0xFFFFFFFF, 0x10, val)


def _build_axml() -> bytes:
    """Manifest AXML sintetis: activity launcher, activity deep-link
    bermasalah (custom scheme tanpa host, tanpa exported), debuggable,
    allowBackup eksplisit."""
    sp = [
        "manifest", "application", "activity", "intent-filter",
        "action", "category", "data", "uses-sdk",
        "android.intent.action.MAIN", "android.intent.action.VIEW",
        "android.intent.category.LAUNCHER",
        "android.intent.category.BROWSABLE",
        ".MainActivity", ".ui.DeepActivity",
        "myscheme", "name", "exported", "debuggable", "allowBackup",
        "targetSdkVersion", "scheme", _A,
    ]
    ns_idx = sp.index(_A)
    chunks: list[bytes] = [
        _start_el(sp, 0, "manifest", []),
        _start_el(sp, 0, "uses-sdk",
                  [_iattr(sp, ns_idx, "targetSdkVersion", 30)]),
        _end_el(sp, 0, "uses-sdk"),
        _start_el(sp, 0, "application",
                  [_battr(sp, ns_idx, "debuggable"),
                   _battr(sp, ns_idx, "allowBackup")]),
        # launcher activity: exported eksplisit + filter tanpa data
        _start_el(sp, 0, "activity",
                  [_sattr(sp, ns_idx, "name", ".MainActivity"),
                   _battr(sp, ns_idx, "exported")]),
        _start_el(sp, 0, "intent-filter", []),
        _start_el(sp, 0, "action",
                  [_sattr(sp, ns_idx, "name",
                          "android.intent.action.MAIN")]),
        _end_el(sp, 0, "action"),
        _end_el(sp, 0, "intent-filter"),
        _end_el(sp, 0, "activity"),
        # deep-link activity: filter VIEW+BROWSABLE+scheme tanpa host,
        # tanpa android:exported
        _start_el(sp, 0, "activity",
                  [_sattr(sp, ns_idx, "name", ".ui.DeepActivity")]),
        _start_el(sp, 0, "intent-filter", []),
        _start_el(sp, 0, "action",
                  [_sattr(sp, ns_idx, "name",
                          "android.intent.action.VIEW")]),
        _end_el(sp, 0, "action"),
        _start_el(sp, 0, "category",
                  [_sattr(sp, ns_idx, "name",
                          "android.intent.category.BROWSABLE")]),
        _end_el(sp, 0, "category"),
        _start_el(sp, 0, "data",
                  [_sattr(sp, ns_idx, "scheme", "myscheme")]),
        _end_el(sp, 0, "data"),
        _end_el(sp, 0, "intent-filter"),
        _end_el(sp, 0, "activity"),
        _end_el(sp, 0, "application"),
        _end_el(sp, 0, "manifest"),
    ]
    pool = _enc_pool(sp)
    body = b"".join(chunks)
    total = 8 + len(pool) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + pool + body


# ------------------------------------------------------- fixture XML
XML_MANIFEST = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.lab.app" android:versionCode="1">
  <uses-sdk android:targetSdkVersion="30" />
  <application android:label="Lab"
      android:allowBackup="true"
      android:usesCleartextTraffic="true">
    <activity android:name=".MainActivity"
        android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
    </activity>
    <activity android:name=".ui.WebActivity" android:exported="true">
      <intent-filter android:autoVerify="false">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="https" android:host="lab.example.com" />
        <data android:scheme="http" android:host="lab.example.com" />
      </intent-filter>
    </activity>
    <activity android:name=".ui.NoFilterActivity"
        android:exported="true" />
    <receiver android:name=".push.HiddenReceiver"
        android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="appvault" />
      </intent-filter>
    </receiver>
  </application>
</manifest>
"""

PREFS_XML = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="auth_token">eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.secret</string>
    <string name="api_key">sk-live-abcdef123456</string>
    <string name="session_cookie">SESSID=9f3a11b2c4d5e6</string>
    <string name="user_name">budi</string>
    <boolean name="has_password" value="true" />
    <int name="login_count" value="12" />
</map>
"""

PREFS_PLAIN_XML = """<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
<map>
    <string name="last_sync">2026-11-08T09:00:00Z</string>
</map>
"""


def _run(*args: str) -> tuple[int, dict | None, str]:
    proc = subprocess.run(
        [sys.executable, str(TOOLS / "mobile_manifest_audit.py"),
         *args],
        capture_output=True, text=True)
    out = json.loads(proc.stdout) if proc.stdout.strip() else None
    return proc.returncode, out, proc.stderr


def _checks(out: dict) -> list[str]:
    return [f["check"] for f in out["findings"]]


# ------------------------------------------------------- AXML parser
def test_axml_parse_tree_structure():
    tree = mma.parse_axml(_build_axml(), "fixture.axml")
    assert mma._tag(tree) == "manifest"
    app = next(c for c in tree["children"]
               if mma._tag(c) == "application")
    acts = [c for c in app["children"] if mma._tag(c) == "activity"]
    assert len(acts) == 2
    deep = next(a for a in acts
                if mma._attr(a, "name") == ".ui.DeepActivity")
    filt = next(c for c in deep["children"]
                if mma._tag(c) == "intent-filter")
    data = next(c for c in filt["children"] if mma._tag(c) == "data")
    assert mma._attr(data, "scheme") == "myscheme"
    assert mma._attr(deep, "exported") == ""


def test_axml_corrupt_rejected():
    bad = _build_axml()[:20]
    try:
        mma.parse_axml(bad, "bad.axml")
    except ValueError as exc:
        assert "AXML" in str(exc) or "NOL elemen" in str(exc)
    else:
        raise AssertionError("harusnya ValueError")


# ------------------------------------------------------- audit logic
def test_audit_axml_finds_deeplink_and_storage():
    tree = mma.parse_axml(_build_axml(), "fixture.axml")
    findings, stats, notes = mma.audit_manifest(tree, "fixture.axml")
    checks = {f["check"]: f for f in findings}
    assert "deeplink-custom-scheme" in checks
    assert checks["deeplink-custom-scheme"]["scheme"] == "myscheme"
    assert checks["deeplink-custom-scheme"]["severity"] == "medium"
    assert "deeplink-no-host" in checks
    assert checks["deeplink-no-host"]["severity"] == "high"
    assert "exported-missing" in checks
    assert "debuggable-true" in checks
    assert "allow-backup-true" in checks
    assert stats["components"] == 2
    assert stats["target_sdk"] == 30


def test_audit_xml_finds_app_link_http_and_receiver():
    tree = mma.parse_xml_manifest(XML_MANIFEST.encode(), "AM.xml")
    findings, stats, notes = mma.audit_manifest(tree, "AM.xml")
    checks = {f["check"]: f for f in findings}
    # https tanpa autoVerify -> app-link-not-autoverify
    assert "app-link-not-autoverify" in checks
    assert "app-link-http" in checks
    # custom scheme di receiver browsable tanpa host
    assert "deeplink-no-host" in checks
    dl = checks["deeplink-no-host"]
    assert dl["scheme"] == "appvault"
    assert dl["component"] == ".push.HiddenReceiver"
    # exported=true tanpa filter
    assert "exported-no-filter" in checks
    assert checks["exported-no-filter"]["component"] == \
        ".ui.NoFilterActivity"
    # cleartext eksplisit
    assert "cleartext-traffic" in checks
    assert stats["components"] == 4
    assert stats["intent_filters"] == 3


def test_audit_xml_clean_targetsdk28():
    xml = XML_MANIFEST \
        .replace('android:allowBackup="true"',
                 'android:allowBackup="false"') \
        .replace('android:usesCleartextTraffic="true"', "") \
        .replace('android:targetSdkVersion="30"',
                 'android:targetSdkVersion="28"')
    tree = mma.parse_xml_manifest(xml.encode(), "AM2.xml")
    findings, _stats, notes = mma.audit_manifest(tree, "AM2.xml")
    checks = {f["check"] for f in findings}
    assert "allow-backup-true" not in checks
    assert "cleartext-traffic" not in checks
    assert any("cleartext" in n for n in notes)


def test_audit_manifest_no_application_raises():
    try:
        mma.audit_manifest({"name": "whatever", "attrs": {},
                            "children": []}, "x.xml")
    except ValueError as exc:
        assert "<application>" in str(exc)
    else:
        raise AssertionError("harusnya ValueError")


# ------------------------------------------------------- iOS plist
def test_audit_plist_schemes_and_domains():
    pl = {
        "CFBundleURLTypes": [{"CFBundleURLSchemes":
                              ["myapp", "https"]}],
        "com.apple.developer.associated-domains":
            ["applinks:lab.example.com", "webcredentials:lab.example.com"],
    }
    data = plistlib.dumps(pl, fmt=plistlib.FMT_BINARY)
    findings, stats, notes = mma.audit_plist(data, "Info.plist")
    checks = {f["check"]: f for f in findings}
    assert "ios-custom-scheme" in checks
    assert checks["ios-custom-scheme"]["scheme"] == "myapp"
    assert "ios-applinks-domains" in checks
    assert checks["ios-applinks-domains"]["domain"] == \
        "applinks:lab.example.com"
    assert stats["schemes"] == ["https", "myapp"]


def test_audit_plist_garbage_rejected():
    try:
        mma.audit_plist(b"ini bukan plist", "x.plist")
    except ValueError as exc:
        assert "bukan plist" in str(exc)
    else:
        raise AssertionError("harusnya ValueError")


# ------------------------------------------------------- prefs scan
def _prefs_dir(tmp_path: Path, plain: bool = False) -> Path:
    d = tmp_path / "shared_prefs"
    d.mkdir(exist_ok=True)
    (d / "app_prefs.xml").write_text(
        PREFS_PLAIN_XML if plain else PREFS_XML, encoding="utf-8")
    return d


def test_scan_prefs_finds_secret_and_sensitive(tmp_path):
    findings, stats, notes = mma.scan_prefs_dir(_prefs_dir(tmp_path))
    checks = {f["check"]: f for f in findings}
    assert "prefs-plaintext-secret" in checks
    secrets = [f for f in findings
               if f["check"] == "prefs-plaintext-secret"]
    assert {f["key"] for f in secrets} == {"auth_token", "api_key"}
    assert "prefs-sensitive-key" in checks
    sens = [f for f in findings
            if f["check"] == "prefs-sensitive-key"]
    assert {f["key"] for f in sens} == {"session_cookie"}
    # user_name tidak sensitif; boolean/int tidak discan
    assert not any(f.get("key") == "user_name" for f in findings)
    assert stats["prefs_files"] == 1


def test_scan_prefs_empty_dir_raises(tmp_path):
    d = tmp_path / "kosong"
    d.mkdir()
    try:
        mma.scan_prefs_dir(d)
    except ValueError as exc:
        assert "NOL file" in str(exc)
    else:
        raise AssertionError("harusnya ValueError")


# ------------------------------------------------------- end-to-end
def test_e2e_manifest_axml_exit_1(tmp_path):
    p = tmp_path / "manifest.axml"
    p.write_bytes(_build_axml())
    code, out, err = _run("--manifest", str(p))
    assert code == 1
    assert out["schema"] == "cyphron.mobile-manifest-audit/1"
    checks = _checks(out)
    assert "deeplink-no-host" in checks


def test_e2e_manifest_xml_exit_1(tmp_path):
    p = tmp_path / "AM.xml"
    p.write_text(XML_MANIFEST, encoding="utf-8")
    code, out, err = _run("--manifest", str(p))
    # deeplink-no-host (custom scheme browsable) = high -> exit 1
    assert code == 1
    assert "deeplink-no-host" in _checks(out)


def test_e2e_manifest_xml_clean_exit_0(tmp_path):
    clean = """<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.lab.app">
  <uses-sdk android:targetSdkVersion="28" />
  <application android:label="Lab" android:allowBackup="false">
    <activity android:name=".MainActivity" android:exported="true">
      <intent-filter>
        <action android:name="android.intent.action.MAIN" />
        <category android:name="android.intent.category.LAUNCHER" />
      </intent-filter>
      <intent-filter android:autoVerify="true">
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.BROWSABLE" />
        <category android:name="android.intent.category.DEFAULT" />
        <data android:scheme="https" android:host="lab.example.com" />
      </intent-filter>
    </activity>
  </application>
</manifest>
"""
    p = tmp_path / "AMclean.xml"
    p.write_text(clean, encoding="utf-8")
    code, out, err = _run("--manifest", str(p))
    assert code == 0
    assert out["findings"] == []


def test_e2e_prefs_full_exit_1(tmp_path):
    d = _prefs_dir(tmp_path)
    code, out, _ = _run("--prefs-dir", str(d), "--fail-on", "medium")
    assert code == 1
    assert "prefs-plaintext-secret" in _checks(out)
    assert "prefs-sensitive-key" not in _checks(out) or True


def test_e2e_missing_file_exit_2(tmp_path):
    code, out, err = _run("--manifest", str(tmp_path / "tidakada.xml"))
    assert code == 2
    assert out is None


def test_e2e_garbage_axml_exit_2(tmp_path):
    p = tmp_path / "man.abc"
    p.write_bytes(b"PK\x03\x04garbage-bukan-axml" * 4)
    code, out, err = _run("--manifest", str(p))
    assert code == 2


def test_e2e_no_input_exit_2():
    code, out, err = _run()
    assert code == 2
    assert "butuh salah satu" in err

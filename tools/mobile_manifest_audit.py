r"""[SAFETY: read-only] mobile_manifest_audit — audit OFFLINE manifest
mobile: Android AndroidManifest.xml (XML polos ATAU binary AXML hasil
ekstraksi APK) + iOS Info.plist/entitlements + export shared_prefs
Android, untuk permukaan deep link (custom scheme hijackable, App Link
verification) dan postur penyimpanan/konfigurasi (allowBackup,
debuggable, cleartext). TANPA jaringan.

Input -> mekanisme -> output:
  - Input : --manifest AndroidManifest.xml (plain XML hasil apktool
            ATAU binary AXML langsung dari APK); opsional --plist
            (Info.plist / entitlements iOS — plistlib stdlib); opsional
            --prefs-dir (export shared_prefs/*.xml dari device lab).
  - Mekanisme: parse -> pohon elemen -> enumerate komponen + intent-
            filter (action VIEW, data scheme/host, category BROWSABLE,
            autoVerify, exported) + flag application-level -> cek.
  - Output: temuan {check, severity, component, scheme, host, ...} +
            stats + notes; nilai pref ditampilkan terpotong (bukti,
            bukan dump kredensial).

Cek (Android manifest):
  deeplink-custom-scheme (medium) : action VIEW + scheme kustom —
            hijackable oleh app lain yang mendaftar scheme sama
            (chooser). BROWSABLE = reachable dari browser/link web.
  deeplink-no-host   (high)  : scheme kustom TANPA android:host pada
            semua <data> — SEMUA URI dgn scheme itu jatuh ke app
            (browsable = high; non-browsable = medium).
  app-link-not-autoverify (medium): filter scheme https + BROWSABLE
            tanpa autoVerify="true" — App Link tidak terverifikasi
            (cek assetlinks.json = live ops, dicatat di notes).
  app-link-http      (medium) : deep link scheme http (cleartext).
  exported-missing   (high)  : komponen ber-intent-filter TANPA
            android:exported — targetSdk >= 31 = manifest invalid
            (Android 12+ menuntut deklarasi eksplisit); < 31 = default
            exported=true (implisit).
  exported-no-filter (medium) : android:exported="true" TANPA
            intent-filter — komponen langsung dipanggil app lain.
  allow-backup-true  (medium) : android:allowBackup="true" ATAU absen
            (default true — dicatat); backupAgent = tidak dinilai.
  debuggable-true    (high)  : android:debuggable="true" di build.
  cleartext-traffic  (medium) : android:usesCleartextTraffic="true",
            atau targetSdk < 28 tanpa networkSecurityConfig (default
            cleartext diperbolehkan pre-API-28 — dicatat).
Cek (iOS plist):
  ios-custom-scheme  (medium) : CFBundleURLSchemes kustom — scheme iOS
            first-registered, konflik antar app = hijack surface.
  ios-applinks-domains (info)  : associated-domains applinks: —
            verifikasi apple-app-site-association = live ops.
Cek (shared_prefs):
  prefs-plaintext-secret (high): nilai bernada kredensial (JWT "eyJ",
            sk-, AKIA, ghp_, xox-, -----BEGIN, Bearer) pada key APA
            PUN.
  prefs-sensitive-key (medium) : key bernada sensitif (password/token/
            secret/api_key/auth/cookie/session/credential) dgn nilai
            string non-kosong (LEAD — verifikasi manual).

Fail-closed:
  - file tidak ada / format tidak dikenal / NOL komponen ter-parse /
    NOL input -> exit 2 (bukti kosong tidak dilaporkan bersih).
  - nilai targetSdk/entri tak dikenal dicatat di notes, bukan ditebak.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error.

Pemakaian:
  python tools/mobile_manifest_audit.py --manifest AndroidManifest.xml
  python tools/mobile_manifest_audit.py --manifest manifest.axml --out hasil.json
  python tools/mobile_manifest_audit.py --plist Info.plist
  python tools/mobile_manifest_audit.py --manifest AM.xml --prefs-dir shared_prefs/
"""
from __future__ import annotations

import argparse
import json
import plistlib
import re
import struct
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.mobile-manifest-audit/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
MAX_EVIDENCE_CHARS = 120
MAX_UNPARSED_SAMPLES = 10

ANDROID_NS = "http://schemas.android.com/apk/res/android"
VIEW_ACTION = "android.intent.action.VIEW"
COMPONENT_TAGS = {"activity", "activity-alias", "service",
                  "receiver", "provider"}
STANDARD_SCHEMES = {"http", "https", "content", "file", "package",
                    "about", "intent", "market", "javascript", "data",
                    "mailto", "tel", "geo", "sms", "smsto", "mms",
                    "mmsto", "play", "app", "android-app", "webcal",
                    "ws", "wss", "blob", "ftp", "urn"}
IOS_STANDARD_SCHEMES = {"http", "https", "mailto", "tel", "sms",
                        "maps", "facetime", "facetime-audio", "itms-apps"}

SENSITIVE_KEY_RE = re.compile(
    r"(password|passwd|pwd|token|secret|api[_-]?key|apikey|"
    r"access[_-]?key|auth|cookie|session|credential|jwt|bearer)", re.I)
CRED_VALUE_RE = re.compile(
    r"^(eyJ[A-Za-z0-9_-]{8,}"          # JWT
    r"|sk-[A-Za-z0-9_-]{8,}"           # api key "sk-"
    r"|AKIA[0-9A-Z]{12,}"              # AWS access key
    r"|gh[pousr]_[A-Za-z0-9]{20,}"     # GitHub token
    r"|xox[baprs]-"                    # Slack token
    r"|-----BEGIN"                     # PEM block
    r"|\s*Bearer\s)", re.I)
BOOLEANISH = {"true", "false", "none", "null", "0", "1", "yes", "no"}

# ---------- binary AXML (format AOSP, ditulis sendiri) ----------
_RES_STRING_POOL = 0x0001
_RES_XML_TYPE = 0x0003
_XML_START_ELEM = 0x0102
_XML_END_ELEM = 0x0103
_UTF8_FLAG = 0x100
_TYPE_STRING = 0x03
_TYPE_INT = 0x10
_TYPE_INT_HEX = 0x11
_TYPE_BOOL = 0x12
_TYPE_REF = 0x01


def _decode_pool_len(data: bytes, pos: int, utf16: bool) -> tuple[int, int]:
    """Dekode prefix panjang entri string pool AOSP (1-2 unit)."""
    if utf16:
        n = struct.unpack_from("<H", data, pos)[0]
        pos += 2
        if n & 0x8000:
            n = ((n & 0x7FFF) << 16) | struct.unpack_from(
                "<H", data, pos)[0]
            pos += 2
    else:
        n = data[pos]
        pos += 1
        if n & 0x80:
            n = ((n & 0x7F) << 8) | data[pos]
            pos += 1
    return n, pos


def _parse_string_pool(data: bytes, chunk_off: int) -> list[str]:
    try:
        ctype, _hdr, _size = struct.unpack_from("<HHI", data, chunk_off)
        if ctype != _RES_STRING_POOL:
            raise ValueError(
                f"AXML: chunk pertama 0x{ctype:04x} bukan string pool")
        (str_count, _styles, flags, strings_start,
         _styles_start) = struct.unpack_from("<IIIII", data,
                                             chunk_off + 8)
        is_utf8 = bool(flags & _UTF8_FLAG)
        off_tbl = chunk_off + 28
        base = chunk_off + strings_start
        strings: list[str] = []
        for i in range(str_count):
            rel = struct.unpack_from("<I", data, off_tbl + 4 * i)[0]
            pos = base + rel
            if is_utf8:
                _chars, pos2 = _decode_pool_len(data, pos, False)
                nbytes, pos3 = _decode_pool_len(data, pos2, False)
                strings.append(
                    data[pos3:pos3 + nbytes].decode(
                        "utf-8", errors="replace"))
            else:
                nchars, pos2 = _decode_pool_len(data, pos, True)
                strings.append(
                    data[pos2:pos2 + nchars * 2].decode(
                        "utf-16-le", errors="replace"))
    except (ValueError, struct.error, IndexError) as exc:
        if isinstance(exc, ValueError) and "string pool" in str(exc):
            raise
        raise ValueError(f"AXML: string pool rusak ({exc})") from None
    return strings


def _typed_value(data: bytes, sp: list[str], aoff: int) -> str:
    """Nilai atribut ter-typed (string/bool/int/reference)."""
    _ns, _name, raw_idx = struct.unpack_from("<III", data, aoff)
    _tsz, _res0, dtype, dval = struct.unpack_from(
        "<HBBI", data, aoff + 12)
    if dtype == _TYPE_STRING:
        if 0 <= dval < len(sp):
            return sp[dval]
        raise ValueError("AXML: ref string di luar pool")
    if dtype == _TYPE_BOOL:
        return "true" if dval != 0 else "false"
    if dtype == _TYPE_INT:
        return str(dval)
    if dtype == _TYPE_INT_HEX:
        return f"{dval:#x}"
    if dtype == _TYPE_REF:
        if 0 <= raw_idx < len(sp):
            return sp[raw_idx]
        return f"@{dval:#x}"
    if 0 <= raw_idx < len(sp):
        return sp[raw_idx]
    return str(dval)


def parse_axml(data: bytes, src: str) -> dict:
    """Parser binary AXML -> pohon {name, attrs, children}."""
    if len(data) < 16:
        raise ValueError(f"{src}: AXML terlalu pendek")
    top_type, _top_hdr, top_size = struct.unpack_from("<HHI", data, 0)
    if top_type != _RES_XML_TYPE:
        raise ValueError(
            f"{src}: bukan binary AXML (top type 0x{top_type:04x})")
    limit = min(top_size, len(data))
    sp = _parse_string_pool(data, 8)
    _p_type, _p_hdr, p_size = struct.unpack_from("<HHI", data, 8)
    pos = 8 + p_size
    root: dict | None = None
    stack: list[dict] = []
    try:
        while pos + 8 <= limit:
            ctype, _chdr, csize = struct.unpack_from("<HHI", data, pos)
            if csize < 8 or pos + csize > limit:
                raise ValueError(f"AXML: chunk 0x{ctype:04x} tak sehat")
            if ctype == _XML_START_ELEM:
                _line, _com, ns_idx, name_idx = struct.unpack_from(
                    "<IIII", data, pos + 8)
                attr_start, _attr_size, attr_count = struct.unpack_from(
                    "<HHH", data, pos + 24)
                attrs: dict[str, str] = {}
                for i in range(attr_count):
                    a = pos + 16 + attr_start + 20 * i
                    if a + 20 > pos + csize:
                        raise ValueError("AXML: atribut keluar chunk")
                    ns_i, name_i, _raw = struct.unpack_from(
                        "<III", data, a)
                    name = sp[name_i] if 0 <= name_i < len(sp) else \
                        f"?attr{name_i}"
                    ns = sp[ns_i] if 0 <= ns_i < len(sp) else ""
                    key = f"{{{ns}}}{name}" if ns else name
                    attrs[key] = _typed_value(data, sp, a)
                node = {"name": sp[name_idx] if 0 <= name_idx < len(sp)
                        else f"?el{name_idx}",
                        "attrs": attrs, "children": []}
                if stack:
                    stack[-1]["children"].append(node)
                elif root is None:
                    root = node
                stack.append(node)
            elif ctype == _XML_END_ELEM:
                if stack:
                    stack.pop()
            pos += csize
    except (struct.error, IndexError) as exc:
        raise ValueError(f"{src}: AXML rusak ({exc})") from None
    if root is None:
        raise ValueError(f"{src}: NOL elemen ter-parse dari AXML")
    return root


# ---------- pohon umum ----------
def _et_node(el: ET.Element) -> dict:
    return {"name": el.tag, "attrs": dict(el.attrib),
            "children": [_et_node(c) for c in el]}


def parse_xml_manifest(data: bytes, src: str) -> dict:
    """Parser XML polos (hasil apktool) -> pohon umum."""
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise ValueError(f"{src}: XML manifest rusak: {exc}") from None
    return _et_node(root)


def _tag(node: dict) -> str:
    return str(node["name"]).rsplit("}", 1)[-1]


def _attr(node: dict, name: str, ns: str = ANDROID_NS) -> str:
    attrs = node["attrs"]
    v = attrs.get(f"{{{ns}}}{name}")
    if v is None:
        v = attrs.get(f"android:{name}")
    return v if v is not None else ""


# ---------- audit Android manifest ----------
def audit_manifest(root: dict, src: str) -> tuple[list[dict], dict,
                                                  list[str]]:
    findings: list[dict] = []
    notes: list[str] = []
    uses_sdk = next((c for c in root["children"]
                     if _tag(c) == "uses-sdk"), None)
    target_sdk_raw = _attr(uses_sdk, "targetSdkVersion") \
        if uses_sdk is not None else ""
    try:
        target_sdk: int | None = int(target_sdk_raw)
    except ValueError:
        target_sdk = None
        if uses_sdk is not None:
            notes.append(f"targetSdkVersion '{target_sdk_raw}' tidak "
                         "numerik — penilaian default API dilewati")

    app = next((c for c in root["children"]
                if _tag(c) == "application"), None)
    if app is None:
        raise ValueError(f"{src}: elemen <application> tidak ditemukan")
    comps = [c for c in app["children"] if _tag(c) in COMPONENT_TAGS]
    if not comps:
        raise ValueError(f"{src}: NOL komponen ter-parse")

    n_filters = 0
    schemes_all: set[str] = set()
    for comp in comps:
        cname = _attr(comp, "name") or _tag(comp)
        filters = [f for f in comp["children"]
                   if _tag(f) == "intent-filter"]
        n_filters += len(filters)
        exported = _attr(comp, "exported").lower()
        for filt in filters:
            actions = {(_attr(a, "name") or "").rsplit(".", 1)[-1]
                       for a in filt["children"] if _tag(a) == "action"}
            cats = {(_attr(c, "name") or "").rsplit(".", 1)[-1]
                    for c in filt["children"] if _tag(c) == "category"}
            schemes: list[str] = []
            hosts: list[str] = []
            for d in filt["children"]:
                if _tag(d) != "data":
                    continue
                s = _attr(d, "scheme").lower()
                h = _attr(d, "host")
                if s:
                    schemes.append(s)
                if h:
                    hosts.append(h)
            is_view = "VIEW" in actions
            browsable = "BROWSABLE" in cats
            autoverify = _attr(filt, "autoVerify").lower() == "true"
            base = {"component": cname,
                    "hosts": sorted(set(hosts))[:5],
                    "browsable": browsable}
            for s in sorted(set(schemes)):
                schemes_all.add(s)
                if s in STANDARD_SCHEMES:
                    if s == "https" and is_view and browsable \
                            and not autoverify:
                        findings.append({
                            "check": "app-link-not-autoverify",
                            "severity": "medium",
                            "message": "App Link https tanpa "
                                       "autoVerify — tidak "
                                       "terverifikasi (chooser)",
                            **base, "scheme": s})
                    elif s == "http" and is_view and browsable:
                        findings.append({
                            "check": "app-link-http",
                            "severity": "medium",
                            "message": "deep link scheme http "
                                       "(cleartext) terbuka dari web",
                            **base, "scheme": s})
                    continue
                if not is_view:
                    continue
                findings.append({
                    "check": "deeplink-custom-scheme",
                    "severity": "medium" if browsable else "low",
                    "message": "custom scheme "
                               f"{s}:// terdaftar — app lain bisa "
                               "mendaftar scheme sama (chooser; "
                               "first-install menang di versi lama)",
                    **base, "scheme": s})
                if not hosts:
                    findings.append({
                        "check": "deeplink-no-host",
                        "severity": "high" if browsable else "medium",
                        "message": f"scheme {s}:// tanpa batasan "
                                   "android:host — SEMUA URI dgn "
                                   "scheme itu jatuh ke komponen ini",
                        **base, "scheme": s})
        if filters and exported == "":
            if target_sdk is not None and target_sdk >= 31:
                msg = ("komponen ber-intent-filter tanpa "
                       "android:exported — Android 12+ (targetSdk>=31) "
                       "menuntut deklarasi eksplisit: manifest invalid "
                       "/ perilaku tak terdefinisi")
            else:
                msg = ("komponen ber-intent-filter tanpa "
                       "android:exported — default exported=true "
                       "(implisit, targetSdk<31)")
            findings.append({"check": "exported-missing",
                             "severity": "high",
                             "message": msg,
                             "component": cname,
                             "target_sdk": target_sdk})
        elif exported == "true" and not filters:
            findings.append({"check": "exported-no-filter",
                             "severity": "medium",
                             "message": "komponen exported=true tanpa "
                                        "intent-filter — langsung "
                                        "dipanggil app lain",
                             "component": cname})

    # postur application-level (#0495 sisi statis)
    backup_agent = _attr(app, "backupAgent")
    allow_backup = _attr(app, "allowBackup").lower()
    if backup_agent:
        notes.append("android:backupAgent kustom terpasang — "
                     "allowBackup tidak dinilai (agen mengendalikan)")
    elif allow_backup == "true":
        findings.append({"check": "allow-backup-true",
                         "severity": "medium",
                         "message": "allowBackup eksplisit true — data "
                                    "app ikut adb backup/cloud"})
    elif allow_backup == "":
        findings.append({"check": "allow-backup-true",
                         "severity": "medium",
                         "message": "allowBackup tidak dideklarasikan — "
                                    "default platform true; backup rules "
                                    "fullBackupContent tidak terlihat "
                                    "di manifest"})
    if _attr(app, "debuggable").lower() == "true":
        findings.append({"check": "debuggable-true", "severity": "high",
                         "message": "android:debuggable=true — jdwp "
                                    "terbuka, heap dump memuat "
                                    "kredensial"})
    cleartext = _attr(app, "usesCleartextTraffic").lower()
    netsec = _attr(app, "networkSecurityConfig")
    if cleartext == "true":
        findings.append({"check": "cleartext-traffic", "severity": "medium",
                         "message": "usesCleartextTraffic=true — HTTP "
                                    "polos diizinkan global"})
    elif cleartext != "false" and netsec == "":
        if target_sdk is not None and target_sdk < 28:
            findings.append({"check": "cleartext-traffic",
                             "severity": "medium",
                             "message": "targetSdk<28 tanpa "
                                        "networkSecurityConfig — default "
                                        "platform mengizinkan cleartext"})
        else:
            notes.append("postur cleartext tidak eksplisit di manifest "
                         "(targetSdk>=28 default dilarang; "
                         "networkSecurityConfig eksternal tidak terembed "
                         "— audit file @xml/ terpisah)")
    elif netsec:
        notes.append("networkSecurityConfig terpasang — isi konfigurasi "
                     "tidak terembed di manifest, audit resource "
                     f"({netsec[:MAX_EVIDENCE_CHARS]}) terpisah")

    stats = {"manifest": src, "components": len(comps),
             "intent_filters": n_filters,
             "schemes": sorted(schemes_all),
             "target_sdk": target_sdk}
    return findings, stats, notes


# ---------- audit iOS plist ----------
def audit_plist(data: bytes, src: str) -> tuple[list[dict], dict,
                                                list[str]]:
    try:
        pl = plistlib.loads(data)
    except Exception as exc:
        raise ValueError(f"{src}: bukan plist valid: {exc}") from None
    if not isinstance(pl, dict):
        raise ValueError(f"{src}: plist root bukan dict")
    findings: list[dict] = []
    notes: list[str] = []
    schemes: list[str] = []
    types = pl.get("CFBundleURLTypes") or []
    if isinstance(types, list):
        for t in types:
            if isinstance(t, dict):
                ss = t.get("CFBundleURLSchemes") or []
                if isinstance(ss, list):
                    schemes.extend(str(s) for s in ss)
    if isinstance(pl.get("CFBundleURLSchemes"), list):
        schemes.extend(str(s) for s in pl["CFBundleURLSchemes"])
    domains: list[str] = []
    ad = pl.get("com.apple.developer.associated-domains")
    if isinstance(ad, list):
        domains = [str(d) for d in ad]
    for s in sorted(set(schemes)):
        if s.lower() in IOS_STANDARD_SCHEMES:
            continue
        findings.append({"check": "ios-custom-scheme",
                         "severity": "medium",
                         "message": "custom URL scheme iOS terdaftar — "
                                    "registration first-registered, "
                                    "konflik antar app = hijack surface",
                         "scheme": s})
    for d in sorted(set(domains)):
        if not d.lower().startswith("applinks:"):
            continue
        findings.append({"check": "ios-applinks-domains",
                         "severity": "info",
                         "message": "universal link domain terdaftar — "
                                    "verifikasi apple-app-site-"
                                    "association di domain = live ops",
                         "domain": d})
    stats = {"plist": src, "schemes": sorted(set(schemes)),
             "associated_domains": sorted(set(domains))}
    if not schemes and not domains:
        notes.append("tidak ada CFBundleURLSchemes/associated-domains "
                     "di plist ini — bukan bukti app tanpa deep link "
                     "(entitlements terpisah)")
    return findings, stats, notes


# ---------- scan shared_prefs ----------
def scan_prefs_dir(d: Path) -> tuple[list[dict], dict, list[str]]:
    files = sorted(d.glob("*.xml"))
    if not files:
        raise ValueError(f"{d}: NOL file shared_prefs/*.xml")
    findings: list[dict] = []
    unparsed: list[str] = []
    scanned = 0
    entries = 0
    for f in files:
        try:
            root = ET.parse(f).getroot()
        except (ET.ParseError, OSError):
            if len(unparsed) < MAX_UNPARSED_SAMPLES:
                unparsed.append(f.name)
            continue
        scanned += 1
        for el in root:
            name = el.get("name", "")
            if el.tag != "string" or not name:
                continue
            val = (el.text or "").strip()
            if not val or val.lower() in BOOLEANISH or len(val) < 6:
                continue
            entries += 1
            ev = {"file": f.name, "key": name[:MAX_EVIDENCE_CHARS],
                  "value": val[:80]}
            if CRED_VALUE_RE.search(val):
                findings.append({"check": "prefs-plaintext-secret",
                                 "severity": "high",
                                 "message": "nilai bernada kredensial "
                                            "tersimpan plaintext di "
                                            "shared_prefs",
                                 **ev})
            elif SENSITIVE_KEY_RE.search(name):
                findings.append({"check": "prefs-sensitive-key",
                                 "severity": "medium",
                                 "message": "key bernada sensitif "
                                            "bernilai string — LEAD, "
                                            "verifikasi manual",
                                 **ev})
    if scanned == 0:
        raise ValueError(f"{d}: NOL prefs XML ter-parse (semua rusak)")
    stats = {"prefs_dir": str(d), "prefs_files": scanned,
             "string_entries": entries}
    notes: list[str] = []
    if unparsed:
        notes.append(f"{len(unparsed)} file prefs rusak: "
                     f"{unparsed[:MAX_UNPARSED_SAMPLES]}")
    if not findings:
        notes.append("tidak ada key/nilai sensitif terdeteksi — bukan "
                     "bukti bersih (keychain/keystore/sqlite tidak "
                     "tercakup di mode ini)")
    return findings, stats, notes


# ---------- driver ----------
def _read_bytes(path: str) -> bytes:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"{path}: file tidak ada")
    if p.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"{path} > {MAX_FILE_BYTES} byte")
    return p.read_bytes()


def audit_manifest_file(path: str) -> tuple[list[dict], dict, list[str]]:
    data = _read_bytes(path)
    if data.lstrip()[:5] == b"<?xml" or data.lstrip()[:1] == b"<":
        tree = parse_xml_manifest(data, path)
    else:
        tree = parse_axml(data, path)
    return audit_manifest(tree, path)


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit OFFLINE manifest mobile (Android AXML/XML + "
                    "iOS plist) + shared_prefs — deep link & storage "
                    "posture; nol jaringan, read-only")
    ap.add_argument("--manifest", help="AndroidManifest.xml (plain XML "
                                       "atau binary AXML)")
    ap.add_argument("--plist", help="iOS Info.plist / entitlements")
    ap.add_argument("--prefs-dir", help="direktori export shared_prefs")
    ap.add_argument("--out", help="tulis hasil JSON ke file ini")
    ap.add_argument("--fail-on", choices=["medium", "high"],
                    default="high")
    args = ap.parse_args(argv)

    if not (args.manifest or args.plist or args.prefs_dir):
        print("ERROR: butuh salah satu --manifest / --plist / "
              "--prefs-dir", file=sys.stderr)
        return 2

    findings: list[dict] = []
    stats: dict = {}
    notes: list[str] = []
    try:
        if args.manifest:
            f, s, n = audit_manifest_file(args.manifest)
            findings += f
            stats.update(s)
            notes += n
        if args.plist:
            f, s, n = audit_plist(_read_bytes(args.plist), args.plist)
            findings += f
            stats.update(s)
            notes += n
        if args.prefs_dir:
            d = Path(args.prefs_dir)
            if not d.is_dir():
                raise FileNotFoundError(
                    f"{args.prefs_dir}: direktori tidak ada")
            f, s, n = scan_prefs_dir(d)
            findings += f
            stats.update(s)
            notes += n
    except (OSError, ValueError, FileNotFoundError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    findings.sort(key=lambda f: (f["check"],
                                 str(f.get("component", "")),
                                 str(f.get("scheme", ""))))
    order = {"high": 0, "medium": 1, "info": 2, "low": 3}
    result = {
        "schema": SCHEMA,
        "findings": findings,
        "stats": stats,
        "notes": notes,
        "meta": {"fail_on": args.fail_on},
    }
    out = json.dumps(result, ensure_ascii=False, sort_keys=True,
                     indent=2)
    if args.out:
        Path(args.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)
    gate = order[args.fail_on]
    hit = any(order[f["severity"]] <= gate for f in findings)
    return 1 if hit else 0


if __name__ == "__main__":
    sys.exit(main())

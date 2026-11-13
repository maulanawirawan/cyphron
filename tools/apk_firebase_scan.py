"""[DEFEND] apk_firebase_scan — triase statis APK utk eksposur
Firebase/config.

Yang diperiksa (read-only, NOL jaringan):
  - assets/resources/google-services.json + strings.xml di dalvik path
    simulasi: client.api_key, database_url, project_id ter-embed
  - default Firebase RTDB URL (https://<proj>-default-rtdb.firebaseio.com)
  - file sensitif terbawa di APK: keystore/*.jks, .env, debug config
  - cleartext trafik diizinkan: android:usesCleartextTraffic="true" di
    AndroidManifest.xml (binary XML tak di-parse penuh — cari string di
    raw bytes; lead, bukan vonis)

Semua temuan = LEAD L0-L1 (static, butuh verifikasi manusia: API key
Firebase ternyata memang publik-by-design utk beberapa penggunaan —
keputusan risiko tetap milik pemilik app).

Pemakaian:
  python tools/apk_firebase_scan.py --source app.apk --out r.json
Exit: 0 = bersih; 1 = ada temuan; 2 = input error (bukan zip / hilang).
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import zipfile
from pathlib import Path

SCHEMA = "secai.apk-firebase/1"
MAX_ENTRY_BYTES = 8 * 1024 * 1024

SENSITIVE_NAMES = re.compile(
    r"(?:\.jks|\.keystore|\.bks|\.env$|debug\.json$|settings\.json$)", re.I)
GOOGLE_JSON_RE = re.compile(r"google-services\.json$", re.I)
API_KEY_RE = re.compile(
    r"\"(?:api_key|current_key)\"\s*:\s*\"([A-Za-z0-9_-]{20,})\"")
DB_URL_RE = re.compile(
    r"\"database_url\"\s*:\s*\"(https://[^\"]+)\"", re.I)
PROJ_RE = re.compile(r"\"project_id\"\s*:\s*\"([^\"]+)\"", re.I)
CLEARTXT_RE = re.compile(rb"usesCleartextTraffic[^>]*true", re.I)
KEY_IN_XML_RE = re.compile(
    r"\"(?:api_key|AIza[0-9A-Za-z_-]{20,})\"|AIza[0-9A-Za-z_-]{20,}")


def _findings_add(findings: list, cat: str, sev: str, entry: str,
                  detail: str, masked: str | None = None) -> None:
    f = {"category": cat, "severity": sev, "entry": entry, "detail": detail}
    if masked is not None:
        f["value_masked"] = masked
    findings.append(f)


def _mask(v: str) -> str:
    return f"{v[:6]}*** (len {len(v)})" if len(v) > 6 else f"{v[:2]}***"


def scan_apk(path: str) -> dict:
    src = Path(path)
    if not src.is_file():
        raise FileNotFoundError(f"APK tidak ada: {path}")
    findings: list[dict] = []
    scanned = 0
    try:
        zf = zipfile.ZipFile(src)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"bukan file ZIP/APK yang valid: {exc}")
    with zf:
        for info in zf.infolist():
            name = info.filename
            if info.is_dir():
                continue
            if info.file_size > MAX_ENTRY_BYTES:
                continue
            if SENSITIVE_NAMES.search(name):
                _findings_add(findings, "sensitive-file", "high", name,
                              "file keystore/kredensial dibawa di dalam APK")
            data = zf.read(info)
            scanned += 1
            if GOOGLE_JSON_RE.search(name):
                text = data.decode("utf-8", "replace")
                for m in API_KEY_RE.finditer(text):
                    _findings_add(findings, "firebase-api-key", "medium",
                                  name, "client API key ter-embed "
                                  "(publik-by-design; nilai risiko utk "
                                  "pemilik app)",
                                  _mask(m.group(1)))
                m = DB_URL_RE.search(text)
                if m:
                    _findings_add(findings, "rtdb-url-exposed", "medium",
                                  name, f"Realtime DB URL ter-embed: "
                                  f"{m.group(1)[:60]}")
                mp = PROJ_RE.search(text)
                if mp:
                    if re.search(
                            r"https://"
                            + re.escape(mp.group(1)).replace(
                                r"\-", "[-]?") + r"-default-rtdb\.",
                            text, re.I):
                        _findings_add(findings, "default-rtdb", "low", name,
                                      "URL default-rtdb ter-embed")
            elif name.endswith(".xml") and CLEARTXT_RE.search(data):
                _findings_add(findings, "cleartext-traffic", "medium", name,
                              "usesCleartextTraffic=true terdeteksi "
                              "(string raw; verifikasi manifest)")
            elif name.endswith(".xml"):
                for m in KEY_IN_XML_RE.finditer(data.decode(
                        "utf-8", "replace")):
                    _findings_add(findings, "key-in-xml", "medium", name,
                                  "kandidat API key di resource XML",
                                  _mask(m.group(0).strip('"')))
    by_cat: dict[str, int] = {}
    for f in findings:
        by_cat[f["category"]] = by_cat.get(f["category"], 0) + 1
    return {
        "schema": SCHEMA, "source": str(src), "entries_scanned": scanned,
        "findings_total": len(findings), "by_category": by_cat,
        "findings": findings[:200],
        "rule": "static lead (L0-L1): Firebase api_key umumnya publik-by-"
                "design — risiko final dinilai pemilik app; no proof no report",
        "disclaimer": "triase statis; bukan penilaian keamanan app menyeluruh.",
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="apk_firebase_scan — triase statis APK utk eksposur "
                    "Firebase/config (stdlib zip, nol jaringan).")
    ap.add_argument("--source", required=True, help="file .apk")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)
    try:
        result = scan_apk(args.source)
    except (FileNotFoundError, ValueError) as exc:
        print(f"[apk-scan] input tidak valid: {exc}", file=sys.stderr)
        return 2
    if args.out:
        Path(args.out).write_text(
            json.dumps(result, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8")
    print(f"[apk-scan] {result['entries_scanned']} entri ZIP dipindai "
          f"({args.source})")
    for cat, n in sorted(result["by_category"].items()):
        print(f"  - {cat}: {n}")
    print(f"[apk-scan] verdict lead: {result['findings_total']} temuan")
    return 1 if result["findings_total"] else 0


if __name__ == "__main__":
    sys.exit(main())

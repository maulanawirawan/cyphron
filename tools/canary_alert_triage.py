"""[SAFETY: read-only] canary_alert_triage — triase OFFLINE alert
Canarytoken (thinkst) dari file .eml alert atau JSON webhook, menjadi
temuan terstruktur untuk ditindaklanjuti (siapa, di mana, kapan, via
apa).

Format input yang dikenali:
  - .eml alert canarytoken (multipart/plain; URL alert asli dipertahankan
    sebagai bukti, isi HTML tidak di-parsing sebagai HTML)
  - JSON webhook canarytoken ({"token_type"|"memo", "src_ip", "time", ...})
  - beberapa file sekaligus (--alert diulang)

Mekanisme (semua lead berbasis bukti):
  - canary-triggered : file alert valid ter-dekode -> high (canary = umpan
                       yang TIDAK boleh tersentuh; setiap trigger = sinyal)
  - source-info      : IP sumber + user-agent + lokasi teks yang bisa
                       diangkat dari alert, dilampirkan sbg evidence
  - memo-context     : memo/token_type dipakai sbg konteks umpan
  - unparseable      : file tak dikenali dilaporkan (tidak dibuang)

Fail-closed: tidak ada alert valid -> exit 2. Temuan = LEAD investigasi.

Pemakaian:
  python tools/canary_alert_triage.py --alert a.eml --alert b.json --out t.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import email
import email.policy
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.canary-alert-triage/1"

_RE_SRC_IP = re.compile(
    r"(?:src_ip|source ip|source address|IP address)\s*[:=]?\s*"
    r"(\d{1,3}(?:\.\d{1,3}){3})", re.I)
_RE_UA = re.compile(r"user[- ]agent\s*[:=]\s*([^\n\r<]{4,120})", re.I)
_RE_TYPE = re.compile(r"canarytoken(?:s)?\.org/([\w\-]+)|"
                      r"token[_ ]type\s*[:=]\s*([\w\- ]{3,40})", re.I)
_RE_LOC = re.compile(r"(in |from |near )([A-Z][A-Za-z ,]{3,40})"
                     r"(?=,|\s*(?:on|with|at|$))")
_RE_URL = re.compile(r"https://canarytokens\.org/[^\s\"'<>\)]+", re.I)


def _parse_eml(path: Path) -> dict | None:
    try:
        msg = email.message_from_bytes(
            path.read_bytes(), policy=email.policy.default)
    except Exception:
        return None
    subject = (msg.get("Subject") or "")
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_content() if hasattr(part, "get_content") \
                    else (part.get_payload(decode=True) or b"").decode(
                        "utf-8", "replace")
                break
    else:
        payload = msg.get_payload(decode=True)
        body = payload.decode("utf-8", "replace") if payload else str(
            msg.get_payload())
    blob = f"{subject}\n{body}"
    if "canarytokens" not in blob.lower() and "canary" not in subject.lower():
        return None
    m_ip = _RE_SRC_IP.search(blob)
    m_ua = _RE_UA.search(blob)
    m_t = _RE_TYPE.search(blob)
    m_url = _RE_URL.search(blob)
    locs = [m.group(2).strip() for m in _RE_LOC.finditer(blob)][:4]
    memo = ""
    mm = re.search(r"(?:memo|token note|reminder)\s*[:=]\s*([^\n\r]{3,120})",
                   blob, re.I)
    if mm:
        memo = mm.group(1).strip()
    return {
        "container": "eml",
        "subject": subject[:160],
        "token_type": (m_t.group(1) or m_t.group(2)).strip()
                      if m_t else "",
        "src_ip": m_ip.group(1) if m_ip else "",
        "user_agent": m_ua.group(1).strip()[:120] if m_ua else "",
        "memo": memo,
        "locations": locs,
        "alert_url": m_url.group(0) if m_url else "",
    }


def _parse_json_webhook(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    keys = {k.lower() for k in data}
    if not keys & {"token_type", "canarytoken", "memo", "src_ip", "token"}:
        return None
    return {
        "container": "json",
        "subject": (data.get("subject") or "")[:160],
        "token_type": str(data.get("token_type") or data.get("canarytoken")
                          or "")[:40],
        "src_ip": str(data.get("src_ip") or data.get("source_ip") or ""),
        "user_agent": str(data.get("user_agent") or "")[:120],
        "memo": str(data.get("memo") or "")[:120],
        "locations": [str(x)[:60] for x in
                      (data.get("locations") or data.get("geo") or [])][:4],
        "alert_url": str(data.get("url") or data.get("alert_url") or ""),
    }


def analyze(alerts: list[dict], unparseable: list[str]) -> list[dict]:
    findings: list[dict] = []
    for a in alerts:
        sev = "high"
        ctx = a.get("memo") or a.get("token_type") or "canarytoken"
        findings.append({
            "type": "canary-triggered", "severity": sev,
            "detail": (f"canary umpan tersentuh ({ctx[:60]}) via "
                       f"{a['container']} — sumber: "
                       f"{a.get('src_ip') or '(tidak terekstrak)'}"),
            "evidence": {
                "token_type": a.get("token_type"),
                "memo": a.get("memo"),
                "src_ip": a.get("src_ip"),
                "user_agent": a.get("user_agent"),
                "locations": a.get("locations"),
                "alert_url": a.get("alert_url"),
                "subject": a.get("subject"),
            },
        })
        if a.get("src_ip"):
            findings.append({
                "type": "source-info", "severity": "info",
                "detail": (f"sumber trigger: {a['src_ip']}"
                           + (f" UA: {a['user_agent'][:60]}"
                              if a.get("user_agent") else "")),
                "evidence": {"src_ip": a["src_ip"],
                             "user_agent": a.get("user_agent", ""),
                             "locations": a.get("locations")},
            })
    if unparseable:
        findings.append({
            "type": "unparseable", "severity": "info",
            "detail": f"{len(unparseable)} file tidak terkenali sebagai "
                      f"alert canarytoken (dilampirkan utk audit)",
            "evidence": {"files": unparseable[:10]},
        })
    return findings


def triage_files(paths: list[Path]) -> dict:
    alerts: list[dict] = []
    unparseable: list[str] = []
    for p in paths:
        if not p.is_file():
            raise ValueError(f"file tidak ada: {p}")
        a = None
        if p.suffix.lower() == ".json" or p.read_bytes()[:1] in (b"{", b"["):
            a = _parse_json_webhook(p)
        if a is None:
            a = _parse_eml(p)
        if a is None:
            unparseable.append(str(p))
        else:
            a["file"] = str(p)
            alerts.append(a)
    if not alerts:
        raise ValueError("tidak ada alert canarytoken valid ditemukan")
    findings = analyze(alerts, unparseable)
    return {
        "schema": SCHEMA,
        "files": [str(p) for p in paths],
        "alerts": len(alerts),
        "unparseable_files": unparseable[:_UNP_MAX],
        "finding_count": len(findings),
        "findings": findings,
        "note": "canary adalah umpan — setiap trigger diperlakukan sinyal "
                "investigasi prioritas, bukan keputusan otomatis",
        "read_only": True,
    }


_UNP_MAX = 10


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase alert canarytoken (.eml/JSON) "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--alert", action="append", required=True,
                    help="file alert .eml atau JSON (diulang)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    try:
        result = triage_files([Path(p) for p in args.alert])
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    line = json.dumps(result, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(line, encoding="utf-8")
    else:
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

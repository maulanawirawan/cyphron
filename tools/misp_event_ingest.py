"""[SAFETY: read-only] misp_event_ingest — ingest OFFLINE event JSON MISP
(menuju triase IOC) lalu cocokkan ke file scope milik sendiri.

Konsep setara entri "MISP" di A-poc/BlueTeam-Tools (katalog referensi
blue team; platform sharing threat intel) — versi ingest lokal: kode ini
ditulis from scratch, stdlib-only, NOL jaringan: input = file event JSON
MISP hasil export milik sendiri/berizin, TIDAK menghubungi instance MISP.

Format input yang dikenali:
  - JSON Event MISP export ({"Event": {..., "Attribute": [...]}}) atau
    object event langsung; .json / .json.gz diterima.
  - scope (opsional): file JSON {"ips": [], "domains": [], "emails": []}
    — IOC yang cocok dengan scope dinaikkan severity-nya.

Mekanisme (semua lead berbasis bukti):
  - ioc-in-scope  : atribut (ip-dst/ip-src/domain/hostname/url/email)
                    yang cocok dengan scope -> high
  - ioc-notable   : atribut bertag malware-family/mitre/priority:high
                    -> medium
  - ioc-catalog   : IOC lain dikatalogkan (info, low) utk korelasi
  - event-summary : atribut tak ter-parse dilaporkan (jenis tak dikenal)

Fail-closed: file kosong/tidak ada atribut valid -> exit 2. Temuan = LEAD
intel, bukan klaim kompromi.

Pemakaian:
  python tools/misp_event_ingest.py --event event.json --out ioc.json
  python tools/misp_event_ingest.py --event ev.json.gz --scope scope.json
Exit: 0 sukses; 2 input error.
"""
from __future__ import annotations

import argparse
import gzip
import ipaddress
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.misp-event-ingest/1"

_IP_TYPES = {"ip-dst", "ip-src", "ip-dst|port", "ip-src|port"}
_DOMAIN_TYPES = {"domain", "hostname", "domain|ip", "hostname|port"}
_EMAIL_TYPES = {"email-src", "email-dst", "email"}
_URL_TYPES = {"url", "link", "uri"}
_NOTABLE_TAG = re.compile(r"(malware|microsoft:customer|mitre|apt|"
                          r"priority:high|ioc)", re.I)
_MAX_BYTES = 20 * 1024 * 1024


def load_event(path: Path) -> dict:
    raw = path.read_bytes()
    if raw[:2] == b"\x1f\x8b" or path.suffix.lower() == ".gz":
        raw = gzip.decompress(raw)
    if len(raw) > _MAX_BYTES:
        raise ValueError(f"file terlalu besar: {path}")
    data = json.loads(raw.decode("utf-8", errors="replace"))
    if isinstance(data, dict) and isinstance(data.get("Event"), dict):
        return data["Event"]
    if isinstance(data, dict) and "Attribute" in data:
        return data
    raise ValueError("bukan JSON Event MISP (kunci Event/Attribute tidak ada)")


def _split_val(t: str, v: str) -> tuple[str, str]:
    if "|" in t and "|" in v:
        a, b = v.split("|", 1)
        return a.strip(), b.strip()
    return v.strip(), ""


def _norm_ip(v: str) -> str | None:
    try:
        return str(ipaddress.ip_address(v))
    except ValueError:
        return None


def analyze(event: dict, scope: dict | None) -> list[dict]:
    findings: list[dict] = []
    attrs = event.get("Attribute") or []
    scope_ips = {i for i in (scope or {}).get("ips", [])}
    scope_domains = {d.lower() for d in (scope or {}).get("domains", [])}
    scope_emails = {e.lower() for e in (scope or {}).get("emails", [])}

    in_scope = 0
    notable = 0
    catalog: list[dict] = []
    unknown_types: dict[str, int] = {}
    event_info = (event.get("EventInfo") or event.get("info") or "")[:160]
    event_id = str(event.get("EventId") or event.get("id") or "?")

    for a in attrs:
        t = (a.get("type") or "").lower()
        v = (a.get("value") or "").strip()
        if not v:
            continue
        tags = " ".join(t_.get("name", "") for t_ in (a.get("Tag") or []))
        cats = ",".join(sorted({c for c in (a.get("category") or "").split()
                                if c}))
        sev = None
        val = v
        if t in _IP_TYPES:
            main, extra = _split_val(t, v)
            ip = _norm_ip(main)
            val = f"{main}:{extra}" if extra else main
            if ip and ip in scope_ips:
                sev = "high"
        elif t in _DOMAIN_TYPES:
            main, extra = _split_val(t, v)
            val = f"{main}:{extra}" if extra else main
            if main.lower() in scope_domains:
                sev = "high"
        elif t in _EMAIL_TYPES:
            if v.lower() in scope_emails:
                sev = "high"
        elif t in _URL_TYPES:
            host = re.search(r"://([^/:]+)", v)
            if host and host.group(1).lower() in scope_domains:
                sev = "high"
        else:
            unknown_types[t or "(none)"] = unknown_types.get(t or "(none)",
                                                             0) + 1
        if sev is None and _NOTABLE_TAG.search(tags):
            sev = "medium"
        if sev == "high":
            in_scope += 1
            findings.append({
                "type": "ioc-in-scope", "severity": "high",
                "detail": f"[{t}] {val} cocok dengan scope",
                "evidence": {"misp_event": event_id, "attr_type": t,
                             "value": val[:160], "tags": tags[:160],
                             "category": a.get("category", "")},
            })
        elif sev == "medium":
            notable += 1
            findings.append({
                "type": "ioc-notable", "severity": "medium",
                "detail": f"[{t}] {val} bertag penting ({tags[:80]})",
                "evidence": {"misp_event": event_id, "attr_type": t,
                             "value": val[:160], "tags": tags[:160]},
            })
        else:
            catalog.append({"type": t, "value": val[:160],
                            "category": a.get("category", ""),
                            "tags": tags[:120]})

    if catalog:
        findings.append({
            "type": "ioc-catalog", "severity": "info",
            "detail": (f"{len(catalog)} IOC dikatalogkan dari event "
                       f"#{event_id} ({event_info})"),
            "evidence": {"iocs": catalog[:50], "count": len(catalog)},
        })
    if unknown_types:
        findings.append({
            "type": "event-summary", "severity": "info",
            "detail": (f"jenis atribut tak terkatalog: "
                       f"{sorted(unknown_types.items(), key=lambda kv: -kv[1])[:6]}"),
            "evidence": {"unknown_types": unknown_types},
        })
    return findings


def triage(path: Path, scope_path: Path | None) -> dict:
    event = load_event(path)
    scope = None
    if scope_path:
        scope = json.loads(scope_path.read_text(encoding="utf-8"))
    findings = analyze(event, scope)
    attrs = event.get("Attribute") or []
    return {
        "schema": SCHEMA,
        "event": str(path),
        "event_id": str(event.get("EventId") or event.get("id") or "?"),
        "event_info": (event.get("EventInfo") or event.get("info") or "")[:200],
        "attributes_total": len(attrs),
        "finding_count": len(findings),
        "findings": findings,
        "scope_used": bool(scope_path),
        "note": "ingest intel pasif — temuan = LEAD, bukan klaim kompromi",
        "read_only": True,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Ingest event JSON MISP + cocokkan scope "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--event", required=True,
                    help="file event JSON MISP (.json/.json.gz)")
    ap.add_argument("--scope", help="JSON scope {'ips':[], 'domains':[], "
                                    "'emails':[]}")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    path = Path(args.event)
    if not path.is_file():
        print(f"ERROR: file tidak ada: {path}", file=sys.stderr)
        return 2
    try:
        result = triage(path, Path(args.scope) if args.scope else None)
    except (ValueError, json.JSONDecodeError, OSError) as exc:
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

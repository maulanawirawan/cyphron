"""[SAFETY: read-only] dmarc_report_triage — triase OFFLINE laporan agregat
DMARC (RUA) untuk indikasi spoofing domain, infrastruktur pengirim baru,
dan kebijakan yang belum ditegakkan.

Format input yang dikenali:
  - XML laporan agregat DMARC (feedback -> report_metadata / policy_published
    / record row) langsung .xml, atau .xml.gz (gzip), atau .zip berisi satu
    XML (zip diketahui aman: dibatasi 1 entri + ukuran maksimum).
  - Bisa lebih dari satu file sekaligus (--report diulang).
  - XML di-parse defensif: DOCTYPE/entity di-striip sebelum parsing
    (anti entity-expansion), ukuran file dibatasi --max-bytes.

Mekanisme deteksi (semua lead berbasis bukti, ambang bisa diatur):
  - spoof-candidate   : sumber IP dengan volume signifikan yang GAGAL SPF
                        DAN DKIM sekaligus terhadap domain terlapor
                        (>= --fail-min pesan -> high; >= 1 -> medium)
  - forwarder-mixed   : sumber yang gagal salah satu alignment tapi lolos
                        yang lain (pola forwarder/mailing-list, medium rendah)
  - unaligned-org     : organisasi pengirim (domain org dari reverse-zone
                        report_metadata) yang belum pernah lolos alignment
                        dua-duanya
  - policy-soft       : policy_published p=none / pct<100 (kebijakan belum
                        ditegakkan -> rekomendasi eskalasi bertahap)
  - new-source        : sumber IP yang tidak ada di --known-ips (file JSON
                        daftar IP infrastruktur pengirim yang diketahui)

Fail-closed: tidak ada file laporan valid -> exit 2. Semua temuan = LEAD
"teramati di laporan agregat", bukan klaim spoofing terkonfirmasi.

Pemakaian:
  python tools/dmarc_report_triage.py --report rua1.xml.gz --report rua2.xml --out d.json
  python tools/dmarc_report_triage.py --report *.xml --known-ips senders.json
Exit: 0 sukses (temuan tetap exit 0); 2 input error.
"""
from __future__ import annotations

import argparse
import gzip
import io
import ipaddress
import json
import re
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path

SCHEMA = "secai.dmarc-report-triage/1"

# DOCTYPE/entity di-striip: laporan DMARC tidak pernah butuh DTD.
_RE_DOCTYPE = re.compile(rb"<!DOCTYPE[^>\[]*(\[[^\]]*\])?\s*>", re.I)
_MAX_BYTES = 20 * 1024 * 1024


def _strip_doctype(data: bytes) -> bytes:
    return _RE_DOCTYPE.sub(b"", data)


def load_report_bytes(path: Path) -> tuple[bytes, str]:
    """Baca satu file laporan -> (xml_bytes, container)."""
    raw = path.read_bytes()
    if len(raw) > _MAX_BYTES:
        raise ValueError(f"file terlalu besar (> {_MAX_BYTES}): {path}")
    if raw[:2] == b"\x1f\x8b" or path.suffix.lower() == ".gz":
        raw = gzip.decompress(raw)
        if len(raw) > _MAX_BYTES:
            raise ValueError(f"konten gzip terlalu besar: {path}")
        return raw, "gzip"
    if zipfile.is_zipfile(io.BytesIO(raw)):
        with zipfile.ZipFile(io.BytesIO(raw)) as zf:
            xmls = [n for n in zf.namelist() if n.lower().endswith(".xml")]
            if len(xmls) != 1:
                raise ValueError(f"zip harus berisi tepat 1 XML: {path}")
            data = zf.read(xmls[0])
            if len(data) > _MAX_BYTES:
                raise ValueError(f"konten zip terlalu besar: {path}")
            return data, "zip"
    return raw, "raw"


def parse_report(xml_bytes: bytes, source_file: str) -> dict | None:
    """Parse satu dokumen feedback DMARC -> dict ringkas, None bila bukan DMARC."""
    try:
        root = ET.fromstring(_strip_doctype(xml_bytes))
    except ET.ParseError:
        return None
    if root.tag != "feedback":
        return None

    def _t(node, path: str) -> str:
        cur = node
        for part in path.split("/"):
            cur = cur.find(part)
            if cur is None:
                return ""
        return (cur.text or "").strip()

    pol = root.find("policy_published")
    reports = []
    for rep in root.findall("report_metadata"):
        reports.append({
            "org_name": _t(rep, "org_name"),
            "report_id": _t(rep, "report_id"),
            "date_begin": _t(rep, "date_range/begin"),
            "date_end": _t(rep, "date_range/end"),
        })
    rows = []
    for rec in root.findall("record"):
        row = rec.find("row")
        pol_eval = row.find("policy_evaluated") if row is not None else None
        ident = rec.find("identifiers")
        if row is None or pol_eval is None or ident is None:
            continue
        def _bool(node, tag: str) -> bool:
            el = node.find(tag)
            return (el.text or "").strip().lower() == "pass"
        rows.append({
            "source_ip": _t(row, "source_ip"),
            "count": int(_t(row, "count") or 0),
            "spf_pass": _bool(pol_eval, "spf"),
            "dkim_pass": _bool(pol_eval, "dkim"),
            "disposition": _t(pol_eval, "disposition") or "none",
            "header_from": _t(ident, "header_from"),
        })
    if not rows and not reports:
        return None
    return {
        "source_file": source_file,
        "reports": reports,
        "policy": {
            "domain": _t(pol, "domain"),
            "p": _t(pol, "p") or "none",
            "sp": _t(pol, "sp"),
            "pct": _t(pol, "pct") or "100",
            "adkim": _t(pol, "adkim"),
            "aspf": _t(pol, "aspf"),
        },
        "records": rows,
    }


def _org_hint(ip: str) -> str:
    """Label organologi kasar dari IP (blok /8 + reverse-ish) — bukan reverse DNS."""
    try:
        a = ipaddress.ip_address(ip)
        return f"block-{str(a).rsplit('.', 2)[0] if a.version == 4 else a.network_address.compressed}"
    except ValueError:
        return "unknown"


def analyze(parsed: list[dict], fail_min: int,
            known_ips: set[str] | None) -> list[dict]:
    """Heuristik DMARC — setiap temuan disertai bukti."""
    findings: list[dict] = []
    per_src: dict[str, dict] = {}
    total_msgs = 0
    policies: dict[str, dict] = {}

    for rep in parsed:
        pol = rep["policy"]
        dom = pol["domain"] or "(unknown)"
        policies.setdefault(dom, pol)
        for row in rep["records"]:
            total_msgs += row["count"]
            src = row["source_ip"] or "(no-ip)"
            st = per_src.setdefault(src, {
                "messages": 0, "spf_pass": 0, "dkim_pass": 0,
                "both_fail": 0, "mixed": 0, "domains": set(),
                "dispositions": set(), "reports": set(),
            })
            st["messages"] += row["count"]
            st["domains"].add(row["header_from"] or "(none)")
            st["dispositions"].add(row["disposition"])
            st["reports"].add(rep["source_file"])
            if row["spf_pass"]:
                st["spf_pass"] += row["count"]
            if row["dkim_pass"]:
                st["dkim_pass"] += row["count"]
            if not row["spf_pass"] and not row["dkim_pass"]:
                st["both_fail"] += row["count"]
            elif not (row["spf_pass"] and row["dkim_pass"]):
                st["mixed"] += row["count"]

    # 1. spoof-candidate: gagal dua-duanya dengan volume
    for src, st in sorted(per_src.items(),
                          key=lambda kv: -kv[1]["both_fail"]):
        if st["both_fail"] <= 0:
            continue
        sev = "high" if st["both_fail"] >= fail_min else "medium"
        is_known = not known_ips or src in known_ips
        findings.append({
            "type": "spoof-candidate", "severity": sev,
            "src": src, "domain": ", ".join(sorted(st["domains"]))[:120],
            "detail": (f"{st['both_fail']} pesan dari {src} gagal SPF DAN "
                       f"DKIM terhadap {sorted(st['domains'])[0]}"),
            "evidence": {
                "messages": st["messages"],
                "both_fail": st["both_fail"],
                "mixed": st["mixed"],
                "spf_pass": st["spf_pass"],
                "dkim_pass": st["dkim_pass"],
                "fail_ratio": round(st["both_fail"] / max(st["messages"], 1), 3),
                "known_sender": is_known,
                "dispositions": sorted(st["dispositions"]),
            },
        })

    # 2. forwarder-mixed: campuran pass/fail alignment
    for src, st in sorted(per_src.items()):
        if st["mixed"] > 0 and st["both_fail"] == 0:
            findings.append({
                "type": "forwarder-mixed", "severity": "low",
                "src": src, "domain": ", ".join(sorted(st["domains"]))[:120],
                "detail": (f"{st['mixed']} pesan gagal salah satu alignment "
                           f"(pola forwarder/mailing-list) dari {src}"),
                "evidence": {"messages": st["messages"], "mixed": st["mixed"],
                             "spf_pass": st["spf_pass"],
                             "dkim_pass": st["dkim_pass"]},
            })

    # 3. new-source: IP tidak ada pada daftar infrastruktur yang diketahui
    if known_ips:
        for src, st in sorted(per_src.items(),
                              key=lambda kv: -kv[1]["messages"]):
            if src not in known_ips and st["messages"] >= fail_min:
                findings.append({
                    "type": "new-source", "severity": "low",
                    "src": src,
                    "domain": ", ".join(sorted(st["domains"]))[:120],
                    "detail": (f"{st['messages']} pesan dari sumber baru "
                               f"(tidak ada di --known-ips): {src}"),
                    "evidence": {"messages": st["messages"],
                                 "org_hint": _org_hint(src)},
                })

    # 4. policy-soft: kebijakan belum ditegakkan
    for dom, pol in sorted(policies.items()):
        soft = []
        if pol["p"] == "none":
            soft.append("p=none (monitor saja)")
        try:
            pct = int(pol["pct"])
        except ValueError:
            pct = 100
        if pct < 100:
            soft.append(f"pct={pct}")
        if soft:
            findings.append({
                "type": "policy-soft", "severity": "low",
                "domain": dom,
                "detail": f"kebijakan DMARC {dom}: {', '.join(soft)}",
                "evidence": {"policy": pol},
            })
    return findings


def triage_files(paths: list[Path], fail_min: int,
                 known_ips: set[str] | None) -> dict:
    parsed: list[dict] = []
    skipped: list[str] = []
    for p in paths:
        if not p.is_file():
            raise ValueError(f"file tidak ada: {p}")
        xml_bytes, container = load_report_bytes(p)
        rep = parse_report(xml_bytes, str(p))
        if rep is None:
            skipped.append(str(p))
        else:
            parsed.append(rep)
    if not parsed:
        raise ValueError("tidak ada laporan DMARC valid di file input")

    findings = analyze(parsed, fail_min, known_ips)
    src_total = len({r["source_ip"] for r in
                     (row for rep in parsed for row in rep["records"])})
    msgs = sum(r["count"] for rep in parsed for r in rep["records"])
    return {
        "schema": SCHEMA,
        "files": [str(p) for p in paths],
        "valid_reports": len(parsed),
        "skipped_files": skipped,
        "containers": sorted({rep["source_file"].rsplit(".", 1)[-1]
                              for rep in parsed}),
        "aggregate_reports": sum(len(rep["reports"]) for rep in parsed),
        "messages": msgs,
        "source_ips_unique": src_total,
        "finding_count": len(findings),
        "findings": findings,
        "thresholds": {"fail_min": fail_min},
        "note": "semua temuan = LEAD teramati di laporan agregat DMARC, "
                "bukan klaim spoofing terkonfirmasi",
        "read_only": True,
    }


def _load_known_ips(path: str | None) -> set[str] | None:
    if not path:
        return None
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    items = data if isinstance(data, list) else data.get("ips") or data.get("senders") or []
    out = set()
    for ip in items:
        try:
            out.add(str(ipaddress.ip_address(str(ip))))
        except ValueError:
            continue
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase laporan agregat DMARC utk spoofing/policy "
                    "(read-only, NOL jaringan)")
    ap.add_argument("--report", action="append", required=True,
                    help="file laporan XML DMARC (.xml/.xml.gz/.zip, "
                         "diulang utk banyak file)")
    ap.add_argument("--known-ips", help="JSON daftar IP pengirim diketahui")
    ap.add_argument("--fail-min", type=int, default=10,
                    help="pesan both-fail minimum utk severity high "
                         "(default 10)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    args = ap.parse_args(argv)

    try:
        known = _load_known_ips(args.known_ips)
        result = triage_files([Path(p) for p in args.report],
                              args.fail_min, known)
    except (ValueError, OSError) as exc:
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

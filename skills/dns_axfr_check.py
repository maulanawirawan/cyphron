"""[SAFETY: bounded-requests] dns-axfr-check — zone transfer (AXFR,
RFC 5936) terbuka pada nameserver domain (CWE-200): seluruh isi zona
DNS bisa terbaca siapa pun. Bounded ketat:
  - 1 query NS ke resolver publik;
  - maks 2 NS; per NS 1 query A + 1 koneksi TCP/53 untuk AXFR;
  - NOL percobaan ke host selain NS milik domain itu; NOL rekursi.
Transfer valid (jawaban diapit SOA..SOA, RCODE 0) = L2 LEAD — WAJIB
verifikasi manual (isi zona bisa memuat host internal). Ditolak/
refused/timeout = AMAN atau unconfirmed (tanpa klaim).
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402  (konsistensi UA guard lintas skill)
import dns_light  # noqa: E402

MAX_NS = 2


def probe(domain: str, resolver: str = dns_light.DEFAULT_RESOLVER,
          timeout: float = 5.0) -> dict:
    out: dict = {"ns": None, "ns_error": None, "axfr": {}, "a_error": {}}
    ns = dns_light.ns_lookup(resolver, domain, timeout)
    if ns is None:
        out["ns_error"] = "query-NS-gagal"
        return out
    out["ns"] = ns
    for host in ns[:MAX_NS]:
        ips = dns_light.a_lookup(resolver, host, timeout)
        if not ips:
            out["a_error"][host] = "resolusi-NS-gagal"
            continue
        res = dns_light.axfr(ips[0], domain, timeout)
        out["axfr"][host] = ({"rcode": res["rcode"],
                              "answers": res["answers"]} if res else None)
    return out


def _zone_valid(answers: list[dict]) -> bool:
    return (len(answers) >= 2
            and answers[0]["type"] == dns_light.QTYPE_SOA
            and answers[-1]["type"] == dns_light.QTYPE_SOA)


def audit(domain: str, result: dict) -> tuple[list[dict], dict]:
    rows: list[dict] = []
    leaked: list[str] = []

    if result.get("ns_error"):
        rows.append(make_finding(
            tool="dns-axfr-check",
            title=f"AXFR check on {domain} — tidak dapat dinilai",
            severity="info",
            description=f"Query NS gagal ({result['ns_error']}) — AXFR "
                        "tidak dicoba (tanpa klaim, fail-closed).",
            target_url=f"dns:{domain}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests",
                   "error": result["ns_error"]}))
        return rows, {"domain": domain, "error": True, "leaked": [],
                      "ns_checked": 0}

    for host, res in (result.get("axfr") or {}).items():
        answers = (res or {}).get("answers") or []
        if res is not None and _zone_valid(answers):
            leaked.append(host)
            summary = ", ".join(
                f"{a['name']}({'SOA' if a['type'] == dns_light.QTYPE_SOA else a['type']})"
                for a in answers[:12])
            rows.append(make_finding(
                tool="dns-axfr-check",
                title=f"DNS zone transfer open on {host} ({domain})",
                severity="high",
                description=f"Nameserver '{host}' melayani AXFR untuk "
                            f"zona '{domain}' tanpa pembatasan — seluruh "
                            f"record zona ({len(answers)} record) terbaca: "
                            f"{summary}. Peta host internal bisa jadi "
                            "peta awal serangan. LEAD — wajib verifikasi "
                            "manual isi zona sebelum dilaporkan.",
                recommendation="Batasi AXFR ke transferee eksplisit "
                               "(allowlist IP secondary), tolak sisanya.",
                cwe="CWE-200",
                target_url=f"dns:{domain} @ {host}",
                response=summary[:300],
                evidence_kind="request-response",
                finding_class="weakness",
                confidence=1.0, status="confirmed", verdict=2,
                extra={"category": "DNS", "safety_class": "bounded-requests",
                       "ns": host, "records": len(answers)}))
        elif res is None:
            rows.append(make_finding(
                tool="dns-axfr-check",
                title=f"AXFR on {host} — koneksi/parse gagal",
                severity="info",
                description="Koneksi TCP/53 atau parse respons gagal — "
                            "status transfer tidak dinilai (tanpa klaim).",
                target_url=f"dns:{host}",
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="unconfirmed", verdict=1,
                extra={"category": "MISC",
                       "safety_class": "bounded-requests"}))
        else:
            rows.append(make_finding(
                tool="dns-axfr-check",
                title=f"AXFR refused on {host} ({domain})",
                severity="info",
                description="Nameserver menolak/mengosongkan transfer "
                            "(RCODE bukan 0 atau jawaban tidak diapit "
                            "SOA..SOA) — AXFR ditegakkan (AMAN).",
                target_url=f"dns:{domain} @ {host}",
                response=f"rcode={(res or {}).get('rcode')} "
                         f"records={len(answers)}",
                evidence_kind="request-response", finding_class="posture",
                confidence=1.0, status="confirmed", verdict=0,
                extra={"category": "AMAN",
                       "safety_class": "bounded-requests"}))
    for host, err in (result.get("a_error") or {}).items():
        rows.append(make_finding(
            tool="dns-axfr-check",
            title=f"AXFR on {host} — resolusi NS gagal",
            severity="info",
            description=f"Alamat NS '{host}' tidak bisa diresolusi — "
                        "AXFR tidak dicoba (tanpa klaim).",
            target_url=f"dns:{host}",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests",
                   "error": err}))
    return rows, {"domain": domain, "leaked": leaked,
                  "ns_checked": len(result.get("axfr") or {})}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--domain", required=True)
    ap.add_argument("--out", default="axfr_findings.json")
    ap.add_argument("--resolver", default=dns_light.DEFAULT_RESOLVER)
    ap.add_argument("--timeout", type=float, default=5.0)
    args = ap.parse_args()
    _ = user_agent()  # UA guard: skill tetap lewat modul ua meski query DNS
    result = probe(args.domain, args.resolver, args.timeout)
    rows, meta = audit(args.domain, result)
    write_findings(args.out, rows,
                   {**meta, "safety_class": "bounded-requests"})
    print(f"dns-axfr-check: {len(rows)} baris "
          f"({len(meta.get('leaked', []))} transfer terbuka) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

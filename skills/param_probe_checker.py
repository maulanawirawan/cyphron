"""[SAFETY: bounded-requests] param-probe-checker — penemuan parameter
tersembunyi (CWE-471/200), konsep publik ala Arjun versi bounded.

Metode (zero-FP dengan kontrol ganda):
  1. GET baseline  (tanpa param tambahan)
  2. GET kontrol   (?randomcanary-<hex>=<hex> — menangkap wildcard/404
     generik yang merespons sama untuk nama apa pun)
  3. SATU GET per kandidat nama-param dari wordlist internal (maks
     MAX_PARAMS) dengan nilai marker unik.

Klasifikasi per kandidat (HARUS beda dari baseline DAN kontrol):
  - marker MUNCUL di respons -> L2 lead "param diterima + direfleksikan"
  - status/panjang respons berubah signifikan -> L1 lead
    "param mempengaruhi perilaku"
Refleksi tidak di-claim XSS (konteks belum diverifikasi — jalur
xss-reflect-check). Fail-closed: endpoint error di baseline = stop.

Pemakaian:
  python skills/param_probe_checker.py --url https://host/api/profile \
      --out f.json
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402
from ua import user_agent  # noqa: E402

UA = user_agent()
MAX_PARAMS = 12  # total request = 2 + MAX_PARAMS (dokumentasikan di desc)

# wordlist internal pendek — nama param high-signal ala Arjun (subset)
WORDLIST = [
    "debug", "test", "admin", "api_key", "apikey", "callback", "redirect",
    "next", "url", "return", "returnTo", "file", "path", "template",
    "preview", "page_id", "user_id", "role", "debug_mode", "internal",
    "profile", "include",
]


def _get(url: str, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(64_000).decode("utf-8", "replace")
            return {"status": r.status, "len": len(body), "body": body}
    except urllib.error.HTTPError as e:
        try:
            body = (e.read(16_000) or b"").decode("utf-8", "replace")
        except Exception:
            body = ""  # body 4xx bisa hang/terputus — status tetap dicatat
        return {"status": e.code, "len": len(body), "body": body,
                "body_error": body == ""}
    except Exception as exc:
        return {"status": None, "len": 0, "error": str(exc)[:120],
                "body": ""}


def probe(url: str, params: list[str], marker: str, nonce: str,
          timeout: float = 15.0) -> dict:
    """Baseline + kontrol random + 1 GET per kandidat (bounded)."""
    sep = "&" if "?" in url else "?"
    out = {"baseline": _get(url, timeout)}
    out["control"] = _get(f"{url}{sep}rc{nonce[:8]}={nonce[:12]}", timeout)
    for p in params[:MAX_PARAMS]:
        out[p] = _get(f"{url}{sep}{urllib.parse.quote(p, safe='')}="
                      f"{urllib.parse.quote(marker, safe='')}", timeout)
    return out


def audit(url: str, results: dict, marker: str) \
        -> tuple[list[dict], dict]:
    rows: list[dict] = []
    base, ctrl = results.get("baseline", {}), results.get("control", {})
    if base.get("status") is None:
        rows.append(make_finding(
            tool="param-probe-checker", title=f"Fetch failed on {url}",
            severity="info", description=str(base.get("error"))[:300],
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests"}))
        return rows, {"url": url, "error": True}
    if ctrl.get("status") is None:
        rows.append(make_finding(
            tool="param-probe-checker", title=f"Control failed on {url}",
            severity="info",
            description="kontrol random-param gagal — hasil tidak bisa "
                        "dipercaya (fail-closed, tidak ada klaim)",
            target_url=url, evidence_kind="request-response",
            finding_class="posture", status="unconfirmed", verdict=1,
            extra={"category": "MISC", "safety_class": "bounded-requests"}))
        return rows, {"url": url, "error": True}

    base_key = (base["status"], base["len"])
    ctrl_key = (ctrl["status"], ctrl["len"])
    # FP-guard wildcard: kalau kontrol random-param JUGA merefleksikan
    # markernya, halaman menggemakan query apa pun — klaim per-param
    # tidak valid (satu observasi wildcard, bukan N hidden param)
    wildcard = marker in ctrl.get("body", "")
    accepted: list[dict] = []
    for name, res in results.items():
        if name in ("baseline", "control") or res.get("status") is None:
            continue
        if (res["status"], res["len"]) == base_key \
                or (res["status"], res["len"]) == ctrl_key:
            continue  # identik baseline/kontrol = tidak menarik (zero-FP)
        if marker in res.get("body", ""):
            accepted.append({"param": name, "kind": "reflected"})
        else:
            accepted.append({"param": name, "kind": "behavior"})
    detected, accepted = accepted, ([] if wildcard else accepted)
    for a in accepted:
        if a["kind"] == "reflected":
            rows.append(make_finding(
                tool="param-probe-checker",
                title=f"Hidden param accepted+reflected on {url}: "
                      f"{a['param']}",
                severity="medium",
                description=f"Parameter '{a['param']}' (tidak ada di "
                            "halaman/JS publik) mengubah respons DAN "
                            "merefleksikan nilai — kandidat kuat untuk "
                            "uji manual (injection/reflection) dalam "
                            "scope. L2 lead, bukan klaim kerentanan.",
                recommendation="Verifikasi konteks refleksi manual; uji "
                               "injection hanya dalam scope program.",
                cwe="CWE-471",
                target_url=url, response=f"param={a['param']} kind="
                                         f"{a['kind']}",
                evidence_kind="request-response",
                finding_class="weakness", confidence=1.0,
                status="confirmed", verdict=2,
                extra={"category": "SURFACE",
                       "safety_class": "bounded-requests",
                       "param": a["param"], "kind": a["kind"]}))
        else:
            rows.append(make_finding(
                tool="param-probe-checker",
                title=f"Hidden param changes behavior on {url}: "
                      f"{a['param']}",
                severity="low",
                description=f"Parameter '{a['param']}' mengubah "
                            "status/panjang respons (beda dari baseline "
                            "DAN kontrol random) — param diterima server; "
                            "makanya perlu verifikasi manual (L1 lead).",
                recommendation="Petakan efek param secara manual dalam "
                               "scope; cek mass-assignment/debug.",
                cwe="CWE-471",
                target_url=url, response=f"param={a['param']} kind="
                                         f"{a['kind']}",
                evidence_kind="request-response",
                finding_class="posture", confidence=1.0,
                status="confirmed", verdict=1,
                extra={"category": "SURFACE",
                       "safety_class": "bounded-requests",
                       "param": a["param"], "kind": a["kind"]}))
    if wildcard:
        rows.append(make_finding(
            tool="param-probe-checker",
            title=f"Wildcard query reflection on {url} (bukan per-param)",
            severity="low",
            description="Kontrol random-param (nama tak ada di wordlist) "
                        "JUGA direfleksikan — halaman menggemakan query "
                        "apa pun; klaim hidden-param individual "
                        "dibatalkan (satu perilaku refleksi, bukan N "
                        "parameter). Verifikasi konteks refleksi manual "
                        "sebelum klaim apa pun.",
            recommendation="Cek di mana query digemakan (JS location."
                           "search / canonical / header) lalu tangani "
                           "satu titik refleksi itu.",
            cwe="CWE-200",
            target_url=url,
            response=f"kontrol direfleksikan; {len(results) - 2} "
                     "kandidat dilewati",
            evidence_kind="request-response", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "SURFACE",
                   "safety_class": "bounded-requests",
                   "wildcard": True}))
    rows.append(make_finding(
        tool="param-probe-checker",
        title=f"Param probe posture on {url}", severity="info",
        description=("wildcard reflection — klaim per-param dibatalkan"
                     if wildcard else
                     f"{len(accepted)} dari {len(results) - 2} kandidat "
                     f"berdampak: {accepted}" if accepted else
                     "Tidak ada param tersembunyi yang berdampak pada "
                     f"{len(results) - 2} kandidat (AMAN/inventaris)."),
        target_url=url, response=json.dumps(
            {"baseline": base_key, "control": ctrl_key})[:300],
        evidence_kind="request-response", finding_class="posture",
        confidence=1.0, status="confirmed", verdict=1 if accepted else 0,
        extra={"category": ("SURFACE" if (accepted or wildcard)
                            else "AMAN"),
               "safety_class": "bounded-requests",
               "accepted": accepted,
               "detected": detected,
               "wildcard": wildcard,
               "requests": len(results)}))
    return rows, {"url": url, "requests": len(results),
                  "accepted": accepted, "marker": marker}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--url", required=True)
    ap.add_argument("--param", action="append", default=None,
                    help="override wordlist (boleh diulang, maks "
                         f"{MAX_PARAMS})")
    ap.add_argument("--out", default="param_probe_findings.json")
    args = ap.parse_args()
    params = args.param or WORDLIST
    marker = f"pp-{secrets.token_hex(8)}"
    nonce = secrets.token_hex(8)
    results = probe(args.url, params, marker, nonce)
    rows, meta = audit(args.url, results, marker)
    write_findings(args.out, rows, {**meta,
                                    "safety_class": "bounded-requests"})
    # meta jalur error tidak bawa 'accepted'/'requests' — jangan crash
    print(f"param-probe-checker: {len(rows)} temuan "
          f"({len(meta.get('accepted', []))} berdampak, "
          f"{meta.get('requests', 0)} request) -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

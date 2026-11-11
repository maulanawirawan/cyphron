"""[SAFETY: read-only, NOL jaringan] smuggling_desync_analyzer — klasifikasi
desync HTTP request smuggling (CWE-444) dari BUKTI permintaan mentah. TIDAK
mengirim payload apa pun.

Konsep request smuggling (CL.TE / TE.CL / TE.TE / CL.CL) — dibangun FROM
SCRATCH, stdlib murni, offline. Hanya MENGANALISIS framing header yang
diberikan; tidak pernah membuka koneksi.

Ceruk vs modul lain (anti-duplikasi):
  - `skills/smuggling_clue_checker.py` = clue pasif dari header respons (LIVE).
    Tool ini meng-KLASIFIKASI framing dari request MENTAH dan memberi vektor
    uji jinak; divergensi front/back pada capture berpasangan dinaikkan ke L2.

"Kejar sampai verdict": CL+TE / TE obfuscated / dua CL berbeda => L1 LEAD
(CWE-444) + vektor uji jinak. Capture berpasangan dgn front_len != back_len =>
L2 REPRODUCED. Framing tunggal yang jelas (hanya CL, well-formed) => L0.

Input -> mekanisme -> output:
  - Input : --request <file berisi request HTTP mentah> ATAU --front <raw> +
            --back <raw> (dua tampilan untuk divergensi).
  - Output: JSON kontrak; --out; --fail-on. Exit 0/1/2.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.smuggling-desync-analyzer/1"
TOOL = "smuggling-desync-analyzer"
MAX_BYTES = 256 * 1024


def _parse_headers(raw: str) -> list[tuple[str, str, str]]:
    """-> [(name_lower, value, raw_name)] sampai baris kosong pertama."""
    out = []
    body_split = re.split(r"\r?\n\r?\n", raw, maxsplit=1)
    head = body_split[0]
    lines = re.split(r"\r?\n", head)
    for line in lines[1:]:                      # lewati request-line
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        out.append((name.strip().lower(), value.strip(), name))
    return out


def analyze(raw: str, front: str | None = None, back: str | None = None) -> dict:
    findings: list[dict] = []
    hdrs = _parse_headers(raw)
    cls = [v for n, v, _ in hdrs if n == "content-length"]
    tes = [(v, rn) for n, v, rn in hdrs if n == "transfer-encoding"]
    te_raw_names = [rn for n, v, rn in hdrs if n == "transfer-encoding"]

    verdicts: list[tuple[str, str, str]] = []   # (variant, detail, severity)

    if cls and tes:
        verdicts.append(("CL.TE/TE.CL",
                         "both Content-Length and Transfer-Encoding present — "
                         "front-end and back-end may disagree on message length",
                         "high"))
    if len(cls) >= 2 and len(set(cls)) >= 2:
        verdicts.append(("CL.CL",
                         "duplicate Content-Length with different values %s" % cls,
                         "high"))
    # TE.TE obfuscation: duplicate TE, non-sole 'chunked', spasi/tab di nama,
    # atau nilai ter-obfuscate
    if len(tes) >= 2:
        verdicts.append(("TE.TE", "duplicate Transfer-Encoding headers", "high"))
    for v, rn in tes:
        if rn != rn.strip() or "\t" in rn or " " in rn.strip():
            verdicts.append(("TE.TE", "obfuscated Transfer-Encoding header name %r" % rn, "medium"))
        vv = v.lower().strip()
        if vv and vv != "chunked" and "chunked" in vv:
            verdicts.append(("TE.TE", "non-sole/obfuscated TE value %r" % v, "medium"))

    # divergensi front/back (bukti kuat) -> L2
    if front is not None and back is not None:
        fl = [v for n, v, _ in _parse_headers(front) if n == "content-length"]
        bl = [v for n, v, _ in _parse_headers(back) if n == "content-length"]
        if fl and bl and fl != bl:
            findings.append(make_finding(
                tool=TOOL, title="HTTP desync reproduced: front/back length divergence",
                severity="high", cwe="CWE-444",
                description=("Front-end parsed Content-Length %s but back-end "
                             "parsed %s for the same bytes — request boundaries "
                             "diverge (desync reproduced from captures)."
                             % (fl, bl)),
                recommendation=("Normalize/enforce one framing; reject requests "
                                "with both CL and TE; use HTTP/2 end-to-end."),
                param="desync:divergence", status="confirmed", verdict=2,
                evidence_kind="differential", confidence=1.0,
                poc="front CL=%s / back CL=%s (captured)" % (fl, bl),
                extra={"kind": "smuggle", "variant": "divergence"}))

    seen = set()
    for variant, detail, sev in verdicts:
        key = (variant, detail)
        if key in seen:
            continue
        seen.add(key)
        vector = ("benign test vector (DO NOT weaponize): craft a request with "
                  "the ambiguous framing above and a benign second request "
                  "(e.g. GET /robots.txt); observe if the back-end treats the "
                  "trailing bytes as a new request. next-step is LIVE and not "
                  "performed here.")
        findings.append(make_finding(
            tool=TOOL, title="HTTP request smuggling candidate: %s" % variant,
            severity=sev, cwe="CWE-444",
            description="%s. %s" % (detail, "Framing ambiguity = smuggling lead."),
            recommendation=("Reject messages with conflicting CL/TE; pin framing "
                            "at the edge; prefer HTTP/2."),
            param="desync:%s:%s" % (variant, detail[:40]),
            status="unconfirmed", verdict=1, evidence_kind="structure",
            confidence=0.6, lab_only=True, poc=vector,
            extra={"kind": "smuggle", "variant": variant}))

    if not findings:
        findings.append(make_finding(
            tool=TOOL, title="No request-smuggling framing ambiguity found",
            severity="info",
            description="Parsed request framing; no conflicting CL/TE, no "
                        "duplicate CL, no obfuscated TE (checked, nothing found).",
            recommendation="Provide front/back captures to test for divergence.",
            param="summary", status="confirmed", verdict=0, evidence_kind="",
            confidence=0.6, extra={"kind": "summary"}))
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_order[f["severity"]], f.get("param") or ""))
    stats = {"findings": len(findings), "variants": sorted({
        f["extra_variant"] if "extra_variant" in f else f.get("variant", "")
        for f in findings if f.get("kind") == "smuggle"} - {""})}
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": [],
            "findings": findings}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Classify HTTP request-smuggling desync from raw request "
                    "evidence — offline, no payloads sent.")
    ap.add_argument("--request", help="file: raw HTTP request")
    ap.add_argument("--front", help="file: front-end raw view")
    ap.add_argument("--back", help="file: back-end raw view")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    try:
        if args.request:
            raw = Path(args.request).read_text(encoding="utf-8", errors="replace")[:MAX_BYTES]
        elif args.front and args.back:
            raw = Path(args.front).read_text(encoding="utf-8", errors="replace")[:MAX_BYTES]
        else:
            print("[smuggling-desync-analyzer] input error: --request atau "
                  "--front+--back wajib", file=sys.stderr)
            return 2
        front = Path(args.front).read_text(encoding="utf-8", errors="replace")[:MAX_BYTES] if args.front else None
        back = Path(args.back).read_text(encoding="utf-8", errors="replace")[:MAX_BYTES] if args.back else None
    except OSError as exc:
        print("[smuggling-desync-analyzer] input error: %s" % exc, file=sys.stderr)
        return 2
    result = analyze(raw, front, back)
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

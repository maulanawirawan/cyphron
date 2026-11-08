r"""[AUDIT: read-only] gcp_orgpolicy_audit — audit OFFLINE cakupan
Organization Policy GCP dari ekspor JSON gcloud: constraint keamanan
esensial yang hilang, dry-run, lemah (enforced=false / allValues=ALLOW /
restoreDefault), dan pengecualian listPolicy.

Mengisi antrean port SKILL-PORT-QUEUE #0629 (mukul975/
Anthropic-Cybersecurity-Skills 'implementing-gcp-organization-policy-
constraints'; atribusi konsep, lisensi sumber Apache-2.0). Dibangun
FROM SCRATCH: model ekspektasi constraint ditulis sendiri dari tabel
"Recommended Baseline Policies" publik di skill sumber. Tidak menyalin
kode sumber; gcloud/policy-intelligence tidak dipakai — inputnya ekspor
JSON baca-saja:
  gcloud org-policies list --organization=ORG_ID --format=json
  gcloud resource-manager org-policies list --organization=ORG_ID \
      --format=json

Ranah: org/folder/project POLICY guardrail — berbeda dari firewall
rules VPC (gcp_fw_audit, #0630) dan IAM escalation (iam_escalation_scan,
B13); tidak diduplikasi.

Input -> mekanisme -> output:
  - Input : JSON daftar policy (array). Field: constraint,
            booleanPolicy.enforced, listPolicy.allValues/
            allowedValues/deniedValues, restoreDefault, dryRunSpec
            (policy dry-run muncul sbg entry terpisah).
  - Mekanisme: peta constraint -> status (enforced-valid / dry-run /
            weak / restore-default / hilang), lalu dibandingkan dgn
            baseline ekspektasi (boolean-enforced, list-deny, present).
  - Output: JSON {schema, stats, findings, notes}; finding =
            {check, severity, constraint, message}.

Cek (zero-FP: hanya bentuk eksplisit di ekspor):
  constraint-missing        (high): constraint baseline tidak ada di
                            ekspor (pendek daftar eksplisit — belum
                            diset di scope org).
  constraint-weak           (high): booleanPolicy.enforced=false,
                            ATAU list-deny dgn allValues != DENY,
                            ATAU restoreDefault (direset ke default
                            Google).
  constraint-dry-run        (medium): hanya dryRunSpec yang ada
                            (dampak dimonitor, BELUM enforce).
  constraint-exceptions     (medium): listPolicy dgn allowedValues/
                            deniedValues eksplisit (pengecualian sah
                            seperti bastion — minta review + catat
                            owner, bukan blokir).
  entry-unparsed            (high): elemen bukan objek / tanpa spec
                            dikenal (fail-closed).

Baseline (dari tabel sumber; --skip-constraint utk anti-FP):
  compute.vmExternalIpAccess            (list-deny)
  gcp.resourceLocations                 (present)
  iam.disableServiceAccountKeyCreation  (boolean)
  iam.automaticIamGrantsForDefaultServiceAccounts (boolean)
  compute.requireOsLogin                (boolean)
  compute.disableSerialPortAccess       (boolean)
  storage.uniformBucketLevelAccess      (boolean)
  sql.restrictPublicIp                  (boolean)

Fail-closed:
  - file tidak ada / JSON tidak valid / bukan array -> exit 2.
  - daftar KOSONG -> exit 2 (bukan audit; salah scope/flag --format —
    org tanpa policy sama sekali dinyatakan via temuan
    constraint-missing dari ekspor yang benar, bukan dari ekspor
    kosong yang tidak bisa dibedakan).
  - constraint di luar baseline dihitung stats.extra_constraints
    (inventaris, bukan temuan).

Catatan: ekspor per-scope (org/folder/project) tidak menyertakan
efek pewarisan lintas-scope — bandingkan ekspor org vs folder vs
project secara manual bila hierarki dipakai (cf. METHODS).
Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/gcp_orgpolicy_audit.py --policies orgpolicy.json --out audit.json
  python tools/gcp_orgpolicy_audit.py --policies orgpolicy.json \
      --skip-constraint constraints/sql.restrictPublicIp --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "cyphron.gcp-orgpolicy-audit/1"
MAX_FILE_BYTES = 16 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

# baseline sumber: constraint -> ekspektasi
BASELINE: "dict[str, str]" = {
    "constraints/compute.vmExternalIpAccess": "list-deny",
    "constraints/gcp.resourceLocations": "present",
    "constraints/iam.disableServiceAccountKeyCreation": "boolean",
    "constraints/iam.automaticIamGrantsForDefaultServiceAccounts": "boolean",
    "constraints/compute.requireOsLogin": "boolean",
    "constraints/compute.disableSerialPortAccess": "boolean",
    "constraints/storage.uniformBucketLevelAccess": "boolean",
    "constraints/sql.restrictPublicIp": "boolean",
}


def _classify_spec(policy: dict) -> "str | None":
    """Kembalikan 'valid' / 'weak' / 'exceptions' / 'restore' / None."""
    bp = policy.get("booleanPolicy")
    if isinstance(bp, dict):
        return "valid" if bp.get("enforced") is True else "weak"
    lp = policy.get("listPolicy")
    if isinstance(lp, dict):
        all_values = str(lp.get("allValues", "")).upper()
        if all_values == "DENY":
            return "valid"
        if all_values == "ALLOW":
            return "weak"
        if isinstance(lp.get("allowedValues"), list) \
                and lp["allowedValues"]:
            return "exceptions"
        if isinstance(lp.get("deniedValues"), list) \
                and lp["deniedValues"]:
            return "exceptions"
        return "weak"  # listPolicy tanpa isi apa pun = tidak mengikat
    if "restoreDefault" in policy:
        return "restore"
    return None


def audit_policies(policies: "list[dict]") -> "tuple[list[dict], dict]":
    findings: "list[dict]" = []
    stats = {
        "entries_total": 0,
        "entries_dryrun": 0,
        "constraints_enforced": 0,
        "constraints_dryrun_only": 0,
        "extra_constraints": 0,
        "unparsed": 0,
    }

    # rank status terbaik per constraint: valid > exceptions > weak/restore
    RANK = {"valid": 3, "exceptions": 2, "weak": 1, "restore": 1}
    status_map: "dict[str, str]" = {}
    dryrun_constraints: "set[str]" = set()

    for raw in policies:
        if not isinstance(raw, dict):
            stats["unparsed"] += 1
            findings.append({
                "check": "entry-unparsed", "severity": "high",
                "constraint": "",
                "message": "elemen ekspor bukan objek policy — tidak "
                           "dievaluasi (fail-closed).",
            })
            continue
        stats["entries_total"] += 1
        constraint = str(raw.get("constraint", "")).strip()
        spec = _classify_spec(raw)
        if spec is None:
            dr = raw.get("dryRunSpec")
            if isinstance(dr, dict):
                stats["entries_dryrun"] += 1
                if constraint:
                    dryrun_constraints.add(constraint)
                continue
            stats["unparsed"] += 1
            findings.append({
                "check": "entry-unparsed", "severity": "high",
                "constraint": constraint,
                "message": "policy tanpa booleanPolicy/listPolicy/"
                           "restoreDefault/dryRunSpec yang dikenal — "
                           "tidak dievaluasi (fail-closed).",
            })
            continue
        if not constraint:
            stats["unparsed"] += 1
            findings.append({
                "check": "entry-unparsed", "severity": "high",
                "constraint": "",
                "message": "objek policy tanpa field constraint — tidak "
                           "bisa dipetakan (fail-closed).",
            })
            continue
        cur = status_map.get(constraint)
        if cur is None or RANK[spec] > RANK[cur]:
            status_map[constraint] = spec

    stats["constraints_enforced"] = sum(
        1 for v in status_map.values() if v == "valid")
    all_seen = set(status_map) | dryrun_constraints
    stats["extra_constraints"] = sum(1 for c in all_seen if c not in BASELINE)

    for constraint in BASELINE:
        expectation = BASELINE[constraint]
        status = status_map.get(constraint)
        if status == "valid":
            continue
        if status is None and constraint in dryrun_constraints:
            stats["constraints_dryrun_only"] += 1
            findings.append({
                "check": "constraint-dry-run", "severity": "medium",
                "constraint": constraint,
                "message": "hanya dryRunSpec yang ada — dampak dimonitor "
                           "belum di-enforce; selesaikan dry-run lalu "
                           "set policy efektif.",
            })
            continue
        if status is None:
            findings.append({
                "check": "constraint-missing", "severity": "high",
                "constraint": constraint,
                "message": f"constraint baseline ({expectation}) tidak ada "
                           "di ekspor — belum diset di scope ini; "
                           "guardrail default Google berlaku.",
            })
            continue
        if status == "weak":
            findings.append({
                "check": "constraint-weak", "severity": "high",
                "constraint": constraint,
                "message": "policy ada tapi tidak mengikat "
                           "(enforced=false / allValues=ALLOW / listPolicy "
                           "kosong) — sama efeknya dgn tidak diset.",
            })
        elif status == "restore":
            findings.append({
                "check": "constraint-weak", "severity": "high",
                "constraint": constraint,
                "message": "restoreDefault — constraint di-reset ke "
                           "perilaku default Google (tidak mengikat).",
            })
        elif status == "exceptions" and expectation == "list-deny":
            findings.append({
                "check": "constraint-exceptions", "severity": "medium",
                "constraint": constraint,
                "message": "listPolicy dgn daftar nilai eksplisit — "
                           "pengecualian (mis. bastion) sah bila "
                           "direview: pastikan owner + alasan "
                           "terdokumentasi.",
            })
        # exceptions dgn expectation 'present' (resourceLocations):
        # keberadaan list-policy cukup = bukan temuan
    return findings, stats


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit cakupan Organization Policy GCP dari ekspor "
                    "JSON gcloud — offline, nol jaringan.")
    ap.add_argument("--policies", required=True,
                    help="JSON ekspor: gcloud org-policies list "
                         "--organization=ORG_ID --format=json")
    ap.add_argument("--skip-constraint", action="append", default=[],
                    metavar="CONSTRAINT",
                    help="abaikan constraint ini (bisa diulang); dicatat")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high", "critical"],
                    help="severity minimum yang memicu exit 1 (default high)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    path = Path(args.policies)
    try:
        if not path.is_file():
            raise ValueError(f"file tidak ada: {path}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("file terlalu besar")
        doc = json.loads(path.read_text(encoding="utf-8"))
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    if not isinstance(doc, list):
        print(json.dumps({
            "schema": SCHEMA,
            "error": "ekspor harus array policy JSON (pakai --format=json)",
        }), file=sys.stderr)
        return 2
    if not doc:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "daftar policy kosong — bukan audit; cek scope "
                     "(org/folder/project) dan --format ekspor",
        }), file=sys.stderr)
        return 2

    findings, stats = audit_policies(doc)
    skip = {str(s).strip() for s in args.skip_constraint if str(s).strip()}
    if skip:
        kept = []
        for f in findings:
            if f["constraint"] in skip:
                stats["skipped_constraints"] = \
                    stats.get("skipped_constraints", 0) + 1
                continue
            kept.append(f)
        findings = kept

    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEV_ORDER.get(f["severity"], 0) >= threshold]
    notes = [
        "audit cakupan per-scope: ekspor org-policies list tidak "
        "menyertakan efek pewarisan lintas org/folder/project — "
        "bandingkan ekspor tiap scope bila hierarki dipakai.",
        "constraint di luar baseline dihitung di stats.extra_constraints "
        "(inventaris), bukan temuan.",
        "dry-run policy (Policy Intelligence) adalah langkah rollout yang "
        "sah — temuan dry-run = reminder menyelesaikan enforcement.",
    ]
    if stats.get("unparsed"):
        notes.append("ada elemen tak ter-parse — hasil TIDAK dianggap "
                     "bersih (fail-closed).")
    if stats.get("skipped_constraints"):
        notes.append(f"{stats['skipped_constraints']} temuan disaring via "
                     "--skip-constraint — saringan dicatat, tidak dipendam.")

    report = {
        "schema": SCHEMA,
        "stats": stats,
        "findings": sorted(
            findings,
            key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                           f["constraint"], f["check"])),
        "notes": notes,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())

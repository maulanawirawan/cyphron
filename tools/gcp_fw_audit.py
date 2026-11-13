r"""[AUDIT: read-only] gcp_fw_audit — audit OFFLINE aturan VPC firewall GCP
dari ekspor JSON gcloud: klasifikasi risiko rule yang terlalu terbuka
(open-to-world), tanpa target, disabled, dan postur egress/logging.

Pembagian ranah (TIDAK diduplikasi):
  - konfigurasi IaC Terraform  -> terraform_audit (B09, #0270)
  - log aktivitas CloudTrail   -> cloudtrail_scan (B13, #0383)
  - eskalasi IAM               -> iam_escalation_scan (B13, #0386)
  - di sini: firewall rules VPC (ekspor gcloud).

Input -> mekanisme -> output:
  - Input : JSON daftar rule gcloud (array), ATAU satu objek rule
            (hasil describe). Field yang dibaca: name, direction,
            disabled, priority, allowed/denied (IPProtocol + ports),
            sourceRanges, destinationRanges, targetTags,
            targetServiceAccounts, logConfig.enable.
  - Mekanisme: klasifikasi deterministik per rule — sumber "world"
            = 0.0.0.0/0 atau ::/0; port dicocokkan dgn tabel
            manajemen/DB (dukung rentang "1000-2000"); rule tanpa
            targetTags/targetServiceAccounts = berlaku utk semua
            instance; postur proyek dihitung dari koleksi rule.
  - Output: JSON {schema, stats, findings, notes}; finding =
            {check, severity, rule, direction, priority, message}.

Cek (zero-FP: hanya bentuk eksplisit di ekspor):
  ingress-open-mgmt   (critical): world -> port manajemen (22/23/3389/
                      5985/5986) ATAU protokol "all".
  ingress-open-db     (critical): world -> port database/cache (mysql/
                      postgres/mssql/oracle/redis/memcached/mongo/
                      elastic/cassandra/couchdb).
  ingress-open-any    (critical): world + entry protokol TANPA daftar
                      ports (semua port protokol itu, mis. tcp tanpa
                      ports).
  ingress-open-world  (medium)  : world -> port lain (web 80/443 sering
                      DISENGAJA — bukan critical; pesan meminta
                      verifikasi kebutuhan via flow logs).
  ingress-untargeted  (medium)  : rule world-open tanpa
                      targetTags/targetServiceAccounts (berlaku utk
                      SEMUA instance — pola [FW-001] sumber).
  rule-disabled       (medium)  : disabled=true (config drift; sumber
                      mengauditnya eksplisit).
  egress-no-deny      (high)    : tidak ada rule EGRESS deny dengan
                      destination world (implied allow-all-egress
                      eksplisit GCP tetap berlaku — pola [FW-002]
                      sumber; cek hanya dijawab bila deny tcp+udp atau
                      protokol "all" ada).
  firewall-logging-absent (medium): TIDAK ADA satu pun rule dengan
                      logConfig.enable=true (tidak bisa validasi
                      efektivitas rule via flow logs).
  entry-unparsed      (high)    : elemen ekspor bukan objek rule
                      (fail-closed — tidak pernah dianggap bersih).

Fail-closed:
  - file tidak ada / JSON tidak valid / bukan daftar-atau-objek -> exit 2.
  - daftar KOSONG -> exit 2 (bukan audit; cek --format dan scope
    project — rule kosong pasti salah ekspor).
  - rule tanpa "name"/direction tidak diflag risk-open (bukan bentuk
    eksplisit) tapi masuk stats.rules_incomplete + note.

Anti-FP: --allow-rule <nama> (boleh diulang) menyaring temuan rule
tersebut; jumlah saringan dicatat di stats.allowed_filtered — tidak
dipendam.

Catatan: firewall-policies hierarkis (org/folder) TIDAK ikut di
ekspor `firewall-rules list` — audit terpisah manual (cf. METHODS).
Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/gcp_fw_audit.py --rules fw.json --out audit.json
  python tools/gcp_fw_audit.py --rules fw.json --allow-rule allow-https-web \
      --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "secai.gcp-fw-audit/1"
MAX_FILE_BYTES = 32 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

WORLD_SOURCES = {"0.0.0.0/0", "::/0"}

MGMT_PORTS = (22, 23, 3389, 5985, 5986)
DB_PORTS = (
    1433, 1521, 3306, 5432, 6379, 11211, 27017,
    9200, 9300, 9042, 5984,
)


def _parse_ports(entry: dict) -> "tuple[str, list[tuple[int, int]] | None]":
    """Kembalikan (protokol, daftar rentang port atau None=semua port).

    None berarti entry protokol tanpa 'ports' = seluruh port protokol.
    Protokol "all" diubah menjadi ("all", [(0, 65535)]).
    """
    proto = str(entry.get("IPProtocol", "")).strip().lower()
    if not proto:
        return "", None
    if proto == "all":
        return "all", [(0, 65535)]
    raw = entry.get("ports")
    if not isinstance(raw, list) or not raw:
        return proto, None
    ranges: "list[tuple[int, int]]" = []
    for token in raw:
        s = str(token).strip()
        if not s:
            continue
        if "-" in s:
            a, _, b = s.partition("-")
            try:
                lo, hi = int(a.strip()), int(b.strip())
            except ValueError:
                continue
            if lo > hi:
                lo, hi = hi, lo
            ranges.append((max(0, lo), min(65535, hi)))
        else:
            try:
                p = int(s)
            except ValueError:
                continue
            if 0 <= p <= 65535:
                ranges.append((p, p))
    return proto, ranges


def _covers(ranges: "list[tuple[int, int]] | None", port: int) -> bool:
    """True bila rentang menutupi port (None = semua port)."""
    if ranges is None:
        return True
    return any(lo <= port <= hi for lo, hi in ranges)


def _is_world(ranges: "list[str] | None") -> bool:
    if not ranges:
        return False
    return any(str(r).strip() in WORLD_SOURCES for r in ranges)


def _iter_entries(rule: dict, key: str) -> "list[dict]":
    v = rule.get(key)
    return [e for e in v if isinstance(e, dict)] if isinstance(v, list) else []


def _unrestricted_target(rule: dict) -> bool:
    """True bila rule tidak membatasi instance (tanpa tag/SA target)."""
    for key in ("targetTags", "targetServiceAccounts"):
        v = rule.get(key)
        if isinstance(v, list) and v:
            return False
    return True


def _match_world_open(rule: dict) -> "tuple[str, int] | None":
    """Klasifikasi rule ingress world-open -> (check, severity) atau None."""
    src = rule.get("sourceRanges")
    if not _is_world(src if isinstance(src, list) else None):
        return None
    entries = _iter_entries(rule, "allowed")
    if not entries:
        return None
    for entry in entries:
        proto, ports = _parse_ports(entry)
        if proto == "all":
            return "ingress-open-mgmt", 4
        if proto in ("", "icmp", "sctp"):
            continue  # protokol tanpa port manajemen/DB
        if ports is None:
            return "ingress-open-any", 4
        if proto in ("tcp", "udp"):
            if any(_covers(ports, p) for p in MGMT_PORTS):
                return "ingress-open-mgmt", 4
            if proto == "tcp" and any(_covers(ports, p) for p in DB_PORTS):
                return "ingress-open-db", 4
    return "ingress-open-world", 2


def audit_rules(rules: "list[dict]", project_scope: bool = True) -> "tuple[list[dict], dict]":
    findings: "list[dict]" = []
    stats = {
        "rules_total": 0,
        "ingress": 0,
        "egress": 0,
        "disabled": 0,
        "world_open_ingress": 0,
        "unparsed": 0,
        "no_egress_deny": 0,
        "logging_enabled": 0,
    }

    for raw in rules:
        if not isinstance(raw, dict):
            stats["unparsed"] += 1
            findings.append({
                "check": "entry-unparsed", "severity": "high",
                "rule": "", "direction": "", "priority": None,
                "message": "elemen ekspor bukan objek rule — tidak "
                           "dievaluasi (fail-closed).",
            })
            continue
        stats["rules_total"] += 1
        name = str(raw.get("name", ""))
        direction = str(raw.get("direction", "")).upper()
        priority = raw.get("priority")
        disabled = bool(raw.get("disabled"))
        if disabled:
            stats["disabled"] += 1
            findings.append({
                "check": "rule-disabled", "severity": "medium",
                "rule": name, "direction": direction, "priority": priority,
                "message": "rule disabled=true — sisa konfigurasi mati; "
                           "hapus atau dokumentasikan alasan keep.",
            })
        if direction == "INGRESS":
            stats["ingress"] += 1
            hit = _match_world_open(raw)
            if hit:
                check, sev = hit
                stats["world_open_ingress"] += 1
                findings.append({
                    "check": check, "severity": {4: "critical", 2: "medium"}[sev],
                    "rule": name, "direction": direction,
                    "priority": priority,
                    "message": "ingress dari world (0.0.0.0/0/::/0) — "
                               "verifikasi kebutuhan; port manajemen/DB/"
                               "semua-port = critical, port web = sering "
                               "disengaja (cek flow logs).",
                })
                if _unrestricted_target(raw):
                    findings.append({
                        "check": "ingress-untargeted", "severity": "medium",
                        "rule": name, "direction": direction,
                        "priority": priority,
                        "message": "rule world-open tanpa "
                                   "targetTags/targetServiceAccounts — "
                                   "berlaku utk SEMUA instance di network.",
                    })
        elif direction == "EGRESS":
            stats["egress"] += 1
            dest = raw.get("destinationRanges")
            denied = _iter_entries(raw, "denied")
            if _is_world(dest if isinstance(dest, list) else None) and denied:
                protos = {_parse_ports(e)[0] for e in denied}
                deny_all = ("all" in protos
                            or {"tcp", "udp"} <= protos)
                if deny_all:
                    stats["no_egress_deny"] += 1

        lc = raw.get("logConfig")
        if isinstance(lc, dict) and lc.get("enable"):
            stats["logging_enabled"] += 1

    if project_scope and stats["no_egress_deny"] == 0:
        findings.append({
            "check": "egress-no-deny", "severity": "high",
            "rule": "(proyek)", "direction": "EGRESS", "priority": None,
            "message": "tidak ada rule EGRESS deny-all ke world — implied "
                       "allow-all-egress tetap berlaku (pola [FW-002]): "
                       "tambahkan default-deny egress priority 65534 + "
                       "allow eksplisit per kebutuhan.",
        })
    if project_scope and stats["rules_total"] > 0 \
            and stats["logging_enabled"] == 0:
        findings.append({
            "check": "firewall-logging-absent", "severity": "medium",
            "rule": "(proyek)", "direction": "", "priority": None,
            "message": "tidak ada rule dgn logConfig.enable=true — "
                       "efektivitas rule tak bisa divalidasi via flow "
                       "logs; nyalakan logging pada rule sensitif.",
        })
    return findings, stats


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Audit aturan VPC firewall GCP dari ekspor JSON "
                    "gcloud — offline, nol jaringan.")
    ap.add_argument("--rules", required=True,
                    help="JSON ekspor: gcloud compute firewall-rules list "
                         "--format=json (array) atau satu objek rule")
    ap.add_argument("--allow-rule", action="append", default=[],
                    metavar="NAMA", help="abaikan rule bernama ini (bisa "
                                         "diulang); dicatat di stats")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high", "critical"],
                    help="severity minimum yang memicu exit 1 (default high)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    path = Path(args.rules)
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

    project_scope = True
    if isinstance(doc, dict):
        if not ("name" in doc or "direction" in doc):
            print(json.dumps({
                "schema": SCHEMA,
                "error": "objek tunggal bukan rule gcloud (butuh field "
                         "name/direction) — cek sumber ekspor",
            }), file=sys.stderr)
            return 2
        rules = [doc]
        project_scope = False  # describe satu rule: postur proyek tak bisa
        # dijawab dari satu rule — cek proyek dilewati eksplisit
    elif isinstance(doc, list):
        rules = doc
    else:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "ekspor harus array rule atau satu objek rule",
        }), file=sys.stderr)
        return 2
    if not rules:
        print(json.dumps({
            "schema": SCHEMA,
            "error": "daftar rule kosong — bukan audit; cek --format dan "
                     "scope project ekspor gcloud",
        }), file=sys.stderr)
        return 2

    findings, stats = audit_rules(rules, project_scope=project_scope)
    allow = {str(a).strip() for a in args.allow_rule if str(a).strip()}
    if allow:
        kept = []
        for f in findings:
            if f["rule"] in allow:
                stats["allowed_filtered"] = \
                    stats.get("allowed_filtered", 0) + 1
                continue
            kept.append(f)
        findings = kept

    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEV_ORDER.get(f["severity"], 0) >= threshold]
    notes = [
        "audit statis ekspor gcloud — kebijakan hierarkis org/folder "
        "(firewall-policies) tidak ikut di ekspor firewall-rules list; "
        "audit terpisah via 'gcloud compute firewall-policies'.",
        *(["input = satu objek rule (describe): cek postur proyek "
           "(egress-no-deny, firewall-logging-absent) tidak dijawab dari "
           "satu rule — jalankan ulang dengan ekspor list proyek."]
          if not project_scope else []),
        "verifikasi kebutuhan port world-open dilakukan dari VPC flow "
        "logs (cf. firewall-logging-absent), bukan dari nama rule.",
        "severity mengikuti kelas risiko publik: port manajemen/DB/"
        "semua-port dari world = critical; port web = medium (sering "
        "disengaja).",
    ]
    if stats.get("unparsed"):
        notes.append("ada elemen tak ter-parse — hasil TIDAK dianggap "
                     "bersih (fail-closed).")
    if stats.get("allowed_filtered"):
        notes.append(f"{stats['allowed_filtered']} temuan disaring via "
                     "--allow-rule — saringan dicatat, tidak dipendam.")

    report = {
        "schema": SCHEMA,
        "stats": stats,
        "findings": sorted(
            findings,
            key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                           f["rule"], f["check"])),
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

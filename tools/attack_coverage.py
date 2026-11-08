r"""[AUDIT: read-only] attack_coverage — matriks cakupan deteksi MITRE
ATT&CK dari ekspor rule deteksi: rule mana memetakan teknik mana,
teknik mana yang hanya punya rule MATI/tanpa-sumber-data, dan gap
terhadap universe teknik prioritas. Offline, nol jaringan.

Mengisi antrean port dari mukul975/Anthropic-Cybersecurity-Skills
'skills/implementing-mitre-attack-coverage-mapping' (#0660 — build
coverage matrix, identifikasi gap, prioritas pengembangan rule, ukur
maturity; atribusi konsep, lisensi sumber Apache-2.0). Dibangun FROM
SCRATCH TANPA kode sumber itu; stdlib json/csv/re saja.

Premis sumber yang diekstrak (statistik CardinalOps yang dikutip skill):
rule yang ADA bukan berarti cakupan — rule nonaktif/draft atau
dengan sumber data yang tidak siap = NON-FUNCTIONAL (dihitung
eksplisit, tidak dianggap cakupan). Karena itu state per teknik:

  covered : >=1 rule ACTIVE dengan data_ready=true
  partial : ada rule tapi tidak satu pun active+data_ready (rule
            disabled/draft, data_ready=false, atau field data_ready
            tidak ada di ekspor — ketidakpastian TIDAK dianggap aman)
  gap     : ada di universe, tidak ada rule sama sekali

Input -> mekanisme -> output:
  - Input : --rules FILE[,FILE...] — JSON (array rule, atau objek
            dgn kunci "rules") ATAU CSV ber-header (kolom fleksibel:
            name/title, techniques/technique_ids/mitre_attack
            [pemisah ; atau ,], status/enabled, data_ready).
            --universe FILE (opsional) — JSON {id: {name, tactic}},
            JSON array id, atau teks satu id per baris (techniques
            prioritas; tanpa ini gap dinilai terhadap gabungan teknik
            yang terlihat di rule dan dicatat eksplisit di notes).
  - Mekanisme: normalisasi field (alias + ekstraksi regex
            T\\d{4}(\\.\\d{3})? dari nilai string) -> state per
            teknik -> ringkasan + breakdown per tactic (bila universe
            membawa field tactic).
  - Output: {summary, techniques, notes}. Rule tanpa teknik ATT&CK
            dihitung "unmapped" (rule tak terlihat oleh matriks =
            temuan tersendiri).

Fail-closed: file tidak ada / tidak valid / tidak ada rule ter-parse
-> exit 2; rule rusak/tanpa nama tercatat, tidak dibuang diam-diam.

Exit: 0 cakupan penuh (atau tanpa universe — informatif); 1 ada gap
(atau partial bila --fail-on partial); 2 error input.
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.attack-coverage/1"
MAX_FILE_BYTES = 16 * 1024 * 1024
RE_TECH = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.I)

STATE_ORDER = {"gap": 0, "partial": 1, "covered": 2}


def _read_text(path: Path) -> str:
    if not path.is_file():
        raise ValueError(f"file tidak ada: {path}")
    if path.stat().st_size > MAX_FILE_BYTES:
        raise ValueError(f"melebihi batas ukuran: {path}")
    return path.read_text(encoding="utf-8", errors="replace")


def _norm_techs(value: object) -> "list[str]":
    """Ekstrak ID ATT&CK dari string/list/string-bebas."""
    if value is None:
        return []
    items = value if isinstance(value, list) else [value]
    out: "list[str]" = []
    for it in items:
        if isinstance(it, str):
            out.extend(m.group(0).upper() for m in RE_TECH.finditer(it))
    return out


def _bool_field(value: object) -> "bool | None":
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        low = value.strip().lower()
        if low in ("true", "yes", "1", "y"):
            return True
        if low in ("false", "no", "0", "n"):
            return False
    return None


def _rule_status(rule: dict) -> str:
    """active / disabled / draft (alias enabled boolean)."""
    for key in ("status", "state"):
        v = rule.get(key)
        if isinstance(v, str) and v.strip():
            low = v.strip().lower()
            if low in ("active", "enabled", "on", "production"):
                return "active"
            if low in ("draft", "dev", "test"):
                return "draft"
            if low in ("disabled", "off", "retired", "paused"):
                return "disabled"
    if "enabled" in rule:
        b = _bool_field(rule.get("enabled"))
        if b is True:
            return "active"
        if b is False:
            return "disabled"
    return "active"  # ekspor tanpa field status diasumsikan aktif


def _rule_name(rule: dict) -> "str | None":
    for key in ("name", "title", "rule_name", "id"):
        v = rule.get(key)
        if isinstance(v, str) and v.strip():
            return v.strip()
    return None


def _rule_data_ready(rule: dict) -> "bool | None":
    for key in ("data_ready", "data_source_ready", "dataSourceReady"):
        if key in rule:
            return _bool_field(rule.get(key))
    return None


def parse_rules_file(path: Path) -> "tuple[list[dict], list[str]]":
    """Kembalikan (rules ternormalisasi, catatan parse)."""
    text = _read_text(path)
    notes: "list[str]" = []
    rules: "list[dict]" = []
    stripped = text.strip()
    if stripped.startswith("{") or stripped.startswith("["):
        data = json.loads(stripped)
        if isinstance(data, dict):
            for key in ("rules", "detections", "analytics"):
                if isinstance(data.get(key), list):
                    data = data[key]
                    break
        if not isinstance(data, list):
            raise ValueError(f"{path}: JSON bukan daftar rule")
        raw_rules = [r for r in data if isinstance(r, dict)]
    else:
        reader = csv.DictReader(io.StringIO(text))
        raw_rules = [dict(r) for r in reader if r]
        if not raw_rules:
            raise ValueError(f"{path}: CSV tanpa baris data")

    for idx, r in enumerate(raw_rules, 1):
        name = _rule_name(r)
        techs = []
        for key in ("techniques", "technique_ids", "technique",
                    "attack", "mitre_attack", "mitre", "attack_techniques"):
            techs.extend(_norm_techs(r.get(key)))
        if name is None:
            notes.append(f"{path}: rule #{idx} tanpa nama — dicatat, "
                         "tidak dibuang diam-diam")
            name = f"(unnamed #{idx})"
        rules.append({"name": name, "techniques": sorted(set(techs)),
                      "status": _rule_status(r),
                      "data_ready": _rule_data_ready(r),
                      "unmapped": not techs})
    if not rules:
        raise ValueError(f"{path}: tidak ada rule ter-parse "
                         "(fail-closed)")
    return rules, notes


def load_universe(path: Path) -> "dict[str, dict]":
    """Universe teknik: JSON {id: {name, tactic}} / array / teks."""
    text = _read_text(path).strip()
    techs: "dict[str, dict]" = {}
    if text.startswith("{") or text.startswith("["):
        data = json.loads(text)
        if isinstance(data, dict):
            for k, v in data.items():
                m = RE_TECH.search(k)
                if not m:
                    continue
                meta = v if isinstance(v, dict) else {}
                techs[m.group(0).upper()] = {
                    "name": meta.get("name"), "tactic": meta.get("tactic")}
        elif isinstance(data, list):
            for it in data:
                for m in RE_TECH.finditer(str(it)):
                    techs[m.group(0).upper()] = {"name": None,
                                                 "tactic": None}
        else:
            raise ValueError(f"{path}: universe JSON tak dikenali")
    else:
        for line in text.splitlines():
            for m in RE_TECH.finditer(line):
                techs[m.group(0).upper()] = {"name": None, "tactic": None}
    if not techs:
        raise ValueError(f"{path}: universe tidak memuat ID ATT&CK "
                         "(fail-closed)")
    return techs


def compute_coverage(rules: "list[dict]",
                     universe: "dict[str, dict] | None") -> dict:
    """State per teknik + ringkasan (murni, untuk test)."""
    by_tech: "dict[str, dict]" = {}
    for r in rules:
        techs = sorted(set(_norm_techs(r.get("techniques"))))
        status = r.get("status") or "active"
        data_ready = r.get("data_ready")
        unmapped = r.get("unmapped", not techs)
        r = dict(r, techniques=techs, status=status,
                 data_ready=data_ready, unmapped=unmapped)
        for t in techs:
            slot = by_tech.setdefault(t, {"rules": []})
            slot["rules"].append(r["name"])
            if status == "active" and data_ready is True:
                slot["has_good"] = True
            elif status == "active" and data_ready is None:
                slot["has_active_no_data_field"] = True
            else:
                slot["has_stale"] = True

    universe_ids = set(universe) if universe else set(by_tech)
    techniques = []
    for t in sorted(universe_ids):
        slot = by_tech.get(t, {})
        if slot.get("has_good"):
            state = "covered"
        elif slot:
            state = "partial"
        else:
            state = "gap"
        meta = (universe or {}).get(t, {})
        techniques.append({"id": t, "state": state,
                           "name": meta.get("name"),
                           "tactic": meta.get("tactic"),
                           "rules": slot.get("rules", [])})
    # teknik yang muncul di rule tapi di luar universe tetap dilaporkan
    for t in sorted(set(by_tech) - universe_ids):
        slot = by_tech[t]
        state = ("covered" if slot.get("has_good") else "partial")
        techniques.append({"id": t, "state": state, "name": None,
                           "tactic": None, "rules": slot["rules"],
                           "outside_universe": True})

    summary = {
        "rules_total": len(rules),
        "rules_active": sum(1 for r in rules
                            if (r.get("status") or "active") == "active"),
        "rules_disabled": sum(1 for r in rules
                              if r.get("status") == "disabled"),
        "rules_draft": sum(1 for r in rules
                           if r.get("status") == "draft"),
        "rules_unmapped": sum(1 for r in rules
                              if r.get("unmapped",
                                       not (r.get("techniques") or []))),
        "rules_data_ready_field_missing":
            sum(1 for r in rules if r.get("data_ready") is None),
        "techniques_unique": len(by_tech),
        "universe_size": len(universe_ids),
        "covered": sum(1 for t in techniques
                       if t["state"] == "covered"
                       and not t.get("outside_universe")),
        "partial": sum(1 for t in techniques
                       if t["state"] == "partial"
                       and not t.get("outside_universe")),
        "gap": sum(1 for t in techniques
                   if t["state"] == "gap"),
        "non_functional_rules": sum(
            1 for r in rules
            if (r.get("status") or "active") != "active"
            or r.get("data_ready") is not True),
    }
    if universe is None:
        summary["universe_size"] = len(universe_ids)
    by_tactic: "dict[str, dict]" = {}
    if universe:
        for t in techniques:
            if t.get("outside_universe"):
                continue
            tac = t["tactic"] or "(tanpa-tactic)"
            slot = by_tactic.setdefault(tac, {"covered": 0, "partial": 0,
                                              "gap": 0, "total": 0})
            slot[t["state"]] += 1
            slot["total"] += 1
    return {"summary": summary, "techniques": techniques,
            "by_tactic": by_tactic}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Matriks cakupan deteksi MITRE ATT&CK dari ekspor "
                    "rule (offline, nol jaringan).")
    ap.add_argument("--rules", required=True,
                    help="file rule dipisah koma (JSON/CSV)")
    ap.add_argument("--universe", default=None,
                    help="teknik prioritas (JSON/teks); tanpa ini "
                         "universe = gabungan teknik di rule")
    ap.add_argument("--fail-on", default="gap",
                    choices=["gap", "partial", "none"],
                    help="state minimum yang memicu exit 1")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    rules: "list[dict]" = []
    parse_notes: "list[str]" = []
    try:
        for part in args.rules.split(","):
            if not part.strip():
                continue
            rs, notes = parse_rules_file(Path(part.strip()))
            rules.extend(rs)
            parse_notes.extend(notes)
        universe = load_universe(Path(args.universe)) \
            if args.universe else None
    except (ValueError, OSError, json.JSONDecodeError) as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    result = compute_coverage(rules, universe)
    summary = result["summary"]
    notes = list(parse_notes) + [
        "rule nonaktif/draft dan rule tanpa data_ready=true dihitung "
        "NON-FUNCTIONAL — tidak dianggap cakupan (premis skill: rule "
        "ada ≠ deteksi jalan).",
        "tanpa --universe, gap dinilai terhadap gabungan teknik yang "
        "terlihat di rule sendiri — gap SESUNGGUHNYA butuh daftar "
        "technique prioritas (ekspor ATT&CK Navigator / kurasi SOC).",
        "field data_ready yang hilang pada ekspor = partial (bukan "
        "covered) — ketidakpastian tidak dianggap aman (fail-closed).",
    ]
    threshold = STATE_ORDER[args.fail_on] if args.fail_on != "none" \
        else -1
    worst = min((STATE_ORDER[t["state"]] for t in result["techniques"]
                 if not t.get("outside_universe")), default=2)
    report = {"schema": SCHEMA, "summary": summary,
              "by_tactic": result["by_tactic"],
              "techniques": result["techniques"], "notes": notes}
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if worst <= threshold else 0


if __name__ == "__main__":
    raise SystemExit(main())

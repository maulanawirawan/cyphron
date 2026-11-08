"""[TRIAGE: score] ssvc_triage — prioritas kerentanan via SSVC (Stakeholder-
Specific Vulnerability Categorization): tabel keputusan resmi SSVC v2.0
deployer + sub-tabel human impact, kosakata outcome CISA Guide — OFFLINE,
nol jaringan, fail-closed.

Mengisi antrean port SKILL-PORT-QUEUE #0991 (mukul975/Anthropic-
Cybersecurity-Skills 'triaging-vulnerabilities-with-ssvc-framework';
atribusi konsep, lisensi sumber Apache-2.0). Skill sumber menyederhanakan
pohon SSVC (5 titik keputusan verbal, branch EPSS/KEV live via API). Inti
deterministik yang diport di sini dievaluasi dari TABEL KEPUTUSAN RESMI:
'Patch Application Priority' deployer (72 baris) + sub-tabel 'Human
Impact' (16 baris) — data terpublikasi CERT/CC SSVC (repo CERTCC/SSVC,
data/csv/ssvc; Copyright Carnegie Mellon University, lisensi MIT
(SEI)-style) — di-embed sebagai data referensi, bukan kode sumber skill.
Kosakata outcome memakai pemetaan CISA SSVC Guide:
  immediate    -> Act     (mitigasi segera)
  out-of-cycle -> Attend  (di luar siklus patch)
  scheduled    -> Track*  (window patch berikutnya)
  defer        -> Track   (siklus patch normal)
SLA default per outcome (heuristik skill sumber, dibawa keluar sebagai
default — bukan kebijakan resmi): Act 48 jam, Attend 14 hari, Track* 60
hari, Track 90 hari.

Kenapa secai butuh: keluarga triase kerentanan sudah punya cvss_score
(skor teknis CVSS v3.1), owasp_risk_rating (konteks bisnis web),
risk_matrix_80030 (register 5x5 NIST), brocards_triage (gerbang mutu
laporan), vuln_sla_aging (aging + SLA severity statis) — belum ada yang
menaikkan prioritas dari STATUS EKSPLOITASI (KEV/PoC/EPSS), exposure
sistem, automatability, dan human impact sekaligus = SSVC.

Ranah EKSPLISIT: cvss_score/owasp_risk_rating/risk_matrix_80030 =
penskoran berbasis skor/konteks; vuln_sla_aging = SLA pasca-prioritas;
di sini = pohon keputusan SSVC v2.0 untuk DEPLOYER (patch application
priority). Skill sumber memakai titik 'technical impact'/'mission
prevalence'/'well-being' versi ringkas; tabel resmi v2.0 memakai System
Exposure + Human Impact (= f(Safety x Mission Impact)) — versi resmi yang
dinilai lengkap di sini, heuristik derivasi tetap diambil dari skill.

Titik keputusan & sumbernya (nilai eksplisit SELALU menang; sumber tiap
titik tercatat di provenance per entri):
  exploitation: none|poc|active
    flag/per-entri > KEV (--kev-json, katalog CISA offline; CVE di
    katalog = active) > EPSS (per-entri/--epss-json, epss > ambang
    --epss-poc-threshold default 0.5 = poc, heuristik skill sumber) >
    none (HANYA bila cve ada = sudah dicek katalog, label
    'derived:no-evidence'); tanpa cve & tanpa flag eksplisit = error
    (fail-closed — tanpa bukti, tak boleh diasumsikan aman).
  exposure: small|controlled|open — flag --default-exposure atau
    per-entri WAJIB (konteks lingkungan; tidak ditebak).
  automatable: no|yes — flag/per-entri > derivasi CVSS vektor
    (AV:N+AC:L+UI:N = yes, else no; heuristik skill sumber) >
    --default-automatable; tanpa semuanya = error.
  safety: negligible|marginal|critical|catastrophic — default flag /
    per-entri WAJIB.
  mission: degraded|mef-support-crippled|mef-failure|mission-failure —
    default flag / per-entri WAJIB.

Fail-closed:
  - source/kev/epss JSON tidak ada/rusak/berstruktur salah -> exit 2;
  - titik keputusan di luar kosakata, automatable bukan bool/yes/no ->
    entri masuk errors, tak pernah dinilai;
  - CVSS vektor yang ADA tapi malformed (metrik tak dikenal) -> error
    (typo-protection), meski automatable eksplisit;
  - EPSS bukan angka 0-1 -> baris dilewati (dihitung), file rusak
    global tetap exit 2;
  - --fail-on act|attend|track*|track|any -> exit 1.

Pemakaian:
  python tools/ssvc_triage.py --source vulns.json --kev-json kev.json
  python tools/ssvc_triage.py --source v.json --kev-json kev.json \
      --default-exposure open --default-safety marginal \
      --default-mission mef-failure --default-automatable yes \
      --out ssvc.json --fail-on attend
Exit: 0 selesai; 1 ada keputusan >= --fail-on; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.ssvc-triage/1"
MAX_FILE_BYTES = 8 * 1024 * 1024

EXPLOITATION = ("none", "poc", "active")
EXPOSURE = ("small", "controlled", "open")
AUTOMATABLE = ("no", "yes")
SAFETY = ("negligible", "marginal", "critical", "catastrophic")
MISSION = ("degraded", "mef-support-crippled", "mef-failure",
           "mission-failure")
HUMAN = ("low", "medium", "high", "very high")

# kosakata outcome tabel resmi (SSVC v2.0 deployer) -> nama CISA Guide
OUTCOME_CISA = {
    "immediate": "act",
    "out-of-cycle": "attend",
    "scheduled": "track*",
    "defer": "track",
}
CISA_ORDER = ("track", "track*", "attend", "act")
CISA_LABEL = {
    "track": "Track — pantau, patch di siklus normal",
    "track*": "Track* — pantau ketat, prioritaskan window berikutnya",
    "attend": "Attend — eskalasi, percepat remediasi",
    "act": "Act — terapkan mitigasi segera, awareness eksekutif",
}
# SLA default heuristik skill sumber (bukan kebijakan resmi)
CISA_SLA = {"track": "90 hari", "track*": "60 hari", "attend": "14 hari",
            "act": "48 jam"}

# sub-tabel Human Impact resmi SSVC v2.0.2 (safety x mission -> human);
# sumber: CERT/CC SSVC data/csv/ssvc/human_impact_1_0_0.csv (CMU SEI)
HUMAN_TABLE: dict[tuple[str, str], str] = {
    ("negligible", "degraded"): "low",
    ("negligible", "mef-support-crippled"): "low",
    ("negligible", "mef-failure"): "medium",
    ("negligible", "mission-failure"): "very high",
    ("marginal", "degraded"): "low",
    ("marginal", "mef-support-crippled"): "low",
    ("marginal", "mef-failure"): "medium",
    ("marginal", "mission-failure"): "very high",
    ("critical", "degraded"): "medium",
    ("critical", "mef-support-crippled"): "high",
    ("critical", "mef-failure"): "high",
    ("critical", "mission-failure"): "very high",
    ("catastrophic", "degraded"): "very high",
    ("catastrophic", "mef-support-crippled"): "very high",
    ("catastrophic", "mef-failure"): "very high",
    ("catastrophic", "mission-failure"): "very high",
}

# tabel keputusan resmi SSVC v2.0 deployer 'Patch Application Priority'
# (exploitation x system exposure x automatable x human impact ->
# defer|scheduled|out-of-cycle|immediate); sumber: CERT/CC SSVC
# data/csv/ssvc/deployer_patch_application_priority_1_0_0.csv (CMU SEI);
# key = (exploitation, exposure, automatable, human_impact)
DEPLOYER_TABLE: dict[tuple[str, str, str, str], str] = {}
_TABLE_TEXT = """
none|small|no|low|defer           none|small|no|medium|defer
none|small|no|high|scheduled      none|small|no|very high|scheduled
none|small|yes|low|defer          none|small|yes|medium|scheduled
none|small|yes|high|scheduled     none|small|yes|very high|scheduled
none|controlled|no|low|defer      none|controlled|no|medium|scheduled
none|controlled|no|high|scheduled none|controlled|no|very high|scheduled
none|controlled|yes|low|scheduled none|controlled|yes|medium|scheduled
none|controlled|yes|high|scheduled
none|controlled|yes|very high|scheduled
none|open|no|low|defer            none|open|no|medium|scheduled
none|open|no|high|scheduled       none|open|no|very high|scheduled
none|open|yes|low|scheduled       none|open|yes|medium|scheduled
none|open|yes|high|scheduled      none|open|yes|very high|out-of-cycle
poc|small|no|low|defer            poc|small|no|medium|scheduled
poc|small|no|high|scheduled       poc|small|no|very high|scheduled
poc|small|yes|low|scheduled       poc|small|yes|medium|scheduled
poc|small|yes|high|scheduled      poc|small|yes|very high|scheduled
poc|controlled|no|low|defer       poc|controlled|no|medium|scheduled
poc|controlled|no|high|scheduled  poc|controlled|no|very high|scheduled
poc|controlled|yes|low|scheduled  poc|controlled|yes|medium|scheduled
poc|controlled|yes|high|scheduled poc|controlled|yes|very high|out-of-cycle
poc|open|no|low|scheduled         poc|open|no|medium|scheduled
poc|open|no|high|scheduled        poc|open|no|very high|out-of-cycle
poc|open|yes|low|scheduled        poc|open|yes|medium|scheduled
poc|open|yes|high|out-of-cycle    poc|open|yes|very high|out-of-cycle
active|small|no|low|scheduled     active|small|no|medium|scheduled
active|small|no|high|out-of-cycle active|small|no|very high|out-of-cycle
active|small|yes|low|scheduled    active|small|yes|medium|out-of-cycle
active|small|yes|high|out-of-cycle
active|small|yes|very high|out-of-cycle
active|controlled|no|low|scheduled
active|controlled|no|medium|scheduled
active|controlled|no|high|out-of-cycle
active|controlled|no|very high|out-of-cycle
active|controlled|yes|low|out-of-cycle
active|controlled|yes|medium|out-of-cycle
active|controlled|yes|high|out-of-cycle
active|controlled|yes|very high|out-of-cycle
active|open|no|low|scheduled      active|open|no|medium|out-of-cycle
active|open|no|high|out-of-cycle  active|open|no|very high|immediate
active|open|yes|low|out-of-cycle  active|open|yes|medium|out-of-cycle
active|open|yes|high|immediate    active|open|yes|very high|immediate
"""
_ROW_RE = re.compile(
    r"\b(none|poc|active)\|(small|controlled|open)\|(no|yes)\|"
    r"(low|medium|high|very high)\|"
    r"(defer|scheduled|out-of-cycle|immediate)\b")
for _m in _ROW_RE.finditer(_TABLE_TEXT):
    DEPLOYER_TABLE[(_m[1], _m[2], _m[3], _m[4])] = _m[5]
if len(DEPLOYER_TABLE) != 72:
    raise RuntimeError(
        f"tabel deployer harus 72 baris unik, dapat {len(DEPLOYER_TABLE)}")


def human_impact(safety: str, mission: str) -> str:
    """Lookup sub-tabel human impact resmi (input sudah kanonik)."""
    return HUMAN_TABLE[(safety, mission)]


def ssvc_outcome(exploitation: str, exposure: str, automatable: str,
                 human: str) -> str:
    """Lookup tabel deployer resmi -> defer/scheduled/out-of-cycle/
    immediate (input sudah kanonik)."""
    return DEPLOYER_TABLE[(exploitation, exposure, automatable, human)]


def cisa_decision(outcome: str) -> tuple[str, str, str]:
    """Outcome SSVC resmi -> (decision CISA, label, SLA default)."""
    dec = OUTCOME_CISA[outcome]
    return dec, CISA_LABEL[dec], CISA_SLA[dec]


def parse_cvss_automatable(vector: str) -> bool:
    """Derivasi automatable dari vektor CVSS v3.x (heuristik skill
    sumber): AV:N + AC:L + UI:N = yes. Vektor malformed/metrik
    tak dikenal = ValueError (vektor CVSS v4.0 pakai kosakata metrik
    berbeda -> ditolak, bukan ditebak)."""
    text = (vector or "").strip()
    if not text.startswith("CVSS:"):
        raise ValueError(f"vektor tidak diawali 'CVSS:': {vector!r}")
    metrics: dict[str, str] = {}
    for part in text.split("/")[1:]:
        if ":" not in part:
            raise ValueError(f"komponen vektor tak sah: {part!r}")
        key, val = part.split(":", 1)
        if not key or not val or key in metrics:
            raise ValueError(f"komponen vektor tak sah: {part!r}")
        metrics[key] = val
    known = {"AV", "AC", "PR", "UI", "S", "C", "I", "A", "E", "RL",
             "RC", "MAV", "MAC", "MPR", "MUI", "MS", "MC", "MI", "MA",
             "CR", "IR", "AR"}
    unknown = set(metrics) - known
    if unknown:
        raise ValueError(f"metrik CVSS tak dikenal: {sorted(unknown)}")
    for req in ("AV", "AC", "UI"):
        if req not in metrics:
            raise ValueError(f"vektor tanpa metrik {req} "
                             f"(AV/AC/UI wajib utk derivasi)")
    return (metrics["AV"] == "N" and metrics["AC"] == "L"
            and metrics["UI"] == "N")


def _norm_automatable(value: object) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    text = str(value).strip().lower()
    if text in ("yes", "true"):
        return "yes"
    if text in ("no", "false"):
        return "no"
    raise ValueError(f"automatable tak sah (bool/yes/no): {value!r}")


def _resolve_exploitation(entry: dict, kev: "set[str] | None",
                          epss_map: "dict[str, float] | None",
                          threshold: float) -> tuple[str, str]:
    """Eksploitation -> (value, source); ValueError bila tak bisa
    dinilai dengan bukti."""
    explicit = entry.get("exploitation")
    if explicit is not None:
        val = str(explicit).strip().lower()
        if val not in EXPLOITATION:
            raise ValueError(f"exploitation di luar kosakata: "
                             f"{explicit!r} ({'|'.join(EXPLOITATION)})")
        return val, "explicit"
    cve = str(entry.get("cve") or "").strip().upper()
    if not cve:
        raise ValueError("exploitation tak bisa dinilai: tanpa cve "
                         "dan tanpa flag eksplisit")
    if kev is not None and cve in kev:
        return "active", "derived:kev"
    if epss_map is not None and cve in epss_map:
        score = epss_map[cve]
        if score > threshold:
            return "poc", f"derived:epss>{threshold:g}"
        return "none", f"derived:epss<={threshold:g}"
    return "none", "derived:no-evidence"


def resolve_points(entry: dict, defaults: dict,
                   kev: "set[str] | None", epss_map: "dict[str, float] | None",
                   threshold: float) -> dict:
    """Selesaikan 5 titik keputusan satu entri -> dict lengkap dgn
    sumber per titik. ValueError utk input salah — pemanggil
    memutuskan error vs lanjut."""
    ref = str(entry.get("id") or "").strip()
    if not ref:
        raise ValueError("entri tanpa id")

    exploit, exploit_src = _resolve_exploitation(entry, kev, epss_map,
                                                 threshold)

    exposure = entry.get("exposure")
    if exposure is None:
        exposure = defaults.get("exposure")
        exposure_src = "default"
        if exposure is None:
            raise ValueError("exposure wajib: flag/per-entri "
                             "atau --default-exposure")
    else:
        exposure = str(exposure).strip().lower()
        exposure_src = "explicit"
    if exposure not in EXPOSURE:
        raise ValueError(f"exposure di luar kosakata: {exposure!r} "
                         f"({'|'.join(EXPOSURE)})")

    auto_val = entry.get("automatable")
    if auto_val is None:
        vector = entry.get("cvss_vector")
        if vector is not None:
            auto_val = ("yes" if parse_cvss_automatable(str(vector))
                        else "no")
            auto_src = "derived:cvss"
        else:
            auto_val = defaults.get("automatable")
            auto_src = "default"
            if auto_val is None:
                raise ValueError("automatable wajib: flag/per-entri, "
                                 "cvss_vector utk derivasi, atau "
                                 "--default-automatable")
    else:
        auto_val = _norm_automatable(auto_val)
        auto_src = "explicit"

    safety = entry.get("safety")
    if safety is None:
        safety = defaults.get("safety")
        safety_src = "default"
        if safety is None:
            raise ValueError("safety wajib: flag/per-entri "
                             "atau --default-safety")
    else:
        safety = str(safety).strip().lower()
        safety_src = "explicit"
    if safety not in SAFETY:
        raise ValueError(f"safety di luar kosakata: {safety!r} "
                         f"({'|'.join(SAFETY)})")

    mission = entry.get("mission")
    if mission is None:
        mission = defaults.get("mission")
        mission_src = "default"
        if mission is None:
            raise ValueError("mission wajib: flag/per-entri "
                             "atau --default-mission")
    else:
        mission = str(mission).strip().lower()
        mission_src = "explicit"
    if mission not in MISSION:
        raise ValueError(f"mission di luar kosakata: {mission!r} "
                         f"({'|'.join(MISSION)})")

    human = human_impact(safety, mission)
    outcome = ssvc_outcome(exploit, exposure, auto_val, human)
    dec, label, sla = cisa_decision(outcome)
    row = {
        "id": ref,
        "decision": dec,
        "decision_label": label,
        "ssvc_outcome": outcome,
        "sla_default": sla,
        "human_impact": human,
        "decision_points": {
            "exploitation": {"value": exploit, "source": exploit_src},
            "system_exposure": {"value": exposure, "source": exposure_src},
            "automatable": {"value": auto_val, "source": auto_src},
            "safety_impact": {"value": safety, "source": safety_src},
            "mission_impact": {"value": mission, "source": mission_src},
        },
        "formula": "human_impact=tabel(safety x mission); "
                   "outcome=tabel deployer SSVC v2.0(exploitation x "
                   "exposure x automatable x human); nama=map CISA "
                   "Guide; SLA=default heuristik skill sumber",
    }
    if entry.get("cve"):
        row["cve"] = str(entry["cve"]).strip().upper()
    if entry.get("cvss_vector") is not None:
        row["cvss_vector"] = str(entry["cvss_vector"])
    if entry.get("epss") is not None:
        row["epss"] = entry["epss"]
    if entry.get("title") is not None:
        row["title"] = str(entry["title"])
    return row


def assess(entries: list, kev: "set[str] | None",
           epss_map: "dict[str, float] | None", threshold: float,
           defaults: dict) -> dict:
    """Nilai semua entri; entri cacat masuk errors (fail-closed per
    entri), sisanya dinilai dan diurut severity."""
    ranked: list[dict] = []
    errors: list[str] = []
    for idx, rec in enumerate(entries):
        if not isinstance(rec, dict):
            errors.append(f"#index-{idx}: record bukan objek")
            continue
        try:
            ranked.append(resolve_points(rec, defaults, kev, epss_map,
                                         threshold))
        except ValueError as exc:
            ref = str(rec.get("id") or f"#index-{idx}")
            errors.append(f"{ref}: {exc}")
    order = {name: i for i, name in enumerate(CISA_ORDER)}
    ranked.sort(key=lambda r: (-order[r["decision"]], r["id"]))
    by_decision = {name: 0 for name in CISA_ORDER}
    sources: dict[str, int] = {}
    for r in ranked:
        by_decision[r["decision"]] += 1
        for dp in r["decision_points"].values():
            sources[dp["source"]] = sources.get(dp["source"], 0) + 1
    summary = {
        "total": len(ranked),
        "by_decision": by_decision,
        "decision_point_sources": dict(sorted(sources.items())),
        "errors": len(errors),
    }
    return {"ranked": ranked, "summary": summary, "errors": errors}


def _read_json(path: Path, what: str) -> object:
    if not path.exists():
        raise ValueError(f"{what} tidak ada: {path}")
    raw = path.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise ValueError(f"{what} terlalu besar (> {MAX_FILE_BYTES} b)")
    try:
        return json.loads(raw.decode("utf-8-sig", errors="replace"))
    except ValueError as exc:
        raise ValueError(f"{what} JSON rusak: {exc}") from exc


def load_kev_set(path: Path) -> set[str]:
    """Katalog CISA KEV offline (known_exploited_vulnerabilities.json)
    -> set CVE id. Struktur salah = ValueError (fail-closed)."""
    data = _read_json(path, "kev-json")
    if not isinstance(data, dict) or not isinstance(
            data.get("vulnerabilities"), list):
        raise ValueError("kev-json bukan katalog CISA KEV "
                         "(tanpa vulnerabilities[])")
    cves: set[str] = set()
    for item in data["vulnerabilities"]:
        if isinstance(item, dict):
            cve = str(item.get("cveID") or "").strip().upper()
            if cve:
                cves.add(cve)
    if not cves:
        raise ValueError("kev-json tidak berisi cveID")
    return cves


def load_epss_map(path: Path) -> dict[str, float]:
    """Ekspor EPSS FIRST offline ({"data":[{"cve","epss"},...]}) ->
    {cve: float}. Baris cacat dilewati (dihitung); struktur salah =
    ValueError."""
    data = _read_json(path, "epss-json")
    if not isinstance(data, dict) or not isinstance(data.get("data"),
                                                   list):
        raise ValueError("epss-json bukan ekspor EPSS FIRST "
                         "(tanpa data[])")
    scores: dict[str, float] = {}
    skipped = 0
    for item in data["data"]:
        if not isinstance(item, dict):
            skipped += 1
            continue
        cve = str(item.get("cve") or "").strip().upper()
        raw = item.get("epss")
        try:
            val = float(raw)
        except (TypeError, ValueError):
            skipped += 1
            continue
        if not cve or not 0.0 <= val <= 1.0:
            skipped += 1
            continue
        scores[cve] = val
    if not scores:
        raise ValueError("epss-json tidak berisi skor EPSS valid")
    return scores


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="ssvc_triage — prioritas kerentanan SSVC v2.0 "
                    "(tabel deployer resmi CERT/CC + kosakata CISA "
                    "Guide; read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True,
                    help="file JSON entri kerentanan (list)")
    ap.add_argument("--kev-json",
                    help="katalog CISA KEV offline "
                         "(known_exploited_vulnerabilities.json)")
    ap.add_argument("--epss-json",
                    help="ekspor EPSS FIRST offline "
                         "({\"data\":[{\"cve\",\"epss\"}]})")
    ap.add_argument("--epss-poc-threshold", type=float, default=0.5,
                    help="ambang EPSS -> poc (default 0.5, heuristik "
                         "skill sumber; pakai epss > ambang)")
    ap.add_argument("--default-exposure", choices=EXPOSURE,
                    help="exposure default utk entri tanpa nilai "
                         "(tercatat sbg 'default')")
    ap.add_argument("--default-safety", choices=SAFETY,
                    help="safety impact default")
    ap.add_argument("--default-mission", choices=MISSION,
                    help="mission impact default")
    ap.add_argument("--default-automatable", choices=AUTOMATABLE,
                    help="automatable default utk entri tanpa nilai/"
                         "cvss_vector")
    ap.add_argument("--fail-on",
                    choices=("act", "attend", "track*", "track", "any"),
                    help="exit 1 bila ada keputusan seberat itu "
                         "(any = act|attend)")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    for name in ("exposure", "safety", "mission", "automatable"):
        if getattr(args, f"default_{name}") is None:
            print(f"[ssvc] gagal: --default-{name} wajib "
                  f"(fail-closed — titik keputusan tidak ditebak)",
                  file=sys.stderr)
            return 2
    defaults = {"exposure": args.default_exposure,
                "safety": args.default_safety,
                "mission": args.default_mission,
                "automatable": args.default_automatable}
    kev: "set[str] | None" = None
    epss_map: "dict[str, float] | None" = None
    try:
        data = _read_json(Path(args.source), "source")
        if args.kev_json:
            kev = load_kev_set(Path(args.kev_json))
        if args.epss_json:
            epss_map = load_epss_map(Path(args.epss_json))
        if not 0.0 <= args.epss_poc_threshold <= 1.0:
            raise ValueError("--epss-poc-threshold di luar 0-1")
    except ValueError as exc:
        print(f"[ssvc] gagal: {exc}", file=sys.stderr)
        return 2
    if isinstance(data, dict):
        data = data.get("vulnerabilities") or data.get("entries")
    if not isinstance(data, list):
        print("[ssvc] JSON harus list atau objek berisi "
              "'vulnerabilities'/'entries'", file=sys.stderr)
        return 2
    result = assess(data, kev, epss_map, args.epss_poc_threshold,
                    defaults)
    out = {
        "schema": SCHEMA,
        "source": args.source,
        "model": "SSVC v2.0 deployer Patch Application Priority "
                 "(tabel resmi CERT/CC, CMU SEI) + map kosakata CISA "
                 "Guide",
        "kev_used": kev is not None,
        "epss_used": epss_map is not None,
        "epss_poc_threshold": args.epss_poc_threshold,
        "defaults": defaults,
        "summary": result["summary"],
        "vulnerabilities": result["ranked"],
        "errors": result["errors"],
        "note": "sumber tiap titik keputusan tercatat di "
                "decision_points[*].source; SLA = default heuristik "
                "skill sumber, bukan kebijakan resmi.",
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = result["summary"]
    dist = ", ".join(f"{k}={s['by_decision'][k]}" for k in CISA_ORDER
                     if s["by_decision"][k])
    print(f"[ssvc] {s['total']} entri dinilai ({dist or 'kosong'}); "
          f"error={s['errors']}")
    for row in result["ranked"][:10]:
        dp = row["decision_points"]
        print(f"  [{row['decision']:7}] {row['id']} "
              f"(exploit={dp['exploitation']['value']}, "
              f"exposure={dp['system_exposure']['value']}, "
              f"auto={dp['automatable']['value']}, "
              f"human={row['human_impact']}, SLA={row['sla_default']})")
    if result["errors"]:
        for e in result["errors"][:10]:
            print(f"  [error   ] {e}")
    if args.fail_on:
        if args.fail_on == "any":
            hit = ("act", "attend")
        else:
            idx = CISA_ORDER.index(args.fail_on)
            hit = CISA_ORDER[idx:]
        if any(r["decision"] in hit for r in result["ranked"]):
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

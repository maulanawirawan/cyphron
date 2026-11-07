"""[TRIAGE: gate] brocards_triage — gerbang 7 brocards untuk triase laporan kerentanan.

Port konsep dari antrean SKILL-PORT-QUEUE #0095 (trailofbits/skills plugin
'vulnerability-triage-brocards'; 7 brocards diadaptasi ToB dari William
Woodruff, "Brocards for vulnerability triage", vulnbrocards.com 2026).
Dibangun FROM SCRATCH — mekanisme evaluasi field terstruktur, tangga
kapabilitas, dan seluruh pola ditulis sendiri; tidak ada kode sumber dari
repo tersebut. Lisensi cyphron: PolyForm NC.

Kenapa cyphron butuh ini: pipeline cyphron menghasilkan lead temuan yang
lalu dilaporkan; alat verifikasi (verify_gate, novelty_check,
triage_advisor) menilai bukti & duplikat — tapi TIDAK ADA gerbang yang
menolak laporan dari SISI logika triase (threat model absen, eksploit
"langit", perilaku terdokumentasi, dsb.) sebelum laporan disusun.

Input  : satu file JSON laporan terstruktur (lihat REPORT_FIELDS di bawah;
         field absen BUKAN otomatis dismiss — fail-closed: absen = NEEDS-
         MORE-INFO, kecuali bukti negatif eksplisit).
Output : verdict per brocard (PASS / DISMISS / NEEDS-MORE-INFO) + overall
         (DISMISS > NEEDS-MORE-INFO > ACCEPT) + next step. NOL jaringan,
         read-only.

7 brocards (urutan evaluasi = urutan spesifikasi):
  1. No vulnerability without a threat model — attacker/capability/action/
     impact wajib lengkap dan non-kosong.
  2. No exploit from the heavens — kapabilitas yang DIBUTUHKAN untuk
     memicu >= kapabilitas yang DIDAPAT dari dampak = redundan (DISMISS).
     Perbandingan via tangga kapabilitas (LADDER); token tak dikenal =
     NEEDS-MORE-INFO (tidak menebak).
  3. No vulnerability outside of usage — reachable=false / dead_code=true
     = DISMISS; "unknown"/absen = NEEDS-MORE-INFO.
  4. No vulnerability from standard behavior — perilaku diizinkan/diwajib-
     kan spesifikasi = DISMISS, KECUALI stricter_than_spec (implementasi
     memilih postur lebih ketat lalu postur ketat itulah yang gagal).
  5. No vulnerability from documented behavior — terdokumentasi eksplisit
     = DISMISS (nuansa downstream misuse dicatat di rationale).
  6. No cure worse than the disease — fix_cost=high pada severity
     low/medium = DISMISS (usulan downgrade); severity high/critical =
     PASS.
  7. Report is neither necessary nor sufficient — CVE/CVSS TANPA bukti
     teknis (poc/request/response) = DISMISS "metadata bukan bukti";
     bukti teknis tanpa metadata = PASS; dua-duanya hampa = NEEDS-MORE-
     INFO.

Exit : 0 ACCEPT; 1 DISMISS; 3 NEEDS-MORE-INFO; 2 input/JSON error.
Default berhenti di DISMISS pertama; --full mengevaluasi ketujuhnya.

Pemakaian:
  python tools/brocards_triage.py --report report.json
  python tools/brocards_triage.py --report report.json --full --json hasil.json
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "cyphron.brocards-triage/1"

# ---------------------------------------------------------------- tangga
# tangga kapabilitas (indeks = kekuatan). Token di luar daftar = tak
# dikenal -> brocard 2 = NEEDS-MORE-INFO (fail-closed, tidak menebak).
LADDER: dict[str, int] = {
    "anon": 0, "anonymous": 0, "unauthenticated": 0, "no-auth": 0,
    "user": 1, "auth-user": 1, "authenticated": 1, "regular-user": 1,
    "privileged-user": 2, "power-user": 2, "tenant-admin": 2,
    "app-admin": 3, "admin": 3, "developer": 3, "maintainer": 3,
    "local-user": 4, "local-access": 4, "local-admin": 4, "container": 4,
    "root": 5, "system": 5, "kernel": 5, "cluster-user": 5,
    "cloud-admin": 6, "cluster-admin": 6, "domain-admin": 6,
    "organization-admin": 6,
}
SEVERITY_W = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
FIXCOST_W = {"low": 0, "medium": 1, "high": 2}
TM_FIELDS = ("attacker", "capability", "action", "impact")
EVIDENCE_FIELDS = ("poc", "request", "response")

PASS, DISMISS, NEEDS = "PASS", "DISMISS", "NEEDS-MORE-INFO"

NAMES = {
    1: "No Vulnerability Without a Threat Model",
    2: "No Exploit from the Heavens",
    3: "No Vulnerability Outside of Usage",
    4: "No Vulnerability from Standard Behavior",
    5: "No Vulnerability from Documented Behavior",
    6: "No Cure Worse Than the Disease",
    7: "The Report Is Neither Necessary nor Sufficient",
}


class InputError(ValueError):
    """Input laporan tidak valid (bukan JSON / bukan objek)."""


def _s(x: object) -> str:
    return x.strip() if isinstance(x, str) else ""


def _tri(value: object) -> bool | None:
    """Normalisasi tri-state: True/False/None (unknown & absen = None)."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("true", "yes"):
            return True
        if v in ("false", "no"):
            return False
    return None


def brocard_1(rep: dict) -> tuple[str, str]:
    """Threat model wajib lengkap: attacker, capability, action, impact."""
    tm = rep.get("threat_model")
    if not isinstance(tm, dict):
        return NEEDS, ("threat_model tidak ada/lain objek — laporan tanpa "
                       "threat model koheren tidak bisa diterima (butuh "
                       + ", ".join(TM_FIELDS) + ")")
    missing = [k for k in TM_FIELDS if not _s(tm.get(k))]
    if missing:
        return NEEDS, "threat_model belum lengkap: " + ", ".join(missing)
    return PASS, ("threat model koheren: " + _s(tm["capability"]) + " -> "
                  + _s(tm["action"]) + " -> " + _s(tm["impact"]))


def brocard_2(rep: dict) -> tuple[str, str]:
    """Kapabilitas prasyarat >= dampak = eksploit dari langit (redundan)."""
    caps_raw = rep.get("attacker_capabilities")
    granted_raw = rep.get("impact_capability")
    if not isinstance(caps_raw, list) or not caps_raw or not _s(granted_raw):
        return NEEDS, ("butuh attacker_capabilities (list) + "
                       "impact_capability untuk membandingkan tangga")
    if _s(granted_raw).lower() not in LADDER:
        return NEEDS, f"impact_capability tak dikenal: {granted_raw!r}"
    granted = LADDER[_s(granted_raw).lower()]
    unknown = [c for c in caps_raw if _s(c).lower() not in LADDER]
    if unknown:
        return NEEDS, "kapabilitas prasyarat tak dikenal: " + ", ".join(map(str, unknown))
    required = max(LADDER[_s(c).lower()] for c in caps_raw)
    if required >= granted:
        return DISMISS, (f"prasyarat ({required}) >= dampak ({granted}) di "
                         f"tangga kapabilitas — penyerang sudah memegang "
                         f"kekuatan yang akan diberikan (redundan)")
    return PASS, f"prasyarat ({required}) < dampak ({granted}) — ada kenaikan nyata"


def brocard_3(rep: dict) -> tuple[str, str]:
    """Jalur tidak terjangkau di pemakaian nyata = bukan vuln."""
    if _tri(rep.get("dead_code")) is True:
        return DISMISS, "kode ditandai dead_code — tidak terjangkau pemakaian nyata"
    r = _tri(rep.get("reachable"))
    if r is True:
        return PASS, "jalur reachable di pemakaian nyata"
    if r is False:
        return DISMISS, "reachable=false — jalur tidak dieksekusi pemakai nyata"
    return NEEDS, "reachable tidak diketahui — bukti pemanggil nyata dibutuhkan"


def brocard_4(rep: dict) -> tuple[str, str]:
    """Perilaku standar = sasarannya spesifikasi, bukan implementasi."""
    stricter = _tri(rep.get("stricter_than_spec")) is True
    spec = _s(rep.get("spec_behavior")).lower()
    if spec in ("spec_permitted", "spec_requires"):
        if stricter:
            return PASS, ("implementasi memilih postur LEBIH KETAT dari "
                          "spesifikasi dan postur ketat itu yang gagal — "
                          "vuln implementasi, bukan spesifikasi")
        return DISMISS, (f"spesifikasi {'mewajibkan' if spec == 'spec_requires' else 'mengizinkan'}"
                         " perilaku ini — sasarannya standar, bukan kode")
    if spec == "implementation":
        return PASS, "perilaku spesifik implementasi (di luar yang diatur spesifikasi)"
    return NEEDS, "spec_behavior tidak diketahui (butuh: implementation|spec_permitted|spec_requires)"


def brocard_5(rep: dict) -> tuple[str, str]:
    """Perilaku terdokumentasi (apalagi dengan peringatan) = bukan vuln."""
    doc = _tri(rep.get("documented"))
    if doc is True:
        warns = _tri(rep.get("doc_warns"))
        nuance = ("dokumentasi menyertakan peringatan keamanan; " if warns
                  else "tanpa peringatan eksplisit di dok; ")
        return DISMISS, nuance + ("perilaku terdokumentasi — keluhan berlaku "
                                  "bagi pemakai downstream yang melanggar "
                                  "panduan, bukan komponen ini")
    if doc is False:
        return PASS, "perilaku tidak terdokumentasi"
    return NEEDS, "status dokumentasi perilaku tidak diketahui"


def brocard_6(rep: dict) -> tuple[str, str]:
    """Biaya remediasi melebihi dampak = jangan fix (usulkan downgrade)."""
    sev = _s(rep.get("severity")).lower()
    cost = _s(rep.get("fix_cost")).lower()
    if sev not in SEVERITY_W or cost not in FIXCOST_W:
        return NEEDS, "butuh severity (info..critical) + fix_cost (low|medium|high)"
    if cost == "high" and SEVERITY_W[sev] <= SEVERITY_W["medium"]:
        return DISMISS, (f"fix berbiaya high pada severity {sev} — remediasi "
                         f"lebih merusak daripada vuln; pertimbangkan "
                         f"downgrade/deprioritisasi")
    return PASS, f"severity {sev} dengan fix_cost {cost} — remediasi proporsional"


def brocard_7(rep: dict) -> tuple[str, str]:
    """CVE/CVSS bukan bukti; bukti teknis yang menentukan."""
    evidence = [k for k in EVIDENCE_FIELDS if _s(rep.get(k))]
    cve = _s(rep.get("cve_id"))
    cvss = rep.get("cvss")
    has_meta = bool(cve) or isinstance(cvss, (int, float))
    if evidence and has_meta:
        return PASS, f"bukti teknis ({', '.join(evidence)}) + metadata {cve or 'CVSS'}"
    if evidence:
        return PASS, "dinilai dari bukti teknis: " + ", ".join(evidence)
    if has_meta:
        return DISMISS, ("CVE/CVSS ada TANPA bukti teknis (poc/request/"
                         "response kosong) — metadata bukan bukti; "
                         "description saja tidak memadai")
    return NEEDS, "tidak ada bukti teknis maupun metadata — tidak bisa dinilai"


BROCARDS = (brocard_1, brocard_2, brocard_3, brocard_4, brocard_5,
            brocard_6, brocard_7)


def triage(report: dict, full: bool = False) -> dict:
    """Evaluasi 7 brocards — default stop di DISMISS pertama (spesifikasi)."""
    if not isinstance(report, dict):
        raise InputError("laporan harus objek JSON")
    results: list[dict] = []
    overall = "ACCEPT"
    for i, fn in enumerate(BROCARDS, 1):
        verdict, why = fn(report)
        results.append({"n": i, "name": NAMES[i], "verdict": verdict,
                        "rationale": why})
        if verdict == DISMISS:
            overall = DISMISS
            if not full:
                break
        elif verdict == NEEDS and overall != DISMISS:
            overall = NEEDS
    next_step = {
        DISMISS: "tutup: dokumentasikan nomor brocard + alasan (bisa minta "
                 "klarifikasi bila DISMISS berasal dari NEEDS yang dipaksakan)",
        NEEDS: "minta info spesifik yang disebut rationale sebelum lanjut",
        "ACCEPT": "lanjut ke pengembangan PoC / verifikasi exploitability",
    }[overall]
    return {
        "schema": SCHEMA,
        "report_id": _s(report.get("id")) or _s(report.get("title")) or "(tanpa-id)",
        "brocards": results,
        "overall": overall,
        "next_step": next_step,
    }


def load_report(path: str) -> dict:
    """Baca + validasi file laporan — fail-closed (bukan objek = error)."""
    p = Path(path)
    if not p.is_file():
        raise InputError(f"file laporan tidak ada: {p}")
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        raise InputError(f"JSON laporan tidak valid: {e}") from e
    if not isinstance(data, dict):
        raise InputError("laporan harus objek JSON")
    return data


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        description="Gerbang 7 brocards untuk triase laporan kerentanan "
                    "(read-only, nol jaringan).")
    ap.add_argument("--report", required=True, help="file JSON laporan")
    ap.add_argument("--full", action="store_true",
                    help="evaluasi 7 brocards meski sudah ada DISMISS")
    ap.add_argument("--json", metavar="OUT",
                    help="tulis hasil triase ke file JSON")
    args = ap.parse_args(argv)

    try:
        result = triage(load_report(args.report), full=args.full)
    except InputError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 2

    for b in result["brocards"]:
        print(f"[{b['verdict']:>15}] #{b['n']} {b['name']}: {b['rationale']}")
    print(f"OVERALL: {result['overall']} — {result['next_step']}")

    if args.json:
        Path(args.json).write_text(
            json.dumps(result, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8")
    return {"ACCEPT": 0, "DISMISS": 1, "NEEDS-MORE-INFO": 3}[result["overall"]]


if __name__ == "__main__":
    sys.exit(main())

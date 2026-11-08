r"""[GATE: read-only] submission_gate — gerbang 7-pertanyaan pra-
submission bug bounty: satu temuan dinilai terhadap disiplin laporan
sebelum ditulis/dikirim. Satu jawaban negatif eksplisit = KILL; jawaban
yang datanya absen = NEEDS-MORE-INFO (fail-closed — kegelapan tidak
pernah dianggap lolos).

Port konsep dari awarexone/Agentic-Bug-Hunter 'triage-validation' skill
(7-Question Gate + 4 pre-submission gates + never-submit list) —
atribusi konsep, lisensi sumber MIT. Dibangun FROM SCRATCH: pertanyaan
dioperasikan jadi cek deterministik atas (a) temuan findings.json,
(b) profil program --program JSON, (c) keluaran opsional tool secai
lain sebagai bukti pendukung. Skill sumber = checklist naratif utk
manusia; tool ini versi yang bisa diaudit dan dijalankan ulang.

Ranah tetangga EKSPLISIT (tidak diduplikasi):
  - verify_gate      = klaim STATUS KERJA butuh bukti segar
  - brocards_triage  = logika triase laporan (threat model, "langit",
                       perilaku terdokumentasi) — bila --brocards
                       diberikan, verdictnya DIPAKAI sebagai jawaban
                       pertanyaan terkait, bukan dinilai ulang
  - triage_advisor   = loop belajar prioritas per kelas
  - scope_gate       = pencocokan scope (W1, mini-program ABH) — bila
                       --scope-verdict diberikan, jawaban Q3 memakainya
  - ssvc_triage / owasp_risk_rating = PRIORITAS — gate ini bukan
                       penskoran; ia menanyakan kelayakan SUBMISI

Tujuh pertanyaan (sumber: skill triage-validation):
  Q1 executable-now  : temuan membawa request/poc yang bisa diulang
                       langkah demi langkah? (tanpa bukti = NEEDS-
                       EVIDENCE; bukti klaim "tidak bisa" = KILL)
  Q2 impact-listed   : kelas temuan ada di daftar impact yang diterima
                       program? (di daftar exclusion = KILL)
  Q3 in-scope        : aset terdampak in-scope? (via --scope-verdict
                       atau daftar scope di profil; absen = NEEDS-INFO)
  Q4 no-priv-required: butuh akses terprivilege yang penyerang nyata
                       tak mungkin punya? (profile.requires_admin /
                       finding.requires_privileged_access eksplisit
                       true = KILL; absen = NEEDS-INFO)
  Q5 not-documented  : perilaku sudah dinyatakan intended/terdokumen-
                       si? (profil.disclosed + verdict --brocards)
  Q6 not-duplicate   : laporan duplikat/disclosed sebelumnya? (profil.
                       duplicates cocok pola endpoint/kelas = KILL)
  Q7 impact-first    : severity temuan selaras konteks (severity
                       critical tanpa impact narrative = NEEDS-INFO)

Input -> output: --finding FILE (satu temuan / array / {findings:[...]};
satu temuan dipilih via --index) + --program FILE (JSON profil:
{impact_list:{critical:[],high:[]}, exclusions:[], scope:{...}|null,
requires_admin:bool|null, disclosed:[], duplicates:[], known_intended:
[]}) + --scope-verdict / --brocards opsional. Output: jawaban per
pertanyaan (PASS/KILL/NEEDS-EVIDENCE/NEEDS-INFO) + overall (SUBMIT /
DO-NOT-SUBMIT bila ada KILL / NEEDS-MORE-INFO) + next-step per
NEEDS; exit 1 bila DO-NOT-SUBMIT atau NEEDS, 0 bila SUBMIT, 2 bila
input rusak / profil tak ada (fail-closed — tanpa data program gate
menolak menilai).

Stdlib json/argparse/re. Nol jaringan.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "submission_gate/v1"

KILL, PASS = "KILL", "PASS"
NEEDS_EV, NEEDS_IN = "NEEDS-EVIDENCE", "NEEDS-INFO"
QIDS = ("q1-executable-now", "q2-impact-listed", "q3-in-scope",
        "q4-no-priv-required", "q5-not-documented", "q6-not-duplicate",
        "q7-impact-first")


def _load(path: Path, what: str) -> dict:
    if not path.exists():
        raise ValueError(f"{what} tidak ada: {path}")
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"{what} tidak terurai: {exc}")


def _pick_finding(data: dict | list, index: int) -> dict:
    if isinstance(data, dict):
        if "findings" in data:
            data = data["findings"]
        elif any(k in data for k in ("tool", "check", "title")):
            data = [data]  # satu temuan polos juga sah
        else:
            raise ValueError("objek tanpa kunci 'findings' dan bukan "
                             "temuan — bentuk tidak dikenal (fail-closed)")
    if not isinstance(data, list) or not data:
        raise ValueError("temuan kosong / bukan array")
    try:
        f = data[index]
    except IndexError:
        raise ValueError(f"--index {index} di luar jangkauan "
                         f"({len(data)} temuan)")
    if not isinstance(f, dict):
        raise ValueError(f"temuan indeks {index} bukan objek")
    return f


def _host(target: str) -> str:
    from urllib.parse import urlsplit
    try:
        h = urlsplit(target).hostname
    except ValueError:
        h = None
    return (h or target).lower()


def _wildcard_hit(patterns: "list[str]", host: str) -> "str | None":
    """Pencocokan scope: wildcard '*' = satu label host; pola polos =
    sama-dengan/substring. Kembalikan pola yang kena."""
    for pat in patterns:
        pat_l = pat.lower().strip()
        if "*" in pat_l:
            rx = "^" + ".*".join(re.escape(x)
                                 for x in pat_l.split("*")) + "$"
            # '*.' di depan juga menerima apex (konvensi umum scope)
            if re.match(rx, host) or re.match(
                    rx.replace("^[.*]", "^", 1)
                    if rx.startswith("^[.*]") else rx, host):
                return pat
            if pat_l.startswith("*.") and (host == pat_l[2:]
                                           or host.endswith(
                                               "." + pat_l[2:])):
                return pat
        elif pat_l == host or pat_l in host:
            return pat
    return None


def _text_hit(patterns: "list[str]", *texts: str) -> "str | None":
    """Pola substring/kata utk pencocokan endpoint/kelas — kembalikan
    pola yang kena (deterministik, case-insensitive)."""
    blob = " ".join(t.lower() for t in texts if t)
    for pat in patterns:
        if pat.lower() in blob:
            return pat
    return None


def evaluate(f: dict, program: dict, scope_verdict: "dict | None",
             brocards: "dict | None") -> dict:
    answers: "list[dict]" = []

    def add(qid, verdict, reason, next_step=""):
        answers.append({"question": qid, "verdict": verdict,
                        "reason": reason, "next_step": next_step})

    # Q1 — bukti request/poc yang bisa diulang
    has_evidence = any(
        (f.get(k) or "") for k in ("request", "response", "poc"))
    if has_evidence and f.get("status") == "confirmed":
        add(QIDS[0], PASS, "temuan confirmed dgn request/poc "
            "copy-paste-ready")
    elif has_evidence:
        add(QIDS[0], NEEDS_EV,
            "ada bukti tapi status 'unconfirmed' — reproduksi dulu "
            "sampai confirmed (L3)", "jalankan probe + verify_gate")
    else:
        add(QIDS[0], NEEDS_EV,
            "tanpa request/poc — tidak bisa ditulis langkah demi "
            "langkah", "rekam request + response nyata dahulu")

    # Q2 — impact list program
    impact = program.get("impact_list") or {}
    exclusions = program.get("exclusions") or []
    fclass = (f.get("check") or f.get("title") or "").lower()
    hit_excl = _text_hit(exclusions, fclass)
    hit_impact = None
    for sev, items in impact.items():
        hit_impact = _text_hit(items, fclass) or hit_impact
    if hit_excl:
        add(QIDS[1], KILL, f"kelas ada di daftar exclusion program "
            f"(pola '{hit_excl}')", "matikan temuan, cari kelas lain")
    elif hit_impact:
        add(QIDS[1], PASS, f"kelas terpetakan ke daftar impact "
            f"(pola '{hit_impact}')")
    else:
        add(QIDS[1], NEEDS_IN, "kelas tidak terpetakan ke daftar impact "
            "mana pun — perlu pemetaan manual ke tipologi program",
            "cocokkan kelas ke halaman program / tanyakan triager")

    # Q3 — scope (via scope_gate bila ada)
    sv = scope_verdict or program.get("scope_verdict")
    target = f.get("target_url") or f.get("file_path") or ""
    if sv is not None:
        verdicts = sv.get("verdicts") or sv.get("results") or []
        row = next((r for r in verdicts
                    if str(r.get("asset", "")) and
                    str(r.get("asset")) in str(target)), None)
        if row is None:
            add(QIDS[2], NEEDS_IN, "scope-verdict diberikan tapi aset "
                "tidak ditemukan di dalamnya",
                "jalankan scope_gate utk aset ini")
        elif str(row.get("verdict", "")).lower() in ("out-of-scope",
                                                    "out_of_scope"):
            add(QIDS[2], KILL, "aset out-of-scope (dari scope_gate)",
                "hentikan — satu request di luar scope bisa melanggar "
                "aturan program")
        else:
            add(QIDS[2], PASS, "aset in-scope (dari scope_gate)")
    elif program.get("scope"):
        in_scope = _wildcard_hit(list(program["scope"]), _host(target))
        if in_scope:
            add(QIDS[2], PASS, f"aset cocok entri scope profil "
                f"('{in_scope}')")
        else:
            add(QIDS[2], NEEDS_IN, "aset tidak cocok entri scope profil "
                "mana pun — profil mungkin tak lengkap",
                "jalankan scope_gate utk kepastian wildcard")
    else:
        add(QIDS[2], NEEDS_IN, "tidak ada data scope (profil tanpa "
            "'scope' dan tanpa --scope-verdict)",
            "jalankan scope_gate dgn kebijakan program")

    # Q4 — akses terprivilege
    priv = program.get("requires_admin")
    if priv is None:
        priv = f.get("requires_privileged_access")
    if priv is True:
        add(QIDS[3], KILL,
            "butuh akses admin/terprivilege — di mayoritas program ini "
            "centralization risk", "matikan kecuali program menerima "
            "kelas ini")
    elif priv is False:
        add(QIDS[3], PASS, "tidak butuh akses terprivilege (dinyatakan "
            "eksplisit)")
    else:
        add(QIDS[3], NEEDS_IN, "kebutuhan akses tidak dinyatakan "
            "(profil.requires_admin dan temuan sama-sama absen)",
            "nyatakan prasyarat akses temuan")

    # Q5 — sudah didokumentasikan / intended
    intended = _text_hit(list(program.get("known_intended") or []),
                         fclass)
    broc = (brocards or {}).get("overall") or (
        (brocards or {}).get("summary") or {}).get("overall")
    if intended:
        add(QIDS[4], KILL, f"perilaku terdokumentasi sbg intended "
            f"(pola '{intended}')", "matikan — design decision")
    elif broc and str(broc).upper().startswith("DISMISS"):
        add(QIDS[4], KILL, f"brocards_triage menilai DISMISS "
            f"({broc})", "ikuti verdict brocards — jangan dinilai ulang")
    elif broc and "NEEDS" in str(broc).upper():
        add(QIDS[4], NEEDS_IN, f"brocards_triage minta info tambahan "
            f"({broc})", "lengkapi konteks yang diminta brocards")
    else:
        add(QIDS[4], PASS, "tidak ada indikasi perilaku intended / "
            "verdict brocards positif atau absen")

    # Q6 — duplikat / sudah didisclose
    dup = _text_hit(list(program.get("duplicates") or []),
                    f.get("target_url") or "", fclass)
    disc = _text_hit(list(program.get("disclosed") or []),
                     f.get("target_url") or "", fclass)
    if dup:
        add(QIDS[5], KILL, f"cocok daftar duplikat (pola '{dup}')",
            "cari variasi/kelas lain pada endpoint sama")
    elif disc:
        add(QIDS[5], KILL, f"sudah disclosed sebelumnya (pola '{disc}')",
            "matikan kecuali ada dampak baru yang jelas")
    else:
        add(QIDS[5], PASS, "tidak ada indikasi duplikat/disclosed pada "
            "profil program")

    # Q7 — severity selaras dampak
    sev = (f.get("severity") or "").lower()
    if sev in ("critical", "high") and not (f.get("poc") or
                                            f.get("response")):
        add(QIDS[6], NEEDS_IN, "severity tinggi tanpa bukti dampak "
            "konkret (poc/response kosong)",
            "tambahkan bukti dampak nyata sebelum klaim severity")
    elif not sev:
        add(QIDS[6], NEEDS_IN, "temuan tanpa severity",
            "tetapkan severity via ssvc_triage/owasp_risk_rating")
    else:
        add(QIDS[6], PASS, f"severity '{sev}' dibawa temuan dgn bukti "
            "yang cukup")

    kills = [a for a in answers if a["verdict"] == KILL]
    needs = [a for a in answers if a["verdict"].startswith("NEEDS")]
    overall = ("DO-NOT-SUBMIT" if kills else
               "NEEDS-MORE-INFO" if needs else "SUBMIT")
    return {"answers": answers, "overall": overall,
            "kills": [a["question"] for a in kills],
            "needs": [a["question"] for a in needs]}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--finding", type=Path, required=True,
                    help="findings.json (satu temuan dipilih --index)")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--program", type=Path, required=True,
                    help="profil program JSON (impact_list, exclusions, "
                         "scope, disclosed, duplicates, requires_admin)")
    ap.add_argument("--scope-verdict", type=Path, default=None,
                    help="opsional: keluaran scope_gate")
    ap.add_argument("--brocards", type=Path, default=None,
                    help="opsional: keluaran brocards_triage")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    try:
        f = _pick_finding(_load(args.finding, "finding"), args.index)
        program = _load(args.program, "program")
        sv = _load(args.scope_verdict, "scope-verdict") \
            if args.scope_verdict else None
        bc = _load(args.brocards, "brocards") if args.brocards else None
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2
    if not isinstance(program, dict):
        print(json.dumps({"schema": SCHEMA,
                          "error": "profil program bukan objek"}),
              file=sys.stderr)
        return 2

    result = evaluate(f, program, sv, bc)
    notes = [
        "satu KILL = jangan submit (rasio validitas lebih mahal dari "
        "satu laporan); NEEDS = lengkapi dulu, bukan lolos",
        "tool ini bukan penskoran (prioritas = ssvc_triage / "
        "owasp_risk_rating) dan bukan penilai bukti teknis "
        "(verify_gate) — ia gerbang disiplin submission",
        "keputusan akhir selalu manusia; tool mencegah laporan lemah "
        "terkirim tanpa sadar",
    ]
    report = {
        "schema": SCHEMA,
        "finding": {"tool": f.get("tool"), "check": f.get("check"),
                    "severity": f.get("severity"),
                    "title": (f.get("title") or "")[:140]},
        "overall": result["overall"],
        "kills": result["kills"],
        "needs": result["needs"],
        "answers": result["answers"],
        "notes": notes,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if result["overall"] == "SUBMIT" else 1


if __name__ == "__main__":
    raise SystemExit(main())

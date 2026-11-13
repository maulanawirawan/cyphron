"""[ABH-W3: report platform] submission_report — draf laporan submission
per-platform (HackerOne / Bugcrowd / Intigriti) dari findings.json +
satu temuan terpilih. MAKSIMAL DRAF L1/L2 — keluaran teks yang direview
manusia, BUKAN submission-ready, dan TIDAK ada pengiriman apa pun (nol
jaringan).

RANAH EKSPLISIT (mini-program ABH-PORT — anti-tabrakan):
  - report_pack.py / report_pdf.py = pengemasan bukti + render laporan
    secai — TIDAK disentuh; tool ini hanya MENGAHASILKAN draf teks.
  - submission_gate.py = gerbang 7-pertanyaan pra-submission — TIDAK
    disentuh; jalankan gate DULU, tool ini menyusun draf temuan yang
    sudah lolos disiplin.
  - tool ini (W3) = draf per-platform utk temuan terpilih.

Fail-closed jujur (inti port ini):
  - Setiap klaim dampak WAJIB membawa evidence_ref dari temuan (field
    'evidence_ref', atau rujukan file#index:field utk bukti
    request/response/poc). Tanpa bukti: seksi Impact TIDAK menulis
    klaim — hanya penanda NEEDS-EVIDENCE.
  - status 'confirmed' + >=1 bukti  -> draf L2 (exit 0)
  - lainnya (unconfirmed / false-positive / tanpa bukti) -> draf L1
    (exit 1) tanpa bahasa klaim terkonfirmasi + penanda perbaikan.
  - Draf TIDAK PERNAH menyatakan submission-ready — itu klaim L3+,
    di luar ranah draf; keputusan submit selalu manusia.

Input -> output: --findings FILE (array / {findings:[...]} / satu objek;
temuan dipilih --index) + --platform {hackerone,bugcrowd,intigriti}.
Output: markdown (stdout atau --out). Exit 0 draf L2; 1 draf L1/NEEDS;
2 input rusak (file tak ada, JSON tak terurai, --index di luar
jangkauan, --platform tidak dikenal).

Pemakaian:
  python tools/submission_report.py --findings findings.json --index 0 \
      --platform hackerone
  python tools/submission_report.py --findings f.json --platform \
      bugcrowd --out draf-bugcrowd.md
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCHEMA = "submission_report/v1"

PLATFORMS = ("hackerone", "bugcrowd", "intigriti")
EVIDENCE_FIELDS = ("request", "response", "poc")
IMPACT_KEYS = ("impact", "impact_statement")
FIX_KEYS = ("recommended_fix", "fix", "remediation")

PLACEHOLDER_IMPACT = "[ISI MANUAL: dampak satu kalimat — apa yang didapat penyerang]"
PLACEHOLDER_FIX = "[ISI MANUAL: perbaikan 1-2 kalimat, spesifik]"
PLACEHOLDER_SETUP = "[ISI MANUAL: akun uji A/B, prasyarat akses, tanggal uji]"


class InputError(ValueError):
    """Input rusak/invalid — dipetakan ke exit 2 (fail-closed)."""


def load_findings(path: Path) -> "list[dict] | dict":
    if not path.exists():
        raise InputError(f"file findings tidak ada: {path}")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise InputError(f"file findings tidak terurai: {exc}")
    return data


def pick_finding(data: "list[dict] | dict", index: int) -> dict:
    """Pilih satu temuan: array / {findings:[...]} / satu objek temuan."""
    if isinstance(data, dict):
        if "findings" in data:
            data = data["findings"]
        elif any(k in data for k in ("tool", "check", "title")):
            data = [data]
        else:
            raise InputError(
                "objek tanpa kunci 'findings' dan bukan temuan — bentuk "
                "tidak dikenal (fail-closed)")
    if not isinstance(data, list) or not data:
        raise InputError("temuan kosong / bukan array")
    if index < 0 or index >= len(data):
        raise InputError(
            f"--index {index} di luar jangkauan ({len(data)} temuan)")
    f = data[index]
    if not isinstance(f, dict):
        raise InputError(f"temuan indeks {index} bukan objek")
    return f


def _first(f: dict, keys: "tuple[str, ...]") -> str:
    for k in keys:
        v = str(f.get(k) or "").strip()
        if v:
            return v
    return ""


def evidence_refs(f: dict, src_name: str, index: int) -> "list[tuple[str, str]]":
    """Daftar (field, evidence_ref) untuk bukti yang ADA di temuan.

    evidence_ref eksplisit dipakai untuk semua field; kalau tidak ada,
    rujukan dibangun deterministik: {nama-file}#{index}:{field}.
    """
    explicit = str(f.get("evidence_ref") or "").strip()
    out = []
    for field in EVIDENCE_FIELDS:
        if str(f.get(field) or "").strip():
            ref = explicit or f"{src_name}#{index}:{field}"
            out.append((field, ref))
    if not out and explicit:
        out.append(("evidence_ref", explicit))
    return out


def build_title(f: dict) -> tuple[str, bool]:
    """Rumus '[KELAS] dampak via endpoint'. True = lengkap tanpa
    placeholder (klaim dampak bersumber temuan, bukan karangan tool)."""
    kelas = (_first(f, ("check", "vuln_class")) or "KELAS").upper()
    dampak = _first(f, IMPACT_KEYS) or _first(f, ("title",))
    endpoint = _first(f, ("endpoint", "target_url", "file_path")) \
        or "[endpoint]"
    complete = bool(dampak) and endpoint != "[endpoint]"
    if not dampak:
        dampak = PLACEHOLDER_IMPACT
    return f"[{kelas}] {dampak} via {endpoint}", complete


def impact_section(f: dict, refs: "list[tuple[str, str]]",
                   draft_l1: bool) -> str:
    """Seksi Impact — KLAIM hanya dengan bukti; tanpa bukti = tidak
    ada klaim, hanya penanda NEEDS-EVIDENCE (fail-closed jujur)."""
    lines: list[str] = []
    claim = _first(f, IMPACT_KEYS)
    if claim and refs:
        ref_all = "; ".join(r for _, r in refs)
        lines.append(claim)
        lines.append("")
        lines.append(f"(bukti: {ref_all})")
        lines.append("")
    elif claim and not refs:
        # klaim tanpa bukti TIDAK ditulis — bahkan klaim dari temuan
        lines.append("NEEDS-EVIDENCE — teks dampak ada di temuan tapi "
                     "tidak ada bukti (request/response/poc/evidence_ref) "
                     "untuk menopangnya; klaim tidak ditulis (fail-closed).")
        lines.append("")
    else:
        lines.append("NEEDS-EVIDENCE — tidak ada klaim dampak yang bisa "
                     "ditulis tanpa bukti (fail-closed).")
        lines.append("")
    for field, ref in refs:
        lines.append(f"- Bukti `{field}` terlampir di laporan ini "
                     f"(bukti: {ref}).")
    if refs:
        lines.append("")
    if draft_l1:
        lines.append(PLACEHOLDER_IMPACT + "  *(draf L1 — wajib dilengkapi "
                     "manusia sebelum lanjut)*")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def steps_section(f: dict) -> str:
    lines = ["**Setup:** " + PLACEHOLDER_SETUP, "", "**Langkah:**", ""]
    n = 1
    request = str(f.get("request") or "").strip()
    poc = str(f.get("poc") or "").strip()
    response = str(f.get("response") or "").strip()
    if not request and not poc:
        lines.append(f"{n}. NEEDS-EVIDENCE — temuan tanpa request/poc; "
                     "langkah reproduksi tidak bisa disusun (fail-closed).")
        lines.append("")
        return "\n".join(lines)
    lines.append(f"{n}. Siapkan akses sesuai Setup.")
    n += 1
    if request:
        lines.append(f"{n}. Kirim permintaan berikut (copy-paste-ready):")
        lines.append("")
        lines.append("```http")
        lines.append(request)
        lines.append("```")
        lines.append("")
        n += 1
    if poc:
        lines.append(f"{n}. Jalankan PoC:")
        lines.append("")
        lines.append("```")
        lines.append(poc)
        lines.append("```")
        lines.append("")
        n += 1
    if response:
        lines.append(f"{n}. Amati respons:")
        lines.append("")
        lines.append("```")
        lines.append(response)
        lines.append("```")
        lines.append("")
    else:
        lines.append(f"{n}. [ISI MANUAL: tempel respons nyata yang "
                     "memperlihatkan dampak]")
        lines.append("")
    return "\n".join(lines)


def build_draft(f: dict, platform: str, src_name: str, index: int) -> "tuple[str, str]":
    """Susun draf markdown. Kembalikan (teks, level) dgn level L1|L2."""
    refs = evidence_refs(f, src_name, index)
    status = str(f.get("status") or "").strip()
    confirmed = status == "confirmed"
    has_evidence = bool(refs)
    level = "L2" if (confirmed and has_evidence) else "L1"
    title, _ = build_title(f)
    severity = str(f.get("severity") or "").strip() or \
        "[ISI MANUAL: severity]"

    hdr = [f"<!-- {SCHEMA} | draf {level} | platform: {platform} -->", ""]
    hdr.append("> **DRAF " + level + "** — dihasilkan "
               "tools/submission_report.py (ABH-W3). WAJIB review manusia; "
               "BUKAN submission-ready; tool ini TIDAK mengirim apa pun "
               "(nol jaringan).")
    hdr.append(f"> Sumber: {src_name}#{index} | platform: {platform} | "
               f"status temuan: {status or '(kosong)'} | "
               f"severity: {severity}")
    if status == "false-positive":
        hdr.append("> **PERINGATAN:** temuan berstatus false-positive — "
                   "draf ini TIDAK untuk dikirim.")
    if level == "L1":
        hdr.append("> **PERINGATAN L1:** temuan belum confirmed dan/atau "
                   "tanpa bukti — semua klaim bersifat kerangka, tidak "
                   "boleh dikirim apa adanya.")
    hdr.append("")

    body: list[str] = []
    if platform == "hackerone":
        body.append("## " + title)
        body.append("")
        body.append(f"**Severity:** {severity} | **CVSS 3.1:** "
                    "[ISI MANUAL: vektor CVSS 3.1]")
        body.append("")
    elif platform == "bugcrowd":
        body.append("# " + title)
        body.append("")
        body.append(f"**VRT:** [ISI MANUAL: kategori VRT] | "
                    f"**Severity:** {severity}")
        body.append("")
    else:  # intigriti — judul gaya "[Kelas]: dampak"
        body.append("# " + title.replace("] ", "]: ", 1))
        body.append("")
        body.append(f"**CVSS 3.1:** [ISI MANUAL: vektor] | "
                    f"**Severity:** {severity}")
        body.append("")

    body.append("## Summary")
    body.append("")
    kelas_txt = _first(f, ("check", "vuln_class")) or "?"
    target_txt = _first(f, ("target_url", "endpoint", "file_path")) or "?"
    body.append(_first(f, ("summary",)) or
                f"[ISI MANUAL: satu paragraf impact-first utk judul di "
                f"atas — apa bugnya, di mana, penyerang bisa apa. "
                f"Kelas: {kelas_txt}; target: {target_txt}; akses yang "
                f"dibutuhkan: [ISI MANUAL].]")
    body.append("")

    body.append("## Steps to Reproduce")
    body.append("")
    body.append(steps_section(f).rstrip())
    body.append("")

    body.append("## Impact")
    body.append("")
    body.append(impact_section(f, refs, level == "L1").rstrip())
    body.append("")

    body.append("## Recommended Fix")
    body.append("")
    body.append(_first(f, FIX_KEYS) or PLACEHOLDER_FIX)
    body.append("")

    body.append("---")
    body.append("*Catatan W3: draf maksimal L1/L2 — verifikasi bukti "
                "(verify_gate) dan disiplin pra-submit (submission_gate) "
                "di ranah tool lain; kemasan bukti via report_pack. "
                "Tanpa bukti, klaim tidak ditulis.*")
    text = "\n".join(hdr + body)
    return text, level


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--findings", type=Path, required=True,
                    help="findings.json (array / {findings:[...]} / satu "
                         "temuan); temuan dipilih --index")
    ap.add_argument("--index", type=int, default=0)
    ap.add_argument("--platform", required=True, choices=PLATFORMS,
                    help="bentuk laporan tujuan")
    ap.add_argument("--out", type=Path, default=None,
                    help="tulis draf markdown ke file (default stdout)")
    args = ap.parse_args(argv)

    try:
        data = load_findings(args.findings)
        f = pick_finding(data, args.index)
    except InputError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    text, level = build_draft(f, args.platform, args.findings.name,
                              args.index)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 0 if level == "L2" else 1


if __name__ == "__main__":
    raise SystemExit(main())

r"""[SAFETY: read-only] aide_change_triage — triase OFFLINE laporan
`aide --check` (file integrity monitoring Linux): klasifikasi added/
removed/changed entries per kritisnya path dan jenis atribut berubah.

Mengisi antrean port SKILL-PORT-QUEUE #0626 (mukul975/
Anthropic-Cybersecurity-Skills 'implementing-file-integrity-monitoring-
with-aide'; atribusi konsep, lisensi sumber Apache-2.0). Skill sumber
menjalankan AIDE di host (aide --init/--check) dan menyebut langkah
"Parse Change Report — extract added, removed, changed" tanpa parser:
inti deterministik yang diekstrak di sini adalah PARSER LAPORAN +
klasifikasi severity-nya, dari scratch (tidak menyalin kode sumber,
tidak memanggil AIDE). AIDE sendiri = alat host eksternal; jalankan
`aide --check` di lab Anda, triase output-nya di secai.

Pembagian ranah (TIDAK diduplikasi):
  - baseline kredensial/appArmor dsb. di Windows  -> mft_scan (B08)
  - baseline sertifikat CT                       -> ct_baseline_diff (B10)
  - di sini: laporan teks AIDE check.

Input -> mekanisme -> output:
  - Input : satu file teks output `aide --check` (format klasik
            "Added/Removed/Changed entries:" ATAU gaya baru "added:/"
            "removed:/changed:"), baca-saja.
  - Mekanisme: pisahkan seksi berdasar header + garis pemisah, parse
            tiap entry [tipe] path [attrs...], klasifikasikan:
            path kritis (/bin,/sbin,/lib*,/boot) > /etc > /tmp & co >
            lainnya; attrs hash (md5/sha256/sha1/sha512/dst.) berubah =
            perubahan ISI (lebih tinggi), metadata saja = lebih rendah;
            bandingkan jumlah ter-parse vs angka Summary (mismatch =
            fail-closed).
  - Output: JSON {schema, stats, findings, notes}; finding =
            {check, severity, kind, path, attrs, message}.

Cek:
  added-binary-path      (high): entry BARU di bin/sbin/lib*/boot.
  removed-binary-path    (high): entry bin/sbin/lib*/boot DIHAPUS.
  changed-binary-path    (high): perubahan di bin/sbin/lib*/boot.
  changed-content-hash   (high): atribut hash berubah = isi berubah
                         (bukan hanya metadata).
  added-etc-path         (medium): file baru di /etc (drift config).
  added-tmp-path         (medium): file baru di /tmp,/var/tmp,/dev/shm
                         (staging umum).
  changed-etc-path       (medium): perubahan /etc tanpa attr hash.
  changed-metadata       (low)  : hanya metadata (mtime/perm/uid/inode).
  added-path             (low)  : entry baru di luar kelas di atas.
  removed-etc-path       (medium): entry /etc dihapus.
  summary-mismatch       (medium): angka Summary != jumlah ter-parse
                         (parser melewatkan sesuatu — fail-closed).
  entry-unparsed         (high) : baris entry tak bisa diekstrak
                         (fail-closed; TIDAK pernah dianggap bersih).

Fail-closed:
  - file tidak ada / bukan teks -> exit 2.
  - bukan output AIDE (tanpa header seksi dan tanpa Summary) -> exit 2.
  - "Looks okay" -> bersih, exit 0 (laporan AIDE eksplisit).
  - entry tanpa path -> entry-unparsed, tetap dievaluasi temuan lain.

Anti-FP: --allow-path PREFIX (boleh diulang) menyaring entry yang
berubah sah (window paket update; operator yang tahu konteksnya);
jumlah saringan dicatat di stats.allowed_filtered — tidak dipendam.

Exit: 0 bersih; 1 ada temuan >= --fail-on (default high); 2 error input.

Pemakaian:
  python tools/aide_change_triage.py --report aide-check.txt --out triage.json
  python tools/aide_change_triage.py --report aide-check.txt \
      --allow-path /var/log --fail-on medium
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

SCHEMA = "secai.aide-change-triage/1"
MAX_FILE_BYTES = 16 * 1024 * 1024

SEV_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

BIN_PREFIXES = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/local/bin/",
    "/usr/local/sbin/", "/boot/", "/lib/", "/lib64/", "/usr/lib/",
    "/usr/lib64/", "/usr/local/lib/", "/usr/local/lib64/",
    "/root/.ssh/",
)
# file langsung (bukan direktori) yang klasik kritis
BIN_FILES = ("/bin", "/sbin", "/boot", "/etc/passwd", "/etc/shadow",
             "/etc/sudoers", "/etc/group", "/etc/gshadow")
ETC_PREFIX = "/etc/"
TMP_PREFIXES = ("/tmp/", "/var/tmp/", "/dev/shm/")
HASH_ATTRS = {
    "md5", "sha1", "sha256", "sha512", "rmd160", "tiger", "haval",
    "crc32", "crc32b", "gost", "whirlpool", "sha3_256", "sha3_512",
    "mdouble", "shash", "norm", "sha512_256",
}
SECTION_HEADERS = {
    "added": ("added entries:", "added:"),
    "removed": ("removed entries:", "removed:"),
    "changed": ("changed entries:", "changed:"),
}


def _classify_kind(section: str, path: str, attrs: "set[str]") -> "tuple[str, int]":
    """(check, severity-map-key) untuk satu entry."""
    p = path.rstrip("/") or "/"
    in_bin = p.startswith(BIN_PREFIXES) or p in BIN_FILES
    in_etc = p.startswith(ETC_PREFIX) or p in ("/etc",)
    in_tmp = p.startswith(TMP_PREFIXES)
    hash_changed = bool(attrs & HASH_ATTRS)

    if section == "added":
        if in_bin:
            return "added-binary-path", 3
        if in_etc:
            return "added-etc-path", 2
        if in_tmp:
            return "added-tmp-path", 2
        return "added-path", 1
    if section == "removed":
        if in_bin:
            return "removed-binary-path", 3
        if in_etc:
            return "removed-etc-path", 2
        return "removed-path", 1
    # changed: isi berubah (attr hash) = sinyal terkuat, di atas lokasi
    if hash_changed:
        return "changed-content-hash", 3
    if in_bin:
        return "changed-binary-path", 3
    if in_etc:
        return "changed-etc-path", 2
    return "changed-metadata", 1


def _parse_entry_line(line: str) -> "tuple[str, set[str]] | None":
    """Kembalikan (path, attrs) atau None bila tak bisa diekstrak."""
    tokens = line.split()
    if not tokens:
        return None
    idx = 0
    if len(tokens) >= 2 and len(tokens[0]) <= 2 and tokens[0].isalpha():
        idx = 1  # token pertama = kode tipe AIDE (f/d/l/b/c/p/r/-)
    path = tokens[idx].rstrip(":")
    if not path.startswith("/"):
        # format tanpa tipe & tanpa path absolut: tetap coba pakai token
        # pertama bila tampak seperti path
        if "/" in tokens[0]:
            path = tokens[0].rstrip(":")
            idx = 0
        else:
            return None
    attrs: "set[str]" = set()
    for tok in tokens[idx + 1:]:
        for part in tok.strip(",").split(","):
            part = part.strip().lower()
            if part and part != path:
                attrs.add(part)
    return path, attrs


def triage_report(text: str) -> "tuple[list[dict], dict]":
    findings: "list[dict]" = []
    stats = {
        "added": 0, "removed": 0, "changed": 0,
        "summary_counts": {}, "mismatch": [],
        "unparsed": 0, "looks_okay": False,
    }
    lines = text.splitlines()

    looks_okay = any("looks okay" in ln.lower() for ln in lines)
    stats["looks_okay"] = looks_okay

    # angka Summary: header + ANGKA (klasik "Added entries:\t2",
    # baru "added: 2"); header tanpa angka = penanda seksi (dibawah).
    summary: "dict[str, int]" = {}
    for ln in lines:
        low = ln.strip().lower()
        m = re.match(r"(added|removed|changed)(?: entries)?:\s*(\d+)\s*$",
                     low)
        if m:
            summary[m.group(1)] = int(m.group(2))

    has_summary_header = any("total number of entries" in ln.lower()
                             for ln in lines)
    stats["summary_counts"] = summary

    # seksi: header mengubah section aktif; baris entry dievaluasi per seksi
    section: "str | None" = None
    seen_sections: "set[str]" = set()

    for raw in lines:
        line = raw.strip()
        low = line.lower()
        if not line or line.startswith("#"):
            continue
        if set(line) <= {"-"}:
            continue  # garis pemisah
        if re.match(r"(added|removed|changed)(?: entries)?:\s*(\d+)\s*$",
                    low):
            continue  # baris angka Summary — bukan penanda seksi
        matched = None
        for key, variants in SECTION_HEADERS.items():
            for v in variants:
                if low.startswith(v) and (len(line) == len(v)
                                          or low[len(v)] in ": \t"):
                    matched = key
        if matched:
            section = matched
            seen_sections.add(matched)
            continue
        if low.startswith(("aide ", "start timestamp", "summary:",
                           "total number of entries",
                           "found differences", "the properties of the")):
            continue
        if section is None:
            continue  # baris di luar seksi: abaikan (header/banner)
        parsed = _parse_entry_line(line)
        if parsed is None:
            stats["unparsed"] += 1
            findings.append({
                "check": "entry-unparsed", "severity": "high",
                "kind": section, "path": line[:120], "attrs": [],
                "message": "baris entry tidak bisa diekstrak path-nya "
                           "(fail-closed) — cek format laporan.",
            })
            continue
        path, attrs = parsed
        stats[section] += 1
        check, sevkey = _classify_kind(section, path, attrs)
        sev = {1: "low", 2: "medium", 3: "high"}[sevkey]
        msg = {
            "added-binary-path": "file BARU di direktori biner/boot/"
                                 "lib — kandidat implant/lolbin baru.",
            "removed-binary-path": "file biner/boot/lib DIHAPUS — bisa "
                                   "tamparan integritas atau update "
                                   "paket (verifikasi konteks).",
            "removed-etc-path": "konfigurasi /etc DIHAPUS — bisa "
                                "hardening sah atau penghilangan kontrol "
                                "sekuriti (verifikasi konteks).",
            "changed-binary-path": "entry biner/boot/lib berubah — "
                                   "verifikasi hash vs paket manager.",
            "changed-content-hash": "atribut HASH berubah = isi file "
                                    "berubah (bukan cuma metadata).",
            "added-etc-path": "file baru di /etc — drift konfigurasi; "
                              "verifikasi sumber perubahan.",
            "added-tmp-path": "file baru di tmp/dev-shm — staging umum "
                              "payload (low-value tapi layak dicatat).",
            "changed-etc-path": "konfigurasi /etc berubah tanpa perubahan "
                                "hash yang tercatat.",
            "changed-metadata": "hanya metadata berubah (mtime/perm/uid/"
                                "inode) — biasanya higiene biasa.",
            "added-path": "entry baru di luar kelas kritis.",
            "removed-path": "entry dihapus di luar kelas kritis.",
        }[check]
        findings.append({
            "check": check, "severity": sev, "kind": section,
            "path": path, "attrs": sorted(attrs), "message": msg,
        })

    # bandingkan Summary vs ter-parse (fail-closed)
    for key in ("added", "removed", "changed"):
        if key in summary and summary[key] != stats[key]:
            stats["mismatch"].append(
                {"kind": key, "summary": summary[key],
                 "parsed": stats[key]})
            findings.append({
                "check": "summary-mismatch", "severity": "medium",
                "kind": key, "path": "(summary)", "attrs": [],
                "message": f"Summary menyebut {summary[key]} entry "
                           f"{key}, parser menemukan {stats[key]} — "
                           "format laporan mungkin beda versi; TIDAK "
                           "dianggap bersih (fail-closed).",
            })

    if not seen_sections and not summary and not has_summary_header \
            and not looks_okay:
        # tidak ada penanda apa pun yang dikenali
        stats["unrecognized"] = True
    return findings, stats


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(
        description="Triase laporan 'aide --check' offline, nol jaringan.")
    ap.add_argument("--report", required=True,
                    help="file teks output 'aide --check'")
    ap.add_argument("--allow-path", action="append", default=[],
                    metavar="PREFIX",
                    help="abaikan entry dengan path-prefix ini (bisa "
                         "diulang); dicatat di stats")
    ap.add_argument("--fail-on", default="high",
                    choices=["low", "medium", "high", "critical"],
                    help="severity minimum yang memicu exit 1 (default high)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args(argv)

    path = Path(args.report)
    try:
        if not path.is_file():
            raise ValueError(f"file tidak ada: {path}")
        if path.stat().st_size > MAX_FILE_BYTES:
            raise ValueError("file terlalu besar")
        text = path.read_text(encoding="utf-8", errors="replace")
    except ValueError as exc:
        print(json.dumps({"schema": SCHEMA, "error": str(exc)}),
              file=sys.stderr)
        return 2

    findings, stats = triage_report(text)
    if stats.get("unrecognized"):
        print(json.dumps({
            "schema": SCHEMA,
            "error": "file tidak berisi header seksi AIDE, Summary, "
                     "angka 'added/removed/changed:', atau 'Looks okay' "
                     "— kemungkinan bukan output `aide --check` "
                     "(fail-closed)",
        }), file=sys.stderr)
        return 2

    allow = tuple(p.strip().rstrip("/") for p in args.allow_path
                  if p.strip())
    if allow:
        kept = []
        for f in findings:
            fp = str(f["path"]).rstrip("/")
            if any(fp == a or fp.startswith(a + "/") or
                   (a in ("/tmp", "/var/tmp", "/dev/shm")
                    and fp.startswith(a + "/")) for a in allow):
                stats["allowed_filtered"] = \
                    stats.get("allowed_filtered", 0) + 1
                continue
            kept.append(f)
        findings = kept

    threshold = SEV_ORDER[args.fail_on]
    hit = [f for f in findings
           if SEV_ORDER.get(f["severity"], 0) >= threshold]
    notes = [
        "triase STATIS laporan AIDE — AIDE sendiri berjalan di host lab "
        "(aide --init dulu utk baseline; baseline usang = semua temuan "
        "menjadi noise, cf. METHODS seksi 70); alat ini mengklasifikasi "
        "laporannya.",
        "severity mengikuti kelas path: biner/boot/lib kritis, /etc "
        "config, tmp staging; attr hash berubah > metadata saja.",
        "entry tanpa path dan mismatch Summary TIDAK pernah dianggap "
        "bersih (fail-closed).",
    ]
    if stats.get("looks_okay"):
        notes.append("laporan menyebut 'Looks okay' — AIDE eksplisit "
                     "menyatakan tidak ada perbedaan.")
    if stats.get("allowed_filtered"):
        notes.append(f"{stats['allowed_filtered']} entry disaring via "
                     "--allow-path — saringan dicatat, tidak dipendam.")

    report = {
        "schema": SCHEMA,
        "stats": stats,
        "findings": sorted(
            findings,
            key=lambda f: (-SEV_ORDER.get(f["severity"], 0),
                           f["path"], f["check"])),
        "notes": notes,
    }
    text_out = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        Path(args.out).write_text(text_out + "\n", encoding="utf-8")
    else:
        print(text_out)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())

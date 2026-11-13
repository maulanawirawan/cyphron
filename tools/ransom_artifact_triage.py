r"""[AUDIT: read-only] ransom_artifact_triage — triase OFFLINE artefak
ransomware dari daftar berkas yang DIKUMPUL + isi ransom note: petunjuk
varian dari ekstensi, nama berkas ransom-note, IOC dalam note, window
waktu enkripsi, dan konsentrasi mass-encryption per direktori.

Ranah tetangga eksplisit (jangan dipindah ke sini):
  - cmdline vssadmin/bcdedit/wbadmin (T1490) = sysmon_triage /
    lolbin_scan / win_persist_triage — tool ini TIDAK mem-parse log
    proses, hanya nama berkas di manifest;
  - entropi PE / packer = packer_scan;
  - dokumen berbahaya (maldoc/pdf) = maldoc_triage / pdf_triage;
  - blok PEM private key = repo_secret_scan (disarikan saja di summary);
  - timeline event Windows = win_*_triage; tool ini memakai mtime
    manifest, bukan event log.

Input -> mekanisme -> output:
  - Input : --listing FILE (WAJIB) — JSON {"files": [...]} atau array:
            entri {"path": str, "size"?: int, "mtime"?: ISO-8601/epoch};
            ATAU daftar teks satu path per baris (tanpa mtime — window
            tidak bisa dihitung dan dicatat sbg keterbatasan). Also:
            --note FILE (boleh berulang) — berkas ransom note (teks).
  - Mekanisme: klasifikasi ekstensi per berkas -> pencocokan pola nama
            note -> ekstraksi IOC dari isi note (bitcoin/monero/onion/
            email) -> window waktu per ekstensi -> agregasi per
            direktori utk konsentrasi mass-encryption.
  - Output: temuan {check, severity, object, field, message} + summary
            (jumlah, varian, window, IOC terkumpul) + notes + errors;
            exit 1 bila temuan >= --fail-on (default medium), exit 2
            bila listing hilang/JSON korup.

Cek (semua verdict = LEAD untuk triase, bukan kesimpulan keluarga):
  variant-extension-match    (high)  : ekstensi pada tabel keluarga
                                       spesifik (mis. .lockbit, .akira);
                                       ekstensi generik (.enc dst.)
                                       SENGAJA tidak masuk tabel (anti-FP)
  ransom-note-filename       (medium): nama berkas berpola note MAJEMUK
                                       (readme-UNTUK-decrypt, how_to_-
                                       restore, ransom, !!!..., #...#;
                                       README.md/txt polos dan
                                       "decryptor" TIDAK kena — anti-FP)
  note-content-ransom-iocs   (medium): isi note memuat onion ATAU
                                       alamat kripto (BTC/XMR); email
                                       sendirian TIDAK menandai (anti-FP)
  mass-encrypted-files       (medium): >= --min-mass berkas dgn ekstensi
                                       generik sama di SATU direktori
                                       (whitelist via --allow-ext)
Fail-closed: entri listing tanpa path / mtime tak terurai -> errors +
            tidak dihitung bersih; note biner -> error, bukan diam;
            note absen -> error (argumen eksplisit).

Pemakaian:
  python tools/ransom_artifact_triage.py --listing files.json \
      --note note1.txt --note note2.html
  python tools/ransom_artifact_triage.py --listing paths.txt \
      --min-mass 50 --fail-on high
Exit: 0 selesai bersih; 1 temuan gagal ambang; 2 input error.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = "secai.ransom-artifact-triage/1"
MAX_NOTE_BYTES = 1024 * 1024

SEVERITY_ORDER = {"high": 3, "medium": 2, "low": 1}

# Ekstensi yang SPESIFIK ke keluarga (publik diketahui, No More Ransom /
# advisori vendor). Ekstensi generik (.enc/.crypt dst.) sengaja di luar
# tabel ini agar tidak memicu FP — mereka ditangani cek mass-encryption.
VARIANT_EXT = {
    ".lockbit": "LockBit",
    ".lockbit3": "LockBit 3.0",
    ".blackcat": "BlackCat/ALPHV",
    ".alphv": "BlackCat/ALPHV",
    ".royal": "Royal",
    ".akira": "Akira",
    ".clop": "Cl0p",
    ".cl0p": "Cl0p",
    ".conti": "Conti",
    ".ryuk": "Ryuk",
    ".revil": "REvil/Sodinokibi",
    ".sodinokibi": "REvil/Sodinokibi",
    ".maze": "Maze",
    ".phobos": "Phobos",
    ".dharma": "Dharma/CrySIS",
    ".cerber": "Cerber",
    ".stop": "STOP/Djvu",
    ".hive": "Hive",
    ".blackbasta": "Black Basta",
    ".play": "Play",
    ".mallox": "Mallox",
    ".monti": "Monti",
    ".babuk": "Babuk",
    ".cuba": "Cuba",
    ".medusalocker": "MedusaLocker",
    ".wcry": "WannaCry",
    ".wnry": "WannaCry",
    ".cryptolocker": "CryptoLocker",
    ".globe": "Globe",
    ".onion": "Dharma/Onion-family",
    ".wallet": "Wallet-family",
    ".enigma": "Enigma",
    ".kraken": "Kraken",
    ".faust": "Faust",
    ".chifr": "Chaos/Chifr",
}

# Ekstensi terenkripsi-GENERIK: hanya dievaluasi lewat konsentrasi massa,
# bukan per berkas (satu .enc sah tidak bermakna).
GENERIC_EXT = {".encrypted", ".locked", ".crypted", ".crypt", ".enc"}

# Pola nama berkas ransom-note (diterapkan pada basename lowercase).
# Anti-FP: token HARUS majemuk (README_FOR_DECRYPT, bukan README.md
# polos), "decryptor" dikecualikan (alat dekripsi sah), "recovery_plan"
# tidak kena (recover diikuti huruf, bukan pemisah).
NOTE_NAME_PATTERNS = (
    r"decrypt(?!or)",
    r"ransom",
    r"how[-_]?to[-_]?(decrypt|restore|recover)",
    r"(^|[^a-z0-9])(restore|recover)[-_. ]",
    r"your[-_]?files",
    r"^!",  # gaya "!!!READ_ME!!!.txt" / "!!!-WARNING-!!!"
    r"^#[a-z0-9#]+(\.[a-z0-9.]+)?$",  # gaya "#RECOVERY#.txt" / "###READ_IT###"
    # "readme/read_me" polos hanya saat ekstensi dropper (bukan .md/.txt
    # dokumen proyek):
    r"read[_-]?me.*\.(hta|lnk|vbs|js|url)$",
)

RE_BTC_LEGACY = re.compile(r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b")
RE_BTC_BECH32 = re.compile(r"\bBC1[A-Z0-9]{8,61}\b", re.IGNORECASE)
RE_XMR = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
RE_ONION = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
RE_EMAIL = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")


def _parse_mtime(raw) -> "datetime | None":
    """ISO-8601 atau epoch numerik -> datetime aware UTC; None bila absen.
    Melempar ValueError bila format tidak bisa diurai (fail-closed)."""
    if raw is None:
        return None
    if isinstance(raw, (int, float)) and not isinstance(raw, bool):
        return datetime.fromtimestamp(float(raw), tz=timezone.utc)
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return None
        if text.isdigit():
            return datetime.fromtimestamp(float(text), tz=timezone.utc)
        norm = text.replace("Z", "+00:00")
        dt = datetime.fromisoformat(norm)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    raise ValueError(f"mtime bertipe aneh: {type(raw).__name__}")


def _read_listing(path: Path, errors: "list[str]") -> "list[dict]":
    """Baca manifest -> list entri {path, size?, mtime?} (teks/JSON).
    Bila JSON korup -> ValueError (pemanggil exit 2)."""
    raw = path.read_text(encoding="utf-8", errors="strict")
    stripped = raw.lstrip()
    entries: "list[dict]" = []
    if stripped[:1] in ("{", "["):
        data = json.loads(raw)
        if isinstance(data, dict):
            data = data.get("files", data.get("entries"))
            if data is None:
                raise ValueError("JSON objek tanpa kunci 'files'/'entries'")
        if not isinstance(data, list):
            raise ValueError("JSON listing harus array atau objek 'files'")
        for i, item in enumerate(data):
            if isinstance(item, str):
                item = {"path": item}
            if not isinstance(item, dict) or not str(item.get("path", "")):
                errors.append(
                    f"listing: entri #{i} tanpa 'path' — dilewati "
                    "(tidak dihitung bersih)")
                continue
            entries.append(item)
        return entries
    for i, line in enumerate(raw.splitlines(), 1):
        p = line.strip()
        if not p or p.startswith("#"):
            continue
        entries.append({"path": p})
    return entries


def _match_note_name(basename: str) -> "str | None":
    low = basename.lower()
    for pat in NOTE_NAME_PATTERNS:
        if re.search(pat, low):
            return pat
    return None


def analyze_note(text: str) -> dict:
    """Ekstraksi IOC kelas ransom dari isi note (tanpa jaringan)."""
    return {
        "bitcoin": sorted(set(RE_BTC_LEGACY.findall(text))
                          | set(RE_BTC_BECH32.findall(text))),
        "monero": sorted(set(RE_XMR.findall(text))),
        "onion": sorted(set(RE_ONION.findall(text))),
        "emails": sorted(set(RE_EMAIL.findall(text))),
    }


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--listing", type=Path, required=True,
                    metavar="FILE",
                    help="manifest JSON {'files':[...]} / array / "
                         "daftar path teks")
    ap.add_argument("--note", type=Path, action="append", default=[],
                    metavar="FILE", help="ransom note (boleh berulang)")
    ap.add_argument("--min-mass", type=int, default=25, metavar="N",
                    help="ambang konsentrasi ekstensi generik per "
                         "direktori (default 25)")
    ap.add_argument("--allow-ext", action="append", default=[],
                    metavar="EXT",
                    help="ekstensi dikecualikan dari cek mass (boleh "
                         "berulang, dgn titik: .enc)")
    ap.add_argument("--allow-check", action="append", default=[],
                    metavar="NAME", help="cek dilewati (sadar, dicatat)")
    ap.add_argument("--fail-on", choices=SEVERITY_ORDER, default="medium")
    ap.add_argument("--out", type=Path)
    args = ap.parse_args(argv)

    errors: "list[str]" = []
    findings: "list[dict]" = []
    notes_out: "list[str]" = []

    def add(check, severity, obj, field, message):
        if check in args.allow_check:
            return
        findings.append({"check": check, "severity": severity,
                         "object": obj, "field": field,
                         "message": message})

    if not args.listing.is_file():
        print(json.dumps({
            "schema": SCHEMA,
            "error": f"listing tidak ada/bukan berkas: {args.listing} — "
                     "fail-closed",
        }), file=sys.stderr)
        return 2

    try:
        entries = _read_listing(args.listing, errors)
    except (ValueError, UnicodeDecodeError) as exc:
        print(json.dumps({
            "schema": SCHEMA,
            "error": f"listing tidak bisa diurai: {exc} — fail-closed",
        }), file=sys.stderr)
        return 2

    allow_ext = {e.lower() if e.startswith(".") else f".{e.lower()}"
                 for e in args.allow_ext}

    variant_hits: "dict[str, dict]" = {}
    generic_by_dir: "dict[tuple, dict[str, int]]" = {}
    window: "dict[str, dict]" = {}
    mtimes_total = 0

    for item in entries:
        p = str(item["path"]).replace("\\", "/")
        norm = p.lower()
        fname = norm.rsplit("/", 1)[-1]
        dot = fname.rfind(".")
        ext = fname[dot:] if dot > -1 and dot != len(fname) - 1 else ""

        if ext in VARIANT_EXT:
            variant = VARIANT_EXT[ext]
            bucket = variant_hits.setdefault(
                variant, {"ext": ext, "count": 0,
                          "first": None, "last": None, "example": p})
            bucket["count"] += 1
        if ext in GENERIC_EXT and ext not in allow_ext:
            parent = tuple(p.rsplit("/", 1)[:-1]) or ("<root>",)
            generic_by_dir.setdefault(parent, {})
            generic_by_dir[parent][ext] = \
                generic_by_dir[parent].get(ext, 0) + 1
        mt_raw = item.get("mtime")
        if mt_raw is not None and ext in (VARIANT_EXT.keys()
                                          | GENERIC_EXT):
            try:
                dt = _parse_mtime(mt_raw)
            except ValueError as exc:
                errors.append(f"{p}: mtime tak terurai ({exc}) — "
                              "tidak dihitung utk window")
                continue
            if dt is None:
                continue
            mtimes_total += 1
            if ext in VARIANT_EXT:
                variant = VARIANT_EXT[ext]
                bucket = variant_hits.setdefault(
                    variant, {"ext": ext, "count": 0, "first": None,
                              "last": None, "example": p})
                if bucket["first"] is None or dt < bucket["first"]:
                    bucket["first"] = dt
                if bucket["last"] is None or dt > bucket["last"]:
                    bucket["last"] = dt

    # findings: varian
    for variant in sorted(variant_hits):
        b = variant_hits[variant]
        add("variant-extension-match", "high", b["example"],
            f"ext={b['ext']}",
            f"{b['count']} berkas dgn ekstensi '{b['ext']}' = petunjuk "
            f"keluarga {variant} — LEAD: konfirmasi dgn isi note/sampel, "
            "ekstensi bisa dipinjam keluarga lain")

    # findings: konsentrasi mass-encryption
    for parent, exts in sorted(generic_by_dir.items()):
        for ext, count in sorted(exts.items()):
            if count >= args.min_mass:
                add("mass-encrypted-files", "medium",
                    "/".join(parent) or "<root>", f"ext={ext}",
                    f"{count} berkas '{ext}' di satu direktori "
                    f"(>= --min-mass {args.min_mass}) = pola enkripsi "
                    "massal — LEAD; ekstensi generik juga dipakai alat "
                    "sah (whitelist --allow-ext bila ya)")

    # notes
    iocs = {"bitcoin": set(), "monero": set(), "onion": set(),
            "emails": set()}
    notes_read = 0
    note_names: "set[str]" = set()
    if not args.note:
        notes_out.append("tidak ada --note diberikan — cek isi note "
                         "dilewati (nama berkas di listing tetap cek)")
    for np in args.note:
        if not np.is_file():
            print(json.dumps({
                "schema": SCHEMA,
                "error": f"note tidak ada/bukan berkas: {np} — "
                         "fail-closed",
            }), file=sys.stderr)
            return 2
        note_names.add(np.name.lower())
        data = np.read_bytes()
        if b"\x00" in data[:4096]:
            errors.append(f"{np.name}: tampak biner (NUL byte) — isi "
                          "tidak dianalisis, nama tetap dicatat")
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:
                text = data.decode("utf-8", errors="replace")
            notes_read += 1
            found = analyze_note(text)
            for k in iocs:
                iocs[k] |= set(found[k])
            if found["onion"] or found["bitcoin"] or found["monero"]:
                add("note-content-ransom-iocs", "medium", np.name,
                    "note-ioc",
                    f"note memuat: "
                    + ", ".join(
                        f"{k}={len(v)}" for k, v in found.items() if v)
                    + " — IOC terkumpul di bagian iocs laporan")
        pat = _match_note_name(np.name)
        if pat:
            add("ransom-note-filename", "medium", np.name,
                f"pattern={pat}",
                "argumen --note berpola nama ransom-note")

    # nama berkas berpola note di listing (di luar --note)
    seen_note_paths: "set[str]" = set()
    for item in entries:
        p = str(item["path"]).replace("\\", "/")
        fname = p.rsplit("/", 1)[-1]
        if fname.lower() in note_names:
            continue  # sudah dilaporkan sbg --note (hindari duplikat)
        if fname in seen_note_paths:
            continue
        if _match_note_name(fname):
            seen_note_paths.add(fname)
            ext = fname.lower().rsplit(".", 1)[-1]
            sev = "medium"
            add("ransom-note-filename", sev, p, "name-pattern",
                "berkas berpola nama ransom-note"
                + (" (.hta = dropper note, sering dieksekusi user)"
                   if ext == "hta" else "")
                + " — cek isinya")

    # window enkripsi di summary
    window_out = {}
    for variant, b in sorted(variant_hits.items()):
        if b["first"] and b["last"]:
            window_out[variant] = {
                "ext": b["ext"], "count": b["count"],
                "first": b["first"].isoformat(),
                "last": b["last"].isoformat(),
                "span_minutes": round(
                    (b["last"] - b["first"]).total_seconds() / 60.0, 1),
            }
    if entries and mtimes_total == 0 and not window_out:
        notes_out.append("listing tanpa mtime (atau mode teks) — window "
                         "waktu enkripsi tidak bisa dihitung")

    threshold = SEVERITY_ORDER[args.fail_on]
    hit = any(SEVERITY_ORDER.get(f["severity"], 0) >= threshold
              for f in findings)
    if args.allow_check:
        notes_out.append(f"check disaring: {', '.join(sorted(args.allow_check))}")
    if args.allow_ext:
        notes_out.append(f"ekstensi di-whitelist utk cek mass: "
                         f"{', '.join(sorted(allow_ext))}")
    notes_out.extend([
        "audit statis atas manifest + note yang DIKUMPUL — bukan hasil "
        "live host; keandalan mengikuti kelengkapan akuisisi",
        "semua verdict = LEAD triase, bukan kesimpulan keluarga "
        "ransomware — identifikasi final via sampel + note + IOC gabungan",
        "ekstensi generik (.enc/.crypt dst.) sengaja tidak masuk tabel "
        "varian (anti-FP) — dievaluasi lewat konsentrasi massal saja",
        "runbook live (Volatility, ID Ransomware online, pembersihan) "
        "= di luar tool — acuan internal memegangnya",
    ])

    report = {
        "schema": SCHEMA,
        "summary": {
            "files_scanned": len(entries),
            "dirs_seen": len({tuple(str(i["path"]).replace("\\", "/")
                                    .rsplit("/", 1)[:-1]) or ("<root>",)
                              for i in entries}),
            "notes_read": notes_read,
            "files_with_mtime_used": mtimes_total,
            "variants": {v: variant_hits[v]["count"]
                         for v in sorted(variant_hits)},
            "encryption_window": window_out,
            "iocs": {k: sorted(v) for k, v in iocs.items()},
            "findings": len(findings),
            "by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in ("high", "medium", "low")
            },
        },
        "findings": sorted(
            findings,
            key=lambda f: (-SEVERITY_ORDER.get(f["severity"], 0),
                           f["object"], f["check"])),
        "notes": notes_out,
        "errors": errors,
    }
    text = json.dumps(report, ensure_ascii=False, indent=2)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)
    return 1 if hit else 0


if __name__ == "__main__":
    raise SystemExit(main())

"""[F51] Binary strings surface — "apa yang terbaca dari binary/firmware
kamu" (kelas tool RE, sisi defensif; CLEAN-ROOM, NOL jaringan,
read-only, stdlib murni).

Input: satu file binary (exe/dll/so/bin/asar/firmware dump — apa pun).
Metode: ekstraksi string ASCII + UTF-16LE (runs >= 6 char, stdlib
regex atas bytes) dengan OFFSET byte tiap string, lalu signature ketat
(sama dgn bundle_exposure): URL absolut -> inventaris L0; secret
ber-format layanan (sk_live_/AKIA/ghp_/xoxb/AIza) -> lead L1
(CWE-798). Tanpa disassembler, tanpa tebakan — ini lapisan PERTAMA
yang dilihat siapa pun yang membuka binary (strings/rea/ghidra semua
mulai dari sini).

Pemakaian:
  python tools/binary_strings_surface.py --file app.exe \\
      --out findings/binary-surface.json
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "core"))
sys.path.insert(0, str(ROOT / "tools"))

from findings import make_finding, write_findings  # noqa: E402
from bundle_exposure import _RE_URL, _RE_SECRET  # noqa: E402

MAX_FILE_BYTES = 64_000_000
MIN_RUN = 6
MAX_ROWS = 40

_RE_ASCII_RUN = re.compile(rb"[\x20-\x7e]{%d,}" % MIN_RUN)
_RE_UTF16_RUN = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % MIN_RUN))


def _iter_matches(data: bytes):
    """Yield (offset, string) utk runs ASCII + UTF-16LE (urut offset)."""
    events: list[tuple[int, str]] = []
    for m in _RE_ASCII_RUN.finditer(data):
        events.append((m.start(), m.group(0).decode("ascii",
                                                    errors="replace")))
    for m in _RE_UTF16_RUN.finditer(data):
        try:
            s = m.group(0).decode("utf-16-le", errors="replace")
        except Exception:  # noqa: BLE001
            continue
        events.append((m.start(), s))
    for off, s in sorted(events):
        yield off, s


def _elf_sections(data: bytes) -> dict[str, tuple[int, int]] | None:
    """ELF64/32 -> {nama_section: (offset, size)} utk provenance;
    bukan ELF / header rusak = None (fail-closed, tanpa sections)."""
    import struct
    if data[:4] != b"\x7fELF" or len(data) < 64:
        return None
    ei_class = data[4]
    try:
        if ei_class == 2:  # ELF64
            e_shoff = struct.unpack_from("<Q", data, 0x28)[0]
            e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x3A)
            e_shstrndx = struct.unpack_from("<H", data, 0x3E)[0]
            FMT, OFF = "<IIQQQQIIQQ", 0
        elif ei_class == 1:  # ELF32
            e_shoff = struct.unpack_from("<I", data, 0x20)[0]
            e_shentsize, e_shnum = struct.unpack_from("<HH", data, 0x2E)
            e_shstrndx = struct.unpack_from("<H", data, 0x32)[0]
            FMT, OFF = "<IIIIIIIIII", 0
        else:
            return None
        if (e_shoff == 0 or e_shnum == 0
                or e_shoff + e_shnum * e_shentsize > len(data)):
            return None
        raw = []
        for i in range(e_shnum):
            raw.append(struct.unpack_from(FMT, data,
                                          e_shoff + i * e_shentsize))
        # ELF64 sh: name, type, flags, addr, offset, size, link, info,
        #            addralign, entsize  (10 field)
        # ELF32 sh: name, type, flags, addr, offset, size, link, info,
        #            addralign, entsize  (10 field — urutan sama)
        strtab_off = raw[e_shstrndx][4]
        strtab_size = raw[e_shstrndx][5]
        strtab = data[strtab_off:strtab_off + strtab_size]
        out: dict[str, tuple[int, int]] = {}
        for sh in raw:
            name_off, sh_type, _fl, _ad, sh_off, sh_size = sh[:6]
            if sh_type == 8:  # SHT_NOBITS — tidak ada byte di file
                continue
            end = strtab.find(b"\x00", name_off)
            name = strtab[name_off:end].decode("ascii", "replace")
            if name:
                out[name] = (sh_off, sh_size)
        return out or None
    except (struct.error, IndexError):
        return None


def _section_for(sections: dict[str, tuple[int, int]] | None,
                 off: int) -> str | None:
    if not sections:
        return None
    for name, (sh_off, sh_size) in sections.items():
        if sh_off <= off < sh_off + sh_size:
            return name
    return None


def audit_binary(path: Path) -> tuple[list[dict], dict]:
    """Murni: satu binary -> (rows, meta). L0 inventaris URL (dgn
    offset), L1 lead secret (dgn offset). Fail-closed file hilang."""
    if not path.is_file():
        return [], {"error": f"file tidak ada: {path}"}
    try:
        if path.stat().st_size > MAX_FILE_BYTES:
            return [], {"error": f"file terlalu besar (> {MAX_FILE_BYTES}B)"}
        data = path.read_bytes()
    except OSError as exc:
        return [], {"error": repr(exc)[:120]}
    rel = path.name
    sections = _elf_sections(data)
    filetype = ("elf" if data[:4] == b"\x7fELF"
                else "pe" if data[:2] == b"MZ"
                else "macho" if data[:4] == b"\xcf\xfa\xed\xfe"
                or data[:4] == b"\xca\xfe\xba\xbe"
                else "lain")
    urls: dict[str, int] = {}
    secrets: dict[str, int] = {}
    n_strings = 0
    for off, s in _iter_matches(data):
        n_strings += 1
        m = _RE_URL.search(s)
        if m and m.group(0) not in urls:
            urls[m.group(0).rstrip(".,;")] = off + m.start()
        m2 = _RE_SECRET.search(s)
        if m2 and m2.group(0) not in secrets:
            secrets[m2.group(0)] = off + m2.start()
    rows: list[dict] = []
    if urls:
        items = [{"url": u, "offset_hex": hex(o),
                  "section": _section_for(sections, o)}
                 for u, o in sorted(urls.items(), key=lambda kv: kv[1])]
        rows.append(make_finding(
            tool="binary-strings-surface",
            title=f"{len(urls)} URL absolut ter-ekspos di binary",
            severity="info",
            description="URL literal di dalam binary (terbaca via "
                        "strings/analisis statis — lapisan pertama yang "
                        "dilihat siapa pun): "
                        + ", ".join(u for u, _ in
                                    [(i["url"], 0) for i in items[:10]])
                        + ("…" if len(items) > 10 else ""),
            recommendation="", cwe=None, target_url=f"binary:{rel}",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "SURFACE", "kind": "urls",
                   "items": items[:MAX_ROWS]}))
    for s, off in sorted(secrets.items(), key=lambda kv: kv[1]):
        rows.append(make_finding(
            tool="binary-strings-surface",
            title="Kandidat secret ber-format layanan di binary",
            severity="medium",
            description=f"String cocok format kunci layanan "
                        f"({s[:8]}…) pada offset {hex(off)} — verifikasi "
                        "manual: nyata, placeholder, atau sisa build.",
            recommendation="Jangan embed kredensial di binary; rotasi "
                           "bila nyata; pindahkan ke server-side.",
            cwe="CWE-798", target_url=f"binary:{rel}",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=1,
            extra={"category": "EXPOSURE", "kind": "secret-literal",
                   "preview": s[:8] + "…", "offset_hex": hex(off),
                   "section": _section_for(sections, off)}))
    if not rows:
        rows.append(make_finding(
            tool="binary-strings-surface",
            title="Tidak ada URL/secret ter-ekspos di lapisan string",
            severity="info",
            description=f"{n_strings} string diperiksa — tanpa URL "
                        "absolut atau kandidat secret ber-format "
                        "(AMAN/inventaris; catatan: ini lapisan string "
                        "saja, bukan analisis disassembler).",
            target_url=f"binary:{rel}",
            evidence_kind="file-manifest", finding_class="posture",
            confidence=1.0, status="confirmed", verdict=0,
            extra={"category": "AMAN"}))
    meta = {"file": str(path), "filetype": filetype,
            "sections": len(sections) if sections else 0,
            "strings": n_strings, "urls": len(urls),
            "secrets": len(secrets),
            "exposures": sum(1 for r in rows
                             if r.get("category") == "EXPOSURE")}
    return rows, meta


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--file", required=True, help="file binary lokal")
    ap.add_argument("--out", default="findings/binary-surface.json")
    args = ap.parse_args()
    p = Path(args.file)
    if not p.is_file():
        print(f"file tidak ada: {p} (fail-closed)", file=sys.stderr)
        return 2
    rows, meta = audit_binary(p)
    write_findings(args.out, rows,
                   {**meta, "run": "binary-strings-surface",
                    "safety_class": "read-only", "requests": 0})
    print(f"binary-strings-surface: strings={meta['strings']} "
          f"urls={meta['urls']} secrets={meta['secrets']} -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

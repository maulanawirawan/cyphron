"""[SAFETY: read-only] pe_import_scan — triase statis PE (Windows
.exe/.dll/.sys): klasifikasi KEMAMPUAN dari import table (IAT), inspeksi
resource ter-embed (embedded PE / entropi tinggi), overlay (data setelah
section terakhir), dan anomali timestamp kompilasi. TANPA jaringan,
read-only — file sumber tidak pernah ditulis.

Ranah EKSPLISIT (pembagian dengan tool triase PE lain):
  - packer_scan (#0229)  : deteksi PACKING (entropi section, nama section
    packer, import minimal ala UPX) — di sini packing TIDAK dinilai ulang;
  - pe_mitigation_scan (#0131): mitigasi biner (DEP/ASLR/CFG) — di sini
    tidak disentuh;
  - binary_strings_surface: ekstraksi string/IOC dari berkas apa pun —
    di sini IOC string TIDAK diekstrak ulang;
  - carve_scan (#0817)   : carve blob mentah format-agnostic — di sini
    inspeksi SADAR-STRUKTUR PE (resource tree + overlay PE-nya sendiri).

Mekanisme:
  1. Header DOS/PE/COFF/Optional (PE32 & PE32+), tabel section (untuk
     pemetaan RVA -> offset file);
  2. IMPORT TABLE: IMAGE_IMPORT_DESCRIPTOR chain -> nama DLL + fungsi
     (thunk PE32 4-b / PE32+ 8-b, ordinal flag 0x80000000/0x8000000000)
     -> diklasifikasi ke klaster kemampuan (injection, evasion,
     keylogger, persistence-registry, persistence-service, network-
     download, network-socket, crypto) memakai tabel API ber-sinyal-
     tinggi sendiri; SATU fungsi mencurigakan = info (banyak API sah
     menyerupai), >=3 klaster berbeda = high-signal kombinasi dropper;
     jumlah import < 4 TIDAK dihitung di sini (ranah packer_scan);
  3. RESOURCE DIRECTORY (3 tingkat): entropi per resource + magic MZ di
     resource = embedded-PE high (pola dropper #0902); entropi > 7.2
     dengan ukuran >= 4 KB = payload-terenkripsi lead medium;
  4. OVERLAY: byte setelah akhir raw section terakhir — ukuran dicatat;
     magic terkenal di overlay (MZ/PK/Rar!/7z) = medium, overlay besar
     ber-entropi tinggi = lead low;
  5. TimeDateStamp: tahun < 2000 atau > tahun sekarang + 1 = low note
     (timestamp mudah dipalsukan — TIDAK pernah jadi temuan berdiri
     sendiri di atas low).

Anti-FP (disiplin NO-FP secai):
  - klaster network umum (WSAStartup/connect/getaddrinfo) TIDAK masuk
    tabel — hanya wininet/winhttp/URLDownloadToFile yang ber-sinyal;
  - klaster crypto sah banyak di aplikasi DRM/backup — crypto sendirian
    selalu info, bukan temuan;
  - overlay info-size TIDAK ditemukan bila file teks kecil atau overlay
    kosong; zero-temuan TIDAK diartikan "bersih" — output selalu bilang
    "diperiksa N aspek".

Fail-closed:
  - bukan MZ, e_lfanew di luar file, PE signature rusak, section table
    terpotong, import/resource directory RVA tak terpeta -> exit 2;
  - file terlalu besar (default 64 MB) -> exit 2;
  - ditemuan TIDAK memicu exit gagal otomatis; --fail-on <level|any>
    mengembalikan 1 bila temuan setinggi itu ada.

Pemakaian:
  python tools/pe_import_scan.py --source sample.exe
  python tools/pe_import_scan.py --source dir --out hasil.json --fail-on any
Exit: 0 selesai; 1 temuan >= --fail-on; 2 input/parse error.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import math
import struct
import sys
from pathlib import Path

SCHEMA = "secai.pe-import-scan/1"
MAX_FILE_BYTES = 64 * 1024 * 1024
DOS_MAGIC = 0x5A4D          # "MZ"
PE_SIGNATURE = 0x00004550   # "PE\0\0"
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664
OPT_MAGIC_PE32 = 0x10B
OPT_MAGIC_PE32PLUS = 0x20B
ORDINAL_FLAG32 = 0x80000000
ORDINAL_FLAG64 = 0x8000000000000000
SECTION_LIMIT = 96          # spesifikasi max 96; lebih = tidak lazim
DESCRIPTOR_LIMIT = 4096     # guard loop import descriptor
RESOURCE_LIMIT = 8192       # guard total node resource tree
OVERLAY_INFO_MIN = 64       # di bawah ini overlay dicatat sebagai info saja
OVERLAY_BIG = 256 * 1024    # overlay besar = lead
RESOURCE_ENTROPY_HIGH = 7.2
RESOURCE_ENTROPY_MIN_BYTES = 4096
HIGH_ENTROPY = 7.0          # ambang section/resource umum (spesifikasi #0902)

SUSPICIOUS_API: dict[str, tuple[str, str]] = {
    # api name (case-sensitive persis PE) -> (klaster, sinyal)
    "VirtualAllocEx": ("injection", "high"),
    "WriteProcessMemory": ("injection", "high"),
    "CreateRemoteThread": ("injection", "high"),
    "CreateRemoteThreadEx": ("injection", "high"),
    "NtCreateThreadEx": ("injection", "high"),
    "RtlCreateUserThread": ("injection", "high"),
    "NtUnmapViewOfSection": ("injection", "medium"),
    "NtMapViewOfSection": ("injection", "medium"),
    "IsDebuggerPresent": ("evasion", "medium"),
    "CheckRemoteDebuggerPresent": ("evasion", "medium"),
    "NtQueryInformationProcess": ("evasion", "medium"),
    "NtSetInformationThread": ("evasion", "medium"),
    "OutputDebugStringA": ("evasion", "low"),
    "OutputDebugStringW": ("evasion", "low"),
    "GetAsyncKeyState": ("keylogger", "medium"),
    "GetKeyState": ("keylogger", "low"),
    "MapVirtualKeyA": ("keylogger", "low"),
    "MapVirtualKeyW": ("keylogger", "low"),
    "GetKeyboardState": ("keylogger", "low"),
    "SetWindowsHookExA": ("keylogger", "medium"),
    "SetWindowsHookExW": ("keylogger", "medium"),
    "RegSetValueExA": ("registry-persist", "medium"),
    "RegSetValueExW": ("registry-persist", "medium"),
    "RegCreateKeyExA": ("registry-persist", "low"),
    "RegCreateKeyExW": ("registry-persist", "low"),
    "RegDeleteKeyA": ("registry-persist", "low"),
    "RegDeleteKeyW": ("registry-persist", "low"),
    "CreateServiceA": ("service-persist", "high"),
    "CreateServiceW": ("service-persist", "high"),
    "StartServiceA": ("service-persist", "medium"),
    "StartServiceW": ("service-persist", "medium"),
    "OpenSCManagerA": ("service-persist", "low"),
    "OpenSCManagerW": ("service-persist", "low"),
    "URLDownloadToFileA": ("network-download", "high"),
    "URLDownloadToFileW": ("network-download", "high"),
    "InternetOpenA": ("network-download", "medium"),
    "InternetOpenW": ("network-download", "medium"),
    "InternetConnectA": ("network-download", "medium"),
    "InternetConnectW": ("network-download", "medium"),
    "HttpSendRequestA": ("network-download", "medium"),
    "HttpSendRequestW": ("network-download", "medium"),
    "WinHttpConnect": ("network-download", "medium"),
    "WinHttpSendRequest": ("network-download", "medium"),
    "WinExec": ("process-exec", "medium"),
    "ShellExecuteA": ("process-exec", "low"),
    "ShellExecuteW": ("process-exec", "low"),
    "CreateProcessA": ("process-exec", "low"),
    "CreateProcessW": ("process-exec", "low"),
    "CryptEncrypt": ("crypto", "low"),
    "CryptDecrypt": ("crypto", "low"),
    "CryptAcquireContextA": ("crypto", "low"),
    "CryptAcquireContextW": ("crypto", "low"),
    "BCryptEncrypt": ("crypto", "low"),
    "BCryptDecrypt": ("crypto", "low"),
}

CLUSTER_SIGNAL_WEIGHT = {"high": 3, "medium": 2, "low": 1}
# kombinasi klaster yang secara historis ber-sinyal tinggi
DROPPER_COMBOS = (
    frozenset({"injection", "network-download"}),
    frozenset({"network-download", "service-persist"}),
    frozenset({"injection", "evasion", "keylogger"}),
)
MAGIC_PROBES = (
    # minimal 4 byte — magic pendek (MZ/gzip) menimbulkan FP pada
    # overlay acak berukuran besar; magic MZ di resource tetap
    # diperiksa secara sadar-struktur (bukan probe overlay)
    ("zip", b"PK\x03\x04"),
    ("rar", b"Rar!\x1a\x07"),
    ("sevenzip", b"7z\xbc\xaf\x27\x1c"),
    ("cab", b"MSCF"),
)


def shannon_entropy(data: bytes) -> float:
    """Entropi Shannon byte 0..8.0 (fungsi sendiri, tanpa pefile)."""
    if not data:
        return 0.0
    counts: list[int] = [0] * 256
    for b in data:
        counts[b] += 1
    total = len(data)
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return ent


class PEFormatError(Exception):
    """Struktur PE tidak valid/truncated — fail-closed."""


class PEFile:
    """Parser PE/COFF minimal (stdlib struct) — read-only."""

    def __init__(self, data: bytes) -> None:
        self.data = data
        if len(data) < 64:
            raise PEFormatError("file lebih pendek dari header DOS 64-b")
        if data[0:2] != b"MZ":
            raise PEFormatError("magic MZ tidak ada — bukan PE")
        (self.e_lfanew,) = struct.unpack_from("<I", data, 0x3C)
        if self.e_lfanew < 64 or self.e_lfanew + 24 > len(data):
            raise PEFormatError(f"e_lfanew di luar file: {self.e_lfanew}")
        if struct.unpack_from("<I", data, self.e_lfanew)[0] != PE_SIGNATURE:
            raise PEFormatError("signature PE tidak valid")
        coff_off = self.e_lfanew + 4
        if coff_off + 20 > len(data):
            raise PEFormatError("COFF header terpotong")
        (self.machine, self.num_sections, self.timestamp, _p, _o,
         opt_size, _chars) = struct.unpack_from("<HHIIIHH", data, coff_off)
        if self.num_sections > SECTION_LIMIT:
            raise PEFormatError(f"jumlah section tak lazim: "
                                f"{self.num_sections}")
        opt_off = coff_off + 20
        if opt_size == 0 or opt_off + opt_size > len(data):
            raise PEFormatError("optional header tidak ada/terpotong")
        (self.opt_magic,) = struct.unpack_from("<H", data, opt_off)
        if self.opt_magic == OPT_MAGIC_PE32PLUS:
            dd_off = opt_off + 112
            num_dd = (opt_size - 112) // 8
        elif self.opt_magic == OPT_MAGIC_PE32:
            dd_off = opt_off + 96
            num_dd = (opt_size - 96) // 8
        else:
            raise PEFormatError(
                f"optional header magic tak dikenal: {self.opt_magic:#x}")
        if num_dd < 16 or dd_off + 16 * 8 > len(data):
            raise PEFormatError("data directory kurang dari 16 entri")
        dd_values = struct.unpack_from("<16II", data, dd_off)
        self.datadir = list(zip(dd_values[0::2], dd_values[1::2]))
        sec_off = opt_off + opt_size
        if sec_off + self.num_sections * 40 > len(data):
            raise PEFormatError("section table terpotong")
        self.sections: list[dict] = []
        for i in range(self.num_sections):
            off = sec_off + i * 40
            name = data[off:off + 8].rstrip(b"\x00").decode(
                "ascii", errors="replace")
            vsize, va, rawsize, rawptr, = struct.unpack_from(
                "<IIII", data, off + 8)
            self.sections.append({
                "name": name, "virtual_size": vsize, "virtual_address": va,
                "raw_size": rawsize, "raw_pointer": rawptr,
            })

    def rva_to_offset(self, rva: int) -> int | None:
        """Pemetaan RVA -> offset file via section table (tanpa crafted
        section yang saling menimpa menghasilkan offset palsu)."""
        for s in self.sections:
            va = s["virtual_address"]
            span = max(s["virtual_size"], s["raw_size"])
            if va <= rva < va + span:
                delta = rva - va
                if delta >= s["raw_size"]:
                    return None  # menunjuk area tanpa data di file
                return s["raw_pointer"] + delta
        return None

    def read_at(self, off: int, size: int) -> bytes:
        if off < 0 or size < 0 or off + size > len(self.data):
            raise PEFormatError("baca di luar batas file")
        return self.data[off:off + size]


def parse_imports(pe: PEFile) -> list[dict]:
    """IMAGE_IMPORT_DESCRIPTOR chain -> list {dll, functions[]}.

    Fail-closed: RVA/offset di luar batas, chain tak berujung, atau
    thunk loop -> PEFormatError (bukan senyap)."""
    imp_rva, imp_size = pe.datadir[1]
    if imp_rva == 0 or imp_size == 0:
        return []
    base = pe.rva_to_offset(imp_rva)
    if base is None:
        raise PEFormatError("import directory RVA tidak terpeta ke file")
    is64 = pe.opt_magic == OPT_MAGIC_PE32PLUS
    ordinal_flag = ORDINAL_FLAG64 if is64 else ORDINAL_FLAG32
    thunk_size = 8 if is64 else 4
    thunk_fmt = "<Q" if is64 else "<I"
    out: list[dict] = []
    for i in range(DESCRIPTOR_LIMIT):
        desc_off = base + i * 20
        if desc_off + 20 > len(pe.data):
            raise PEFormatError("import descriptor terpotong")
        (oft_rva, _ts, _fc, name_rva,
         first_thunk_rva) = struct.unpack_from("<IIIII", pe.data, desc_off)
        if oft_rva == 0 and name_rva == 0 and first_thunk_rva == 0:
            break  # terminator null — akhir chain yang sah
        name_off = pe.rva_to_offset(name_rva)
        if name_off is None:
            raise PEFormatError(
                f"RVA nama DLL import tak terpeta: {name_rva:#x}")
        dll = pe.read_at(name_off, 256).split(b"\x00", 1)[0].decode(
            "ascii", errors="replace")
        thunk_rva = oft_rva or first_thunk_rva
        thunk_off = pe.rva_to_offset(thunk_rva)
        if thunk_off is None:
            raise PEFormatError(
                f"thunk RVA import tak terpeta: {thunk_rva:#x}")
        funcs: list[str] = []
        for j in range(DESCRIPTOR_LIMIT):
            toff = thunk_off + j * thunk_size
            if toff + thunk_size > len(pe.data):
                raise PEFormatError("thunk array import terpotong")
            (val,) = struct.unpack_from(thunk_fmt, pe.data, toff)
            if val == 0:
                break
            if val & ordinal_flag:
                funcs.append(f"#ordinal-{val & ~ordinal_flag}")
                continue
            hname_off = pe.rva_to_offset(val)
            if hname_off is None:
                raise PEFormatError(
                    f"RVA nama fungsi import tak terpeta: {val:#x}")
            # IMAGE_IMPORT_BY_NAME: hint 2-b lalu nama ASCII
            fname = pe.read_at(hname_off + 2, 256).split(b"\x00", 1)[0]
            funcs.append(fname.decode("ascii", errors="replace"))
        out.append({"dll": dll, "functions": funcs})
    return out


def classify_imports(imports: list[dict]) -> dict:
    """Klasifikasi fungsi import ke klaster kemampuan + temuan."""
    hits: list[dict] = []
    clusters: dict[str, list[str]] = {}
    best_signal: dict[str, str] = {}
    total_named = 0
    for entry in imports:
        total_named += len(entry["functions"])
        for fn in entry["functions"]:
            row = SUSPICIOUS_API.get(fn)
            if not row:
                continue
            cluster, signal = row
            hits.append({"dll": entry["dll"], "api": fn,
                         "cluster": cluster, "signal": signal})
            clusters.setdefault(cluster, []).append(fn)
            prev = best_signal.get(cluster)
            if prev is None or (CLUSTER_SIGNAL_WEIGHT[signal]
                                > CLUSTER_SIGNAL_WEIGHT[prev]):
                best_signal[cluster] = signal
    findings: list[dict] = []
    cluster_set = set(clusters)
    combo = next((c for c in DROPPER_COMBOS if c <= cluster_set), None)
    for cluster in sorted(clusters):
        sig = best_signal[cluster]
        if combo and cluster in combo and len(cluster_set) >= 3:
            level = "high"
            note = ("kombinasi kemampuan ber-sinyal-tinggi (pola dropper "
                    f"{'+'.join(sorted(combo))})")
        elif sig == "high":
            level = "high"
            note = "API kemampuan ber-sinyal-tinggi"
        elif sig == "medium":
            level = "medium"
            note = "API klaster ini umum juga di software sah (lead)"
        else:
            level = "info"
            note = "API di daftar pantau (banyak penggunaan sah)"
        findings.append({
            "id": f"iat-capability/{cluster}",
            "level": level,
            "apis": sorted(clusters[cluster]),
            "note": note,
        })
    return {
        "findings": findings,
        "total_imports": total_named,
        "clusters": sorted(cluster_set),
        "hits": hits,
    }


def parse_resources(pe: PEFile) -> list[dict]:
    """Resource directory 3-tingkat -> daftar {type, id, lang, size,
    entropy, embedded_pe} — bounds-checked penuh."""
    res_rva, res_size = pe.datadir[2]
    if res_rva == 0 or res_size == 0:
        return []
    root = pe.rva_to_offset(res_rva)
    if root is None:
        raise PEFormatError("resource directory RVA tidak terpeta")
    resources: list[dict] = []
    seen: set[int] = set()

    def walk_dir(dir_off: int, level: int, path: list[int]) -> None:
        if dir_off in seen:
            raise PEFormatError("resource directory cycle terdeteksi")
        seen.add(dir_off)
        if len(resources) + 1 > RESOURCE_LIMIT or len(seen) > RESOURCE_LIMIT:
            raise PEFormatError("resource tree melebihi batas wajar")
        if dir_off + 16 > len(pe.data):
            raise PEFormatError("resource directory terpotong")
        _chars, _ts, _mj, _mn, n_name, n_id = struct.unpack_from(
            "<IIHHHH", pe.data, dir_off)
        count = n_name + n_id
        if count > 8192:
            raise PEFormatError("jumlah entri resource tak lazim")
        for i in range(count):
            ent_off = dir_off + 16 + i * 8
            if ent_off + 8 > len(pe.data):
                raise PEFormatError("entri resource terpotong")
            (name_or_id, offset_field) = struct.unpack_from(
                "<II", pe.data, ent_off)
            val = name_or_id & 0x7FFFFFFF
            if offset_field & 0x80000000:
                sub_off = root + (offset_field & 0x7FFFFFFF)
                if level >= 2:
                    raise PEFormatError(
                        "resource tree lebih dalam dari 3 tingkat")
                walk_dir(sub_off, level + 1, path + [val])
            else:
                data_rva, data_size = struct.unpack_from(
                    "<II", pe.data, root + offset_field)
                d_off = pe.rva_to_offset(data_rva)
                if d_off is None or d_off + data_size > len(pe.data):
                    raise PEFormatError("data resource di luar file")
                blob = pe.read_at(d_off, data_size)
                resources.append({
                    "path": path + [val],
                    "size": data_size,
                    "entropy": round(shannon_entropy(blob), 3),
                    "embedded_pe": blob[:2] == b"MZ",
                })

    walk_dir(root, 0, [])
    return resources


def scan(source: Path) -> dict:
    """Scan satu file PE -> dict hasil lengkap (raise PEFormatError)."""
    raw = source.read_bytes()
    if len(raw) > MAX_FILE_BYTES:
        raise PEFormatError(f"file terlalu besar (> {MAX_FILE_BYTES} byte)")
    pe = PEFile(raw)
    if not pe.sections:
        raise PEFormatError("PE tanpa section — tidak valid untuk triase")

    findings: list[dict] = []
    imp = parse_imports(pe)
    cls = classify_imports(imp)

    resources = parse_resources(pe)
    embedded = [r for r in resources if r["embedded_pe"]]
    hot = [r for r in resources if r["entropy"] >= RESOURCE_ENTROPY_HIGH
           and r["size"] >= RESOURCE_ENTROPY_MIN_BYTES]
    for r in embedded:
        findings.append({
            "id": "resource/embedded-pe",
            "level": "high",
            "resource_path": r["path"],
            "size": r["size"],
            "note": "resource berisi image PE ter-embed (pola dropper)",
        })
    for r in hot:
        if any(r["path"] == e["path"] for e in embedded):
            continue
        findings.append({
            "id": "resource/high-entropy",
            "level": "medium",
            "resource_path": r["path"],
            "size": r["size"],
            "entropy": r["entropy"],
            "note": "resource ber-entropi tinggi (payload terenkripsi/"
                    "terkompresi — lead)",
        })

    # overlay: byte setelah akhir raw section terakhir
    raw_end = max((s["raw_pointer"] + s["raw_size"])
                  for s in pe.sections) if pe.sections else 0
    overlay = raw[raw_end:] if raw_end < len(raw) else b""
    overlay_sig = next(
        ({"kind": k, "at": overlay.find(m)} for k, m in MAGIC_PROBES
         if overlay.find(m) != -1), None)
    o_ent = shannon_entropy(overlay) if overlay else 0.0
    if overlay and len(overlay) >= OVERLAY_INFO_MIN:
        if overlay_sig:
            findings.append({
                "id": "overlay/known-signature",
                "level": "medium",
                "size": len(overlay),
                "signature": overlay_sig["kind"],
                "offset": raw_end + overlay_sig["at"],
                "note": "signature berkas dikenal di overlay PE",
            })
        elif len(overlay) >= OVERLAY_BIG and o_ent >= HIGH_ENTROPY:
            findings.append({
                "id": "overlay/high-entropy",
                "level": "low",
                "size": len(overlay),
                "entropy": round(o_ent, 3),
                "note": "overlay besar ber-entropi tinggi (lead — bisa "
                        "sah: katalog installer, tanda tangan)",
            })
        else:
            findings.append({
                "id": "overlay/present",
                "level": "info",
                "size": len(overlay),
                "entropy": round(o_ent, 3),
                "note": "overlay ada — diperiksa tanpa signature dikenal",
            })

    # timestamp anomaly: <2000 atau > tahun sekarang + 1 (mudah dipalsukan)
    year = 1970 + pe.timestamp // 31556926 if pe.timestamp else 1970
    now_year = dt.datetime.now(dt.timezone.utc).year
    if pe.timestamp == 0:
        findings.append({
            "id": "timestamp/zero", "level": "info",
            "timestamp": 0,
            "note": "timestamp kompilasi nol — dihapus/dipalsukan",
        })
    elif year < 2000 or year > now_year + 1:
        findings.append({
            "id": "timestamp/anomali", "level": "low",
            "timestamp": pe.timestamp, "year": year,
            "note": "timestamp kompilasi di luar rentang wajar "
                    "(mudah dipalsukan — lead saja)",
        })

    findings = findings + cls["findings"]
    machine = {IMAGE_FILE_MACHINE_I386: "i386",
               IMAGE_FILE_MACHINE_AMD64: "amd64"}.get(pe.machine,
                                                      f"0x{pe.machine:04x}")
    return {
        "file": str(source),
        "format": {
            "machine": machine,
            "pe": "PE32+" if pe.opt_magic == OPT_MAGIC_PE32PLUS
            else "PE32",
            "sections": pe.num_sections,
            "compile_timestamp": pe.timestamp,
            "compile_year": year if pe.timestamp else None,
        },
        "imports": {
            "dll_count": len(imp),
            "total_imports": cls["total_imports"],
            "clusters": cls["clusters"],
            "hits": cls["hits"],
        },
        "resources": {
            "count": len(resources),
            "embedded_pe": len(embedded),
            "high_entropy": len(hot),
        },
        "overlay": {
            "size": len(overlay),
            "entropy": round(o_ent, 3),
        },
        "findings": findings,
        "checked": ["imports", "resources", "overlay", "timestamp"],
        "summary": {
            "total": len(findings),
            "by_level": {
                lv: sum(1 for f in findings if f["level"] == lv)
                for lv in ("high", "medium", "low", "info")
            },
        },
    }


LEVEL_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


def _parse_args(argv: "list[str] | None" = None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(
        description="pe_import_scan — triase statis PE: klasifikasi "
                    "kemampuan IAT, resource ter-embed, overlay, timestamp "
                    "(read-only, nol jaringan, fail-closed).")
    ap.add_argument("--source", required=True,
                    help="berkas PE atau direktori berisi PE")
    ap.add_argument("--fail-on", choices=("any", "high", "medium", "low"),
                    help="exit 1 bila ada temuan setinggi itu")
    ap.add_argument("--out", help="tulis hasil JSON ke file")
    return ap.parse_args(argv)


def main(argv: "list[str] | None" = None) -> int:
    args = _parse_args(argv)
    src = Path(args.source)
    if not src.exists():
        print(f"[pe-import-scan] source tidak ada: {src}", file=sys.stderr)
        return 2
    targets = ([src] if src.is_file()
               else sorted(p for p in src.iterdir() if p.is_file()))
    if not targets:
        print("[pe-import-scan] tidak ada file untuk dipindai",
              file=sys.stderr)
        return 2

    results: list[dict] = []
    for path in targets:
        try:
            results.append(scan(path))
        except PEFormatError as exc:
            print(f"[pe-import-scan] {path.name}: BUKAN/bukan-PE valid: "
                  f"{exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"[pe-import-scan] {path.name}: gagal baca: {exc}",
                  file=sys.stderr)
            return 2

    out = {
        "schema": SCHEMA,
        "source": str(src),
        "scanned": len(results),
        "results": results,
        "summary": {
            "total": sum(r["summary"]["total"] for r in results),
            "by_level": {
                lv: sum(r["summary"]["by_level"][lv] for r in results)
                for lv in LEVEL_ORDER
            },
        },
        "note": "zero-temuan = diperiksa, bukan klaim bersih; timestamp "
                "PE mudah dipalsukan (selalu lead).",
    }
    rendered = json.dumps(out, indent=2, ensure_ascii=False)
    if args.out:
        Path(args.out).write_text(rendered + "\n", encoding="utf-8")
    s = out["summary"]
    dist = ", ".join(f"{k}={v}" for k, v in s["by_level"].items())
    print(f"[pe-import-scan] {len(results)} file, {s['total']} temuan "
          f"({dist})")
    for res in results:
        for f in res["findings"]:
            extra = f" size={f['size']}" if "size" in f else ""
            print(f"  [{f['level']:6}] {res['file']}: {f['id']}{extra}")
    if args.fail_on:
        lvls = (["high", "medium", "low"] if args.fail_on == "any"
                else [LEVEL_ORDER[l] for l in
                      ["high", "medium", "low"]
                      if LEVEL_ORDER[l] >= LEVEL_ORDER[args.fail_on]])
        hit = any(f["level"] in lvls for res in results
                  for f in res["findings"])
        if hit:
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

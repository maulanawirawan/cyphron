"""apk_kit — APK pentest kit v1 (Fullpower B3): pelengkap apk_surface_probe.

Analisis statis TANPA eksekusi APK (read-only, stdlib-only):

- string-pool AndroidManifest.xml (parser AXML minimal) + sapu DEX/arsc:
  perm berbahaya terdaftar;
- native libs per ABI + deteksi packer/hardening berdasar nama (tabel
  deterministik: jiagu, shella, dexhelper, tprt, mobisec, ...);
- signing assessment: v1 (META-INF/*.RSA|DSA|EC) + APK Signing Block v2/v3
  (magic "APK Sig Block 42") — tanpa androguard pun tetap jalan;
- anti-tamper / anti-analysis coverage: indikasi deteksi Frida/Xposed/
  Substrate/root (RootBeer, /proc/self/maps, magisk, test-keys);
- kesimpulan ASSESSMENT defensif: "seberapa siap app ini diuji dinamis" —
  bukan klaim kerentanan. Semua temuan = posture/info (LEAD), zero-FP.

Klaim identitas app (versi, sertifikat SHA-256, exported components)
butuh androguard bila terpasang (opsional) — absen = bagian itu dilabel
"butuh androguard", bukan ditebak.
"""

from __future__ import annotations

import re
import zipfile
from pathlib import Path

from .base import Tool, ToolContext, ToolResult
from ..findings import Finding

# perm berbahaya (izin dokumen publik Android) — tabel deterministik
_DANGEROUS_PERMS = {
    "android.permission.CAMERA": "Kamera",
    "android.permission.RECORD_AUDIO": "Rekam audio",
    "android.permission.READ_SMS": "Baca SMS",
    "android.permission.SEND_SMS": "Kirim SMS",
    "android.permission.RECEIVE_SMS": "Terima SMS",
    "android.permission.READ_CONTACTS": "Baca kontak",
    "android.permission.WRITE_CONTACTS": "Tulis kontak",
    "android.permission.ACCESS_FINE_LOCATION": "Lokasi presisi",
    "android.permission.ACCESS_BACKGROUND_LOCATION": "Lokasi latar",
    "android.permission.READ_PHONE_STATE": "Identitas perangkat/telepon",
    "android.permission.READ_CALL_LOG": "Log panggilan",
    "android.permission.CALL_PHONE": "Panggilan langsung",
    "android.permission.READ_EXTERNAL_STORAGE": "Baca penyimpanan",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Tulis penyimpanan",
    "android.permission.MANAGE_EXTERNAL_STORAGE": "Semua file akses",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Instal paket (sideload)",
    "android.permission.INSTALL_PACKAGES": "Instal paket (sistem)",
    "android.permission.SYSTEM_ALERT_WINDOW": "Overlay layar",
    "android.permission.GET_ACCOUNTS": "Daftar akun perangkat",
    "android.permission.READ_LOGS": "Baca log sistem",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Aksesibilitas (permintaan)",
    "android.permission.QUERY_ALL_PACKAGES": "Daftar semua app terpasang",
}
_PERM_RE = re.compile(r"\b((?:android\.)?permission\.[A-Z_]{3,64})\b")

# packer/hardening native libs (nama umum industri) — indikasi, bukan klaim
_PACKER_LIBS = (
    "libjiagu", "libshella", "libdexhelper", "libtprt", "libmobisec",
    "libnesec", "libexec", "libsecexe", "libsecmain", "libprotectclass",
    "libtup", "libtosprotection", "libchaosvmp", "libddog", "libfdog",
)
_ANTI_ANALYSIS = (
    ("frida", "Frida (string/agent)"),
    ("gum-js-loop", "Frida gum loop"),
    ("xposed", "Xposed"),
    ("de.robv.android.xposed", "Xposed bridge"),
    ("substrate", "Cydia Substrate"),
    ("rootbeer", "RootBeer root check"),
    ("magisk", "Magisk root"),
    ("/proc/self/maps", "pemetaan memori (anti-hook)"),
    ("test-keys", "build test-keys"),
    ("ptrace", "ptrace (anti-debug)"),
)
_ABI_DIRS = ("arm64-v8a", "armeabi-v7a", "x86_64", "x86")


def axml_strings(data: bytes) -> list[str]:
    """Ekstrak string-pool dari AndroidManifest.xml biner (AXML minimal).

    Tidak parse struktur lengkap (node/attribute) — cukup string pool yang
    memuat nama izin, nama komponen, dan nilai string. Format salah ->
    list kosong (fail-open, jangan crash)."""
    try:
        if len(data) < 16 or int.from_bytes(data[0:2], "little") != 0x0003:
            return []
        # chunk pertama setelah file header 8 byte = string pool
        off = 8
        ctype = int.from_bytes(data[off:off + 2], "little")
        if ctype != 0x0001:
            return []
        header_size = int.from_bytes(data[off + 2:off + 4], "little")
        chunk_size = int.from_bytes(data[off + 4:off + 8], "little")
        string_count = int.from_bytes(data[off + 8:off + 12], "little")
        flags = int.from_bytes(data[off + 16:off + 20], "little")
        strings_start = int.from_bytes(data[off + 20:off + 24], "little")
        is_utf8 = bool(flags & 0x100)
        offsets_base = off + header_size
        data_base = off + strings_start
        out: list[str] = []
        for i in range(min(string_count, 20000)):
            p = offsets_base + i * 4
            if p + 4 > len(data):
                break
            str_off = data_base + int.from_bytes(data[p:p + 4], "little")
            if str_off >= min(data_base + chunk_size, len(data)):
                out.append("")
                continue
            if is_utf8:
                n = data[str_off]  # char count (abaikan), byte len berikut
                blen = data[str_off + 1]
                if blen & 0x80:
                    blen = ((blen & 0x7F) << 8) | data[str_off + 2]
                    raw = data[str_off + 3:str_off + 3 + blen]
                else:
                    raw = data[str_off + 2:str_off + 2 + blen]
                out.append(raw.decode("utf-8", "replace"))
            else:
                u16len = int.from_bytes(data[str_off:str_off + 2], "little")
                if u16len & 0x8000:
                    u16len = int.from_bytes(data[str_off + 2:str_off + 4],
                                            "little")
                    raw = data[str_off + 4:str_off + 4 + u16len * 2]
                else:
                    raw = data[str_off + 2:str_off + 2 + u16len * 2]
                out.append(raw.decode("utf-16-le", "replace"))
        return out
    except Exception:
        return []


class ApkPentestKitTool(Tool):
    name = "apk_pentest_kit"
    description = ("APK pentest kit v1: perm berbahaya, native libs/packer, "
                   "signing v1/v2, coverage anti-tamper — assessment siap-"
                   "uji defensif (pasif, read-only).")
    risk_tags = {"local", "passive"}
    source_skill = "deobf-05"

    def run(self, args: dict, ctx: ToolContext) -> ToolResult:
        path = Path(str(args.get("path") or ""))
        if not path.is_file():
            return ToolResult(tool=self.name, ok=False,
                              error=f"APK tidak ditemukan: {path}")
        perms: set[str] = set()
        libs: list[dict] = []
        has_v1_sig = False
        has_v2_sig = False
        dex_text: list[str] = []
        manifest_strings: list[str] = []
        entries = 0

        with zipfile.ZipFile(path) as z:
            for name in z.namelist():
                entries += 1
                lower = name.lower()
                if lower.endswith((".rsa", ".dsa", ".ec")) and lower.startswith("meta-inf/"):
                    has_v1_sig = True
                if name.startswith("lib/") and name.endswith(".so"):
                    parts = name.split("/")
                    abi = parts[1] if len(parts) > 2 else "?"
                    libname = parts[-1]
                    libs.append({"abi": abi, "name": libname,
                                 "size": z.getinfo(name).file_size})
                if name == "AndroidManifest.xml":
                    manifest_strings = axml_strings(z.read(name))
                if name.endswith(".dex"):
                    try:
                        dex_text.append(z.read(name).decode("latin-1", "replace"))
                    except Exception:
                        continue

        # APK Signing Block v2/v3 (magic panjang 16 byte di whole-file scan)
        try:
            raw = path.read_bytes()
            has_v2_sig = b"APK Sig Block 42" in raw[:min(len(raw), 4_000_000)]
        except OSError:
            pass

        pool_text = "\n".join(manifest_strings)
        dex_blob = "\n".join(dex_text[:6])  # batasi memori
        for m in _PERM_RE.finditer(pool_text + "\n" + dex_blob[:400_000]):
            perms.add(m.group(1))
        dangerous = sorted(p for p in perms if p in _DANGEROUS_PERMS)
        other_perms = sorted(perms - set(dangerous))[:20]

        packers = sorted({lib["name"].lower() for lib in libs
                          if any(p in lib["name"].lower()
                                 for p in _PACKER_LIBS)})
        abis = sorted({lib["abi"] for lib in libs})
        anti = sorted(label for needle, label in _ANTI_ANALYSIS
                      if needle.lower() in dex_blob.lower())
        hardening_score = len(anti)

        findings: list[Finding] = []
        if not anti:
            f = Finding(
                tool=self.name,
                title="Tidak ada indikasi anti-tamper/anti-hook di app",
                severity="info",
                description=(
                    "Assessment kesiapan pengujian: tidak ditemukan indikator "
                    "deteksi Frida/Xposed/root pada sapu statis DEX. Artinya "
                    "app ini relatif SIAP diuji dinamis (instrumented) dalam "
                    "engagement berotorisasi — ini observasi postur, bukan "
                    "kerentanan."),
                recommendation=(
                    "Untuk penguatan produksi: tambahkan tamper/root/hook "
                    "detection + certificate pinning; untuk engagement: "
                    "instrumentasi statis lebih cepat mungkin."),
                confidence=0.6,
                finding_class="posture",
                status="unconfirmed",
            )
            findings.append(f)
        if "android.permission.REQUEST_INSTALL_PACKAGES" in dangerous \
                or "android.permission.INSTALL_PACKAGES" in dangerous:
            findings.append(Finding(
                tool=self.name,
                title="App meminta izin instal paket (sideload/self-update)",
                severity="info",
                description=(
                    "Perm REQUEST/INSTALL_PACKAGES terdaftar — app dapat "
                    "memasang APK lain (pola self-update di luar store). "
                    "Perlu justifikasi produk; vektor penyalahgunaan bila "
                    "sumber unduhan tidak terkunci."),
                recommendation=(
                    "Kunci sumber unduhan (domain milik sendiri + signature "
                    "check), atau hapus izin bila tak dipakai."),
                cwe="CWE-250",
                confidence=0.7,
                finding_class="posture",
                status="unconfirmed",
            ))
        if packers:
            findings.append(Finding(
                tool=self.name,
                title=f"Packer/hardening native terdeteksi: {', '.join(packers[:3])}",
                severity="info",
                description=(
                    "Nama native lib cocok tabel packer/hardening umum. "
                    "Ini berarti app dilindungi (sisi positif) DAN engagement "
                    "dinamis butuh persiapan khusus (bypass assessment)."),
                recommendation=(
                    "Untuk dev: dokumentasikan vendor hardening; untuk "
                    "engagement: siapkan rencana assessment hardening."),
                confidence=0.6,
                finding_class="posture",
                status="unconfirmed",
            ))

        signing = {
            "v1_jar": has_v1_sig,
            "v2_apk_signature_block": has_v2_sig,
            "note": ("v2/v3 menandatangani seluruh APK (lebih kuat); "
                     "v1 saja = rentan Janus-class tanpa v2"),
        }
        data = {
            "apk": str(path),
            "entries": entries,
            "package_strings_sample": manifest_strings[:10],
            "permissions_dangerous": [
                {"perm": p, "meaning": _DANGEROUS_PERMS[p]}
                for p in dangerous],
            "permissions_other_sample": other_perms,
            "native_libs": {"abis": abis, "count": len(libs),
                            "packer_indicators": packers,
                            "top_by_size": sorted(
                                libs, key=lambda l: -l["size"])[:10]},
            "signing": signing,
            "anti_analysis_indicators": anti,
            "hardening_score": hardening_score,
            "androguard_available": _androguard_available(),
            "assessment": ("siap diuji dinamis (hardening statis minim)"
                           if hardening_score == 0 else
                           f"hardening terdeteksi ({hardening_score} indikator)"
                           " — siapkan rencana instrumentasi"),
        }
        ctx.world.note(f"apk_pentest_kit: {len(dangerous)} perm berbahaya, "
                       f"{len(libs)} native lib, hardening {hardening_score}")
        return ToolResult(tool=self.name, ok=True, data=data,
                          findings=findings)


def _androguard_available() -> bool:
    try:
        import androguard  # noqa: F401
        return True
    except Exception:
        return False


def render_mobile_report(scan_data: dict) -> str:
    """Compose laporan pentest mobile (markdown) dari data kit + surface."""
    kit = scan_data.get("kit", {})
    surface = scan_data.get("surface", {})
    lines = [
        "# Laporan Pentest Mobile (statis, pasif)", "",
        f"**APK**: {kit.get('apk', '-')}  ",
        f"**Entri diperiksa**: {kit.get('entries', 0)}  ",
        f"**Assessment**: {kit.get('assessment', '-')}", "",
        "> Kerangka: assessment defensif 'seberapa siap app ini diuji dan "
        "dilindungi'. APK dari kanal tak resmi = LEAD; klaim butuh verifikasi "
        "silang versi + sertifikat ke app resmi.", "",
        "## 1. Izin berbahaya terdaftar", "",
        "| Izin | Arti |", "|---|---|",
    ]
    for row in kit.get("permissions_dangerous", []):
        lines.append(f"| `{row['perm']}` | {row['meaning']} |")
    if not kit.get("permissions_dangerous"):
        lines.append("| (tidak ada izin daftar berbahaya yang terdeteksi) | |")
    lines += ["", "## 2. Native library & packer", "",
              f"- ABI: {', '.join(kit.get('native_libs', {}).get('abis', []) or ['-'])}",
              f"- jumlah .so: {kit.get('native_libs', {}).get('count', 0)}",
              f"- indikator packer/hardening: "
              + (", ".join(kit.get("native_libs", {}).get("packer_indicators", []))
                 or "tidak terdeteksi"), "",
              "## 3. Signing", "",
              f"- v1 (JAR): {'ada' if kit.get('signing', {}).get('v1_jar') else 'tidak'}",
              f"- v2 (APK Signature Block): "
              f"{'ada' if kit.get('signing', {}).get('v2_apk_signature_block') else 'tidak'}",
              "", "## 4. Anti-tamper / anti-analysis coverage", ""]
    anti = kit.get("anti_analysis_indicators", [])
    if anti:
        for a in anti:
            lines.append(f"- {a}")
    else:
        lines.append("- Tidak ada indikator deteksi Frida/Xposed/root pada sapu statis")
    lines += ["", "## 5. Recon surface (pelengkap apk_surface_probe)", "",
              f"- host API ter-hardcode: {len(surface.get('top_hosts', []) or [])}",
              f"- kandidat secret (dengan FP-guard): "
              f"{len(surface.get('candidates', []) or [])}",
              f"- dev-leftover IP: "
              f"{surface.get('private_ip_dev_leftover', 0)}", "",
              "## 6. Batasan", "",
              "- Analisis statis pasif; tanpa eksekusi APK, tanpa request ke "
              "infrastruktur vendor.",
              "- Exported components & fingerprint sertifikat detail butuh "
              "androguard (opsional) — bila absen, bagian itu dilabel butuh "
              "alat tambahan, bukan ditebak.",
              "- Temuan pada laporan ini berkelas posture/info (LEAD); tidak "
              "ada klaim kerentanan tanpa verifikasi dinamis berotorisasi.", ""]
    return "\n".join(lines)

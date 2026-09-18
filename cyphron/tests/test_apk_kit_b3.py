"""B3: APK pentest kit v1 — perm berbahaya (string-pool AXML), native libs/
packer, signing v1/v2, anti-tamper coverage, laporan mobile. APK sintetis."""

from __future__ import annotations

import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.apk_kit import ApkPentestKitTool, axml_strings, render_mobile_report
from cyphron.tools.base import ToolContext
from cyphron.world.model import WorldModel

# string-pool AXML mini yang sah (header 0x0003 + chunk 0x0001, UTF-16)
def _fake_axml(strings: list[str]) -> bytes:
    import struct
    body = b""
    offsets = []
    for s in strings:
        offsets.append(len(body))
        body += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(body) % 4:
        body += b"\x00"
    strings_start = 8 + 4 * len(strings) + 20
    header_size = 28
    chunk_size = strings_start + len(body)
    out = struct.pack("<IHHII", 0x00080003, 8, 0, 0, 0)[:8]
    out += struct.pack("<HHIIIIII", 0x0001, header_size, chunk_size,
                       len(strings), 0, 0x0000, strings_start, 0)
    out += b"".join(struct.pack("<I", o) for o in offsets)
    out += body
    return out


def _make_apk(path: Path, with_v2: bool = False):
    manifest = _fake_axml([
        "com.example.bankku",
        "android.permission.CAMERA",
        "android.permission.READ_SMS",
        "android.permission.REQUEST_INSTALL_PACKAGES",
        "android.permission.INTERNET",
        "com.example.bankku.MainActivity",
    ])
    dex = (b"android.permission.ACCESS_FINE_LOCATION "
           b"de.robv.android.xposed.XposedBridge "
           b"/proc/self/maps rootbeer frida "
           b"ro.build.tags=test-keys")
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", dex)
        z.writestr("lib/arm64-v8a/libjiagu.so", b"MZ-fake-elf" * 40)
        z.writestr("lib/armeabi-v7a/libnative.so", b"\x7fELF" * 30)
        z.writestr("META-INF/CERT.RSA", b"fake-signature-blob")
        if with_v2:
            z.comment = b"APK Sig Block 42"


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0)


class TestApkKit(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.addCleanup(self._td.cleanup)
        self.apk = Path(self._td.name) / "fake.apk"
        _make_apk(self.apk, with_v2=True)

    def test_axml_string_pool_diterjemahkan(self):
        import struct
        raw = self.apk.read_bytes()
        # baca langsung dari zip
        with zipfile.ZipFile(self.apk) as z:
            data = z.read("AndroidManifest.xml")
        strings = axml_strings(data)
        self.assertIn("com.example.bankku", strings)
        self.assertIn("android.permission.CAMERA", strings)

    def test_perm_native_signing_antitamper(self):
        res = ApkPentestKitTool().run({"path": str(self.apk)}, _ctx())
        self.assertTrue(res.ok, res.error)
        d = res.data
        perms = {r["perm"] for r in d["permissions_dangerous"]}
        self.assertIn("android.permission.CAMERA", perms)
        self.assertIn("android.permission.REQUEST_INSTALL_PACKAGES", perms)
        self.assertIn("android.permission.READ_SMS", perms)
        # dari DEX juga terbaca
        self.assertIn("android.permission.ACCESS_FINE_LOCATION", perms)
        # native libs
        self.assertEqual(set(d["native_libs"]["abis"]),
                         {"arm64-v8a", "armeabi-v7a"})
        self.assertIn("libjiagu.so", str(d["native_libs"]["packer_indicators"]))
        # signing: v1 ada (CERT.RSA), v2 terdeteksi via magic
        self.assertTrue(d["signing"]["v1_jar"])
        self.assertTrue(d["signing"]["v2_apk_signature_block"])
        # anti-tamper dari DEX
        self.assertTrue(any("Xposed" in a for a in d["anti_analysis_indicators"]))
        self.assertTrue(any("Frida" in a for a in d["anti_analysis_indicators"]))
        self.assertGreater(d["hardening_score"], 0)
        # temuan: installer perm + packer (tidak ada temuan 'tidak ada anti-tamper')
        titles = " | ".join(f.title for f in res.findings)
        self.assertIn("instal paket", titles)
        self.assertIn("Packer", titles)

    def test_app_tanpa_antitamper_dilabel_siap_diuji(self):
        apk2 = Path(self._td.name) / "clean.apk"
        with zipfile.ZipFile(apk2, "w") as z:
            z.writestr("AndroidManifest.xml", _fake_axml(
                ["com.example.kosong", "android.permission.INTERNET"]))
            z.writestr("classes.dex", b"dex polos tanpa indikator")
        res = ApkPentestKitTool().run({"path": str(apk2)}, _ctx())
        self.assertTrue(res.ok)
        self.assertEqual(res.data["hardening_score"], 0)
        self.assertIn("siap diuji dinamis", res.data["assessment"])
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].finding_class, "posture")
        self.assertEqual(res.findings[0].status, "unconfirmed")

    def test_mobile_report_markdown(self):
        res = ApkPentestKitTool().run({"path": str(self.apk)}, _ctx())
        md = render_mobile_report({"kit": res.data, "surface": {}})
        self.assertIn("# Laporan Pentest Mobile", md)
        self.assertIn("CAMERA", md)
        self.assertIn("Signing", md)
        self.assertIn("LEAD", md)
        self.assertIn("Batasan", md)

    def test_apk_tidak_ada(self):
        res = ApkPentestKitTool().run({"path": "nggak-ada.apk"}, _ctx())
        self.assertFalse(res.ok)
        self.assertIn("tidak ditemukan", res.error)

    def test_engine_terdaftar(self):
        names = {t.name for t in build_default_registry(_ctx()).all()}
        self.assertIn("apk_pentest_kit", names)


if __name__ == "__main__":
    unittest.main()

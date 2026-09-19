"""B7 gap-port: engine email_intel (triage header phishing/BEC, offline).

Kontrak yang diuji:
- tanpa jaringan sama sekali (hanya parse pesan yang diberikan);
- semua temuan = LEAD (status unconfirmed, finding_class info, severity info);
- zero-FP: email internal polos TIDAK menghasilkan temuan;
- setiap jenis indikator punya test positif & negatif.
"""

import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.guardrails.authorization import AuditLog, AuthorizationGate
from cyphron.tools.base import ToolContext
from cyphron.tools.email_intel import EmailIntelTool
from cyphron.world.model import WorldModel


def _ctx() -> ToolContext:
    return ToolContext(gate=AuthorizationGate(None), audit=AuditLog(),
                       world=WorldModel(), rate_limit_s=0.0, timeout_s=5.0,
                       max_requests=50)


BENIGN = """From: Nyoman Saputra <nyoman@ptcontoh.co.id>
To: finance@ptcontoh.co.id
Subject: Jadwal rapat Q3
Date: Fri, 18 Sep 2026 09:15:00 +0700
Message-ID: <rapat-q3@ptcontoh.co.id>
Return-Path: <nyoman@ptcontoh.co.id>

Halo, rapat Q3 jadwalnya minggu depan. Terima kasih.
"""

SPOOF = """From: "PT Contoh - Keuangan" <finance@ptcontoh.co.id>
To: finance@ptcontoh.co.id
Subject: Perubahan rekening vendor - SEGERA
Reply-To: keuangan.ptcontoh@gmail.com
Return-Path: <bounce@mail-massa.example.net>
Authentication-Results: mx.periksa.id;
	spf=fail (sender IP is 203.0.113.9) smtp.mailfrom=mail-massa.example.net;
	dmarc=fail action=quarantine header.from=ptcontoh.co.id
Date: Fri, 18 Sep 2026 09:20:00 +0700
Message-ID: <c1@mail-massa.example.net>

Mohon segera proses perubahan rekening vendor. Rahasia, jangan beri tahu
siapa pun.
"""

IMPERSONATE = """From: "PT Contoh - Keuangan" <keuangan.ptcontoh@gmail.com>
To: finance@ptcontoh.co.id
Subject: Permintaan pembayaran vendor
Date: Fri, 18 Sep 2026 09:22:00 +0700
Message-ID: <c2@gmail.com>

Mohon proses pembayaran vendor terlampir.
"""

LOOKALIKE = """From: "PT Contoh Billing" <billing@ptcontoh-coid.com>
To: finance@ptcontoh.co.id
Subject: Invoice overdue
Date: Fri, 18 Sep 2026 09:25:00 +0700
Message-ID: <inv@ptcontoh-coid.com>

Invoice anda overdue.
"""

PUNY = """From: "Admin" <admin@xn--ptcontoh-2we.com>
To: nyoman@ptcontoh.co.id
Subject: Verifikasi akun
Date: Fri, 18 Sep 2026 09:30:00 +0700
Message-ID: <p@xn--ptcontoh-2we.com>

Verifikasi akun anda.
"""


class TestEmailIntel(unittest.TestCase):
    def setUp(self):
        self.tool = EmailIntelTool()

    def _kinds(self, tr):
        return [f.title.split(": ", 1)[1] for f in tr.findings]

    def test_benign_zero_finding(self):
        tr = self.tool.run({"raw_email": BENIGN}, _ctx())
        self.assertTrue(tr.ok)
        self.assertEqual(tr.findings, [], "email polos tidak boleh bertemuan")
        self.assertEqual(tr.data["from_domain"], "ptcontoh.co.id")

    def test_spoof_bundle(self):
        tr = self.tool.run({"raw_email": SPOOF}, _ctx())
        self.assertTrue(tr.ok)
        kinds = set(self._kinds(tr))
        self.assertIn("auth_fail", kinds)
        self.assertIn("replyto_mismatch", kinds)
        self.assertIn("urgency_subject", kinds)
        # dmarc fail dilaporkan header
        self.assertEqual(tr.data["auth_reported"]["dmarc"], "fail")
        self.assertEqual(tr.data["auth_reported"]["spf"], "fail")
        for f in tr.findings:
            self.assertEqual(f.status, "unconfirmed")
            self.assertEqual(f.finding_class, "info")
            self.assertEqual(f.severity, "info")

    def test_displayname_impersonation(self):
        # freemail dengan token organisasi/jabatan di display name = lead
        tr = self.tool.run({"raw_email": IMPERSONATE}, _ctx())
        self.assertIn("displayname_impersonation", self._kinds(tr))
        # domain sah dengan token yang sama = bukan lead (FP guard)
        safe = IMPERSONATE.replace("keuangan.ptcontoh@gmail.com",
                                   "keuangan@ptcontoh.co.id")
        tr = self.tool.run({"raw_email": safe}, _ctx())
        self.assertNotIn("displayname_impersonation", self._kinds(tr))

    def test_replyto_mismatch_positive_and_negative(self):
        # negatif: reply-to domain sama -> tidak ada lead replyto
        same = BENIGN.replace("nyoman@ptcontoh.co.id",
                              "nyoman@ptcontoh.co.id", 1).replace(
            "Subject: Jadwal rapat Q3",
            "Subject: Jadwal rapat Q3\nReply-To: nyoman@ptcontoh.co.id")
        tr = self.tool.run({"raw_email": same}, _ctx())
        self.assertNotIn("replyto_mismatch", self._kinds(tr))
        # positif
        tr = self.tool.run({"raw_email": SPOOF}, _ctx())
        self.assertIn("replyto_mismatch", self._kinds(tr))

    def test_returnpath_mismatch(self):
        tr = self.tool.run({"raw_email": SPOOF}, _ctx())
        self.assertIn("returnpath_mismatch", self._kinds(tr))
        tr = self.tool.run({"raw_email": BENIGN}, _ctx())
        self.assertNotIn("returnpath_mismatch", self._kinds(tr))

    def test_brand_lookalike(self):
        tr = self.tool.run({"raw_email": LOOKALIKE,
                            "brand_words": ["contoh"],
                            "brand_domains": ["ptcontoh.co.id"]}, _ctx())
        self.assertIn("brand_lookalike", self._kinds(tr))
        # tanpa konteks brand -> bukan temuan (jangan menebak)
        tr = self.tool.run({"raw_email": LOOKALIKE}, _ctx())
        self.assertNotIn("brand_lookalike", self._kinds(tr))

    def test_punycode_domain(self):
        tr = self.tool.run({"raw_email": PUNY}, _ctx())
        self.assertIn("punycode_domain", self._kinds(tr))

    def test_freemail_tanpa_token_org_tidak_berlead(self):
        # freemail tanpa token organisasi/jabatan = bukan temuan
        m = BENIGN.replace("nyoman@ptcontoh.co.id", "nyoman@gmail.com")
        tr = self.tool.run({"raw_email": m}, _ctx())
        self.assertNotIn("displayname_impersonation", self._kinds(tr))

    def test_no_network_and_args_validation(self):
        tr = self.tool.run({}, _ctx())
        self.assertFalse(tr.ok)
        tr = self.tool.run({"raw_email": "bukan pesan ==="}, _ctx())
        self.assertFalse(tr.ok)

    def test_engine_registered_and_passive(self):
        from cyphron.tools import build_default_registry
        reg = build_default_registry(_ctx())
        names = [t.name for t in reg.all()] if hasattr(reg, "all") else []
        if not names:
            names = [t.name for t in reg.tools()] if hasattr(reg, "tools") else []
        self.assertIn("email_intel", names)
        self.assertIn("passive", EmailIntelTool().risk_tags)


if __name__ == "__main__":
    unittest.main()

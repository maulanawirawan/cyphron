"""Test linux_cis_audit (#0528) — nol jaringan, fixture konfigurasi inline."""

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tools"))

import linux_cis_audit as lca

GOOD_SSHD = """\
# sshd hardening acuan skill sumber 5.2
PermitRootLogin no
PasswordAuthentication no
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 60
MaxStartups 10:30:60
X11Forwarding no
AllowTcpForwarding no
LogLevel VERBOSE
ClientAliveInterval 300
ClientAliveCountMax 3
"""

BAD_SSHD = """\
PermitRootLogin yes
# PasswordAuthentication absen (default distro sering yes)
PermitEmptyPasswords yes
MaxAuthTries 6
LoginGraceTime 120
MaxStartups 30:30:60
X11Forwarding yes
AllowTcpForwarding yes
LogLevel INFO
ClientAliveInterval 0
Include /etc/ssh/sshd_config.d/*.conf
"""

GOOD_SYSCTL = """\
net.ipv4.ip_forward = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
"""

BAD_SYSCTL = """\
# komentar dilewati
net.ipv4.ip_forward = 1
net/ipv4/conf/all/accept_redirects = 1
net.ipv4.tcp_syncookies = 0
"""

BAD_PWQ = "minlen = 8\n# dcredit tidak diset\n"
GOOD_PWQ = "minlen = 14\ndcredit = -1\nucredit = -1\nocredit = -1\nlcredit = -1\n"

BAD_LDEFS = "PASS_MAX_DAYS 0\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 3\nENCRYPT_METHOD MD5\n"
GOOD_LDEFS = "PASS_MAX_DAYS 365\nPASS_MIN_DAYS 1\nPASS_WARN_AGE 7\nENCRYPT_METHOD SHA512\n"


class TestSshd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmp.cleanup()

    def _run(self, sshd=None, sysctl=None, pwq=None, ldefs=None, extra=None):
        argv: "list[str]" = []
        if sshd is not None:
            p = Path(self.tmp.name) / "sshd_config"
            p.write_text(sshd, encoding="utf-8")
            argv += ["--sshd", str(p)]
        if sysctl is not None:
            p = Path(self.tmp.name) / "sysctl.conf"
            p.write_text(sysctl, encoding="utf-8")
            argv += ["--sysctl", str(p)]
        if pwq is not None:
            p = Path(self.tmp.name) / "pwquality.conf"
            p.write_text(pwq, encoding="utf-8")
            argv += ["--pwquality", str(p)]
        if ldefs is not None:
            p = Path(self.tmp.name) / "login.defs"
            p.write_text(ldefs, encoding="utf-8")
            argv += ["--login-defs", str(p)]
        out = Path(self.tmp.name) / "r.json"
        argv += ["--out", str(out)] + (extra or [])
        rc = lca.main(argv)
        return rc, json.loads(out.read_text(encoding="utf-8"))

    def _by_check(self, rep):
        return {f["check"]: f for f in rep["findings"]}

    def test_good_sshd_clean(self):
        rc, rep = self._run(sshd=GOOD_SSHD)
        self.assertEqual(rc, 0)
        self.assertEqual(rep["summary"]["findings"], 0)

    def test_bad_sshd_all_fire(self):
        rc, rep = self._run(sshd=BAD_SSHD)
        self.assertEqual(rc, 1)
        checks = self._by_check(rep)
        self.assertEqual(checks["sshd-permitrootlogin"]["severity"], "high")
        self.assertIn("PasswordAuthentication tidak ditemukan",
                      checks["sshd-passwordauthentication"]["message"])
        self.assertEqual(checks["sshd-permitemptypasswords"]["severity"],
                         "high")
        self.assertIn("> 4", checks["sshd-maxauthtries"]["message"])
        self.assertIn("120", checks["sshd-login-gracetime"]["message"])
        self.assertIn("ambang awal 30 > 10",
                      checks["sshd-maxstartups"]["message"])
        self.assertEqual(checks["sshd-x11forwarding"]["severity"], "medium")
        self.assertEqual(checks["sshd-loglevel"]["severity"], "low")
        self.assertIn("Include", checks["sshd-include-unaudited"]["message"])

    def test_absent_sshd_params_fail_closed(self):
        rc, rep = self._run(sshd="Port 22\n")
        self.assertEqual(rc, 1)
        checks = self._by_check(rep)
        self.assertIn("sshd-permitrootlogin", checks)
        self.assertIn("sshd-passwordauthentication", checks)
        # absen default = medium (bukan high) untuk password auth
        self.assertEqual(checks["sshd-passwordauthentication"]["severity"],
                         "medium")

    def test_first_wins_semantics(self):
        # OpenSSH: nilai pertama menang — duplikat kedua tidak menutupi
        rc, rep = self._run(
            sshd="PermitRootLogin yes\nPermitRootLogin no\n")
        self.assertEqual(rc, 1)
        f = self._by_check(rep)["sshd-permitrootlogin"]
        self.assertIn("'yes'", f["message"])

    def test_sysctl_good_and_bad(self):
        rc, rep = self._run(sysctl=GOOD_SYSCTL)
        self.assertEqual(rc, 0)
        rc, rep = self._run(sysctl=BAD_SYSCTL)
        self.assertEqual(rc, 1)
        msgs = " | ".join(f["message"] for f in rep["findings"])
        # key slash dinormalisasi ke dotted
        self.assertIn("accept_redirects = 1", msgs)
        self.assertIn("ip_forward = 1", msgs)
        self.assertIn("tcp_syncookies = 0", msgs)
        # parameter yang absen juga dilaporkan (fail-closed)
        n_missing = sum(1 for f in rep["findings"]
                        if "tidak ditemukan" in f["message"])
        self.assertEqual(n_missing, 15)  # 18 param - 3 yang diberikan

    def test_pwquality(self):
        rc, rep = self._run(pwq=BAD_PWQ)
        self.assertEqual(rc, 1)
        checks = self._by_check(rep)
        self.assertIn("minlen = 8 < 14", checks["pwq-minlen"]["message"])
        # empat kelas credit = empat temuan bernama sama — hitung dari list
        n_credit = sum(1 for f in rep["findings"]
                       if f["check"] == "pwq-class-credit")
        self.assertEqual(n_credit, 4)
        rc, rep = self._run(pwq=GOOD_PWQ)
        self.assertEqual(rc, 0)

    def test_login_defs(self):
        rc, rep = self._run(ldefs=BAD_LDEFS)
        self.assertEqual(rc, 1)
        checks = self._by_check(rep)
        self.assertEqual(checks["ldefs-encrypt-method"]["severity"], "medium")
        rc, rep = self._run(ldefs=GOOD_LDEFS)
        self.assertEqual(rc, 0)

    def test_allow_check(self):
        rc, rep = self._run(sshd=BAD_SSHD,
                            extra=["--allow-check", "sshd-permitrootlogin"])
        self.assertNotIn("sshd-permitrootlogin",
                         self._by_check(rep))
        self.assertTrue(any("disaring" in n for n in rep["notes"]))

    def test_no_files_exit2(self):
        self.assertEqual(lca.main([]), 2)

    def test_unreadable_exit2_with_finding(self):
        rc, rep = self._run(sshd=GOOD_SSHD, extra=["--fail-on", "low"])
        # hapus file supaya run berikut gagal baca — pakai file khusus
        p = Path(self.tmp.name) / "hilang.conf"
        rc2 = lca.main(["--sshd", str(p),
                        "--out", str(Path(self.tmp.name) / "r2.json")])
        rep2 = json.loads((Path(self.tmp.name) / "r2.json")
                          .read_text(encoding="utf-8"))
        self.assertEqual(rc2, 1)  # input-unreadable high >= fail-on medium
        self.assertTrue(any(f["check"] == "input-unreadable"
                            for f in rep2["findings"]))

    def test_fail_on_low(self):
        rc, rep = self._run(sshd="LogLevel INFO\n", extra=["--fail-on", "low"])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()

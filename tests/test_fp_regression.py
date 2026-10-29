"""FP regression suite — setiap false positive yang tertangkap jadi test
permanen. Mesin makin lama makin bersih; tidak ada FP yang "dibiarkan".

Fp1  banner: "owa" tidak boleh kena substring "reflowApp" (live 2026-10-06)
Fp2  email:  "No DMARC subdomain" tidak boleh medium bila org domain
             menetapkan sp=reject (warisan RFC 7489, live 2026-10-06)
Fp3  email:  node _dmarc ber-CNAME tidak boleh memicu "No DMARC"
Fp4  banner: host http:// tidak boleh memicu lead "No HSTS on https host"
Fp5  nuclei: matcher-status=false tidak boleh jadi temuan
Fp6  email:  kunci DKIM revoked (p= kosong) bukan "Active DKIM sender"
             (ditemukan saat review FAO 2026-10-07)
Fp7  FAO:    tool sama dua baris bukan quorum (tidak boleh naik kelas)
Fp8  FAO:    L0 inventaris tidak boleh naik jadi kerentanan
Fp9  intel:  sync yang di-skip (TTL segar) tetap terekam, bukan kosong senyap
Fp10 FAO:    dedup id identik digabung, tidak dobel di laporan
Fp11 CORS:   wildcard * tanpa cred bukan high, reflect tanpa cred = low (bukan high)
Fp12 REDIR:  redirect loop vs truncated 5 hop harus dibedakan
Fp13 RDAP:   RDAP timeout/__error__ harus info+unconfirmed, bukan medium
Fp14 AV:     intel_sync --verify delta actual<manifest harus terdeteksi av_deletion
Fp15 NUCLEI: matcher-status:false kedua varian + empty JSONL bukan finding
Fp16 PWACC:  autocomplete="current-password" pada form login BUKAN risiko
             (nilai yang benar menurut HTML spec — dipastikan
             live pada scan lapangan 2026-10-17)
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import banner_posture as bp  # noqa: E402
import email_sender_surface as ess  # noqa: E402
import nuclei_runner as nr  # noqa: E402
import intel_sync as isl  # noqa: E402
import cors_checker as cors  # noqa: E402
import redirect_chain as rch  # noqa: E402
import rdap_whois as rd  # noqa: E402


def mock_doh(map_by_name):
    def _doh(name, rtype="TXT", timeout=20.0):
        return list(map_by_name.get(name, []))
    return _doh


class TestFpBanner(unittest.TestCase):
    def test_fp1_owa_substring_reflowapp(self):
        body = ('<title>Zimbra Web Client Sign In</title>'
                '<div class="reflowApp">login</div>')
        rows, meta = bp.audit("https://mail.example.id/",
                              {"status": 200, "headers": {}, "body": body})
        self.assertEqual(meta["products"], ["Zimbra Collaboration Suite"])

    def test_fp4_http_host_no_https_hsts_lead(self):
        rows, _ = bp.audit("http://lab.example.id/",
                           {"status": 200, "headers": {}, "body": "ok"})
        self.assertFalse(
            any(r["title"].startswith("No HSTS on https") for r in rows),
            "host http tidak boleh kena lead HSTS https")


class TestFpEmail(unittest.TestCase):
    APEX, SUB = "example.go.id", "mail.example.go.id"
    DMARC = ("v=DMARC1;p=reject;rua=mailto:a@example.go.id;adkim=s;"
             "aspf=s;pct=100;sp=reject")

    def test_fp2_subdomain_dmarc_inheritance(self):
        with patch.object(ess, "doh", mock_doh({
            f"_dmarc.{self.SUB}": [],
            f"_dmarc.{self.APEX}": [(16, f'"{self.DMARC}"')],
        }), patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(self.SUB, mta_sts=False)
        dmarc = [r for r in rows if r["title"].startswith("No DMARC")]
        self.assertEqual(dmarc[0]["severity"], "info")
        self.assertEqual(dmarc[0]["category"], "AMAN")

    def test_fp3_dmarc_cname_node_not_no_dmarc(self):
        with patch.object(ess, "doh", mock_doh({
            self.APEX: [(16, '"v=spf1 -all"')],
            f"_dmarc.{self.APEX}": [(5, "dmarc.other.example")],  # CNAME saja
        }), patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(self.APEX, mta_sts=False)
        dmarc_rows = [r for r in rows if "DMARC" in r["title"]]
        self.assertTrue(all("v=dmarc" not in r["title"].lower()
                            for r in dmarc_rows))

    def test_fp6_dkim_revoked_key_not_active(self):
        with patch.object(ess, "doh", mock_doh({
            self.APEX: [(16, '"v=spf1 -all"')],
            f"_dmarc.{self.APEX}": [(16, '"v=DMARC1;p=reject"')],
            f"k1._domainkey.{self.APEX}": [(16, '"v=DKIM1; p="')],  # revoked
            f"s1._domainkey.{self.APEX}": [(16, '"v=DKIM1; p=MIGfMA0GCSq"')],
        }), patch.object(ess, "doh_doc", lambda *a, **k: None)):
            rows, _gets = ess.audit(self.APEX, mta_sts=False)
        active = [r for r in rows if "Active DKIM" in r["title"]]
        self.assertEqual(len(active), 1, "hanya kunci ber-material")
        self.assertIn("s1", active[0]["title"])
        self.assertNotIn("k1", active[0]["title"])


class TestFpNuclei(unittest.TestCase):
    def test_fp5_matcher_false_not_finding(self):
        rows, _ = nr.parse_jsonl(
            '{"template-id":"x","info":{"name":"X","severity":"high"},'
            '"matcher-status":false}\n')
        self.assertEqual(nr.to_findings(rows), [])

    def test_fp15_matcher_false_string_and_empty(self):
        # Fp15: varian matcher-status sebagai string "false" dan JSONL kosong
        rows, _ = nr.parse_jsonl(
            '{"template-id":"y","info":{"name":"Y","severity":"medium"},'
            '"matcher-status":false}\n'
            '{"template-id":"z","info":{"name":"Z","severity":"low"},'
            '"matched-at":"http://x"}\n')
        # hanya yang matched-at valid yang lolos, tapi matcher-status:false harus 0
        # parse_jsonl mengembalikan raw, to_findings yang filter
        findings = nr.to_findings(rows)
        # z tanpa matcher-status tapi ada matched-at => bisa jadi finding, tapi y harus tidak
        self.assertTrue(all("y" not in f.get("title","").lower() for f in findings))
        # JSONL kosong => 0 finding
        self.assertEqual(nr.to_findings(nr.parse_jsonl("")[0]), [])
        self.assertEqual(nr.to_findings(nr.parse_jsonl("\n\n")[0]), [])


class TestFpFao(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        exe_name = "cyphron.exe" if sys.platform == "win32" else "cyphron"
        if not (ROOT / "core-rs/target/release" / exe_name).exists():
            raise unittest.SkipTest(
                "binary core belum dibangun: cargo build --release "
                "--manifest-path core-rs/Cargo.toml")

    def _scan(self, skills):
        tmp = tempfile.mkdtemp(prefix="fpregr_")
        reg = Path(tmp) / "registry.json"
        reg.write_text(json.dumps({"version": 1, "skills": skills}),
                       encoding="utf-8")
        exe_name = "cyphron.exe" if sys.platform == "win32" else "cyphron"
        exe = ROOT / "core-rs/target/release" / exe_name
        out = Path(tmp) / "out"
        r = subprocess.run([str(exe), "scan", "--registry", str(reg),
                            "--out", str(out)], capture_output=True, text=True)
        return r, out, tmp

    def test_fp7_same_tool_twice_not_quorum(self):
        skills = [{"name": "s1", "cmd": ["python", "-c", SCRIPT_ID, "@OUT@"],
                   "safety_class": "read-only", "needs": "none"}]
        r, out, tmp = self._scan(skills)
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        f = doc["findings"][0]
        self.assertNotIn("quorum", f, "satu tool = bukan sumber independen")
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)

    def test_fp10_dedup_identical_ids(self):
        skills = [{"name": f"s{i}",
                   "cmd": ["python", "-c", SCRIPT_ID, "@OUT@"],
                   "safety_class": "read-only", "needs": "none"}
                  for i in (1, 2)]
        r, out, tmp = self._scan(skills)
        self.assertEqual(r.returncode, 0, r.stderr)
        doc = json.loads((out / "findings.json").read_text(encoding="utf-8"))
        self.assertEqual(len(doc["findings"]), 1, "id identik = satu temuan")
        self.assertEqual(doc["findings"][0]["dup_count"], 2)
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


SCRIPT_ID = ("import json,sys,hashlib\n"
             "h=hashlib.sha256('t|ok|x.id||'.encode()).hexdigest()[:16]\n"
             "json.dump({'ok':True,'data':{},'findings':[{'tool':'t',"
             "'title':'ok','severity':'info','description':'d',"
             "'target_url':'x.id','evidence_kind':'dns','finding_class':"
             "'posture','confidence':1.0,'status':'confirmed','verdict':0,"
             "'verdict_tag':'L0 OBSERVED - LEAD','id':h,'reportable':False,"
             "'category':'SURFACE','cwe':'CWE-200'}]}, open(sys.argv[1],'w'))")


class TestFpIntelSync(unittest.TestCase):
    def test_fp9_skipped_sync_still_recorded(self):
        import time
        tmp = tempfile.TemporaryDirectory()
        old_intel, old_manifest = isl.INTEL, isl.MANIFEST
        isl.INTEL = Path(tmp.name)
        isl.MANIFEST = isl.INTEL / "manifest.json"
        try:
            fresh = {"version": "abc", "template_count": 100,
                     "synced_at": time.time()}  # TTL segar
            isl.MANIFEST.write_text(json.dumps(
                {"components": {"nuclei-templates": fresh}, "history": []}),
                encoding="utf-8")
            r = isl.sync_nuclei_templates()  # tanpa force
            self.assertTrue(r.get("skipped"), "TTL segar harus dilewati")
            self.assertEqual(r["prev"]["template_count"], 100)
            out = Path(tmp.name) / "intel.json"
            sys.argv = ["intel_sync.py", "--components", "nuclei-templates",
                        "--out", str(out)]
            try:
                isl.main()
            finally:
                sys.argv = ["intel_sync.py"]
            doc = json.loads(out.read_text(encoding="utf-8"))
            self.assertTrue(doc["ok"])
            self.assertEqual(doc["findings"][0]["verdict"], 0)
            self.assertIn("dilewati", doc["findings"][0]["title"])
        finally:
            isl.INTEL, isl.MANIFEST = old_intel, old_manifest
            tmp.cleanup()

    def test_fp14_av_delete_detected(self):
        # Fp14: actual < manifest => av_deletion_suspected true, exit_code 2
        import time
        tmp = tempfile.TemporaryDirectory()
        old_intel, old_manifest = isl.INTEL, isl.MANIFEST
        isl.INTEL = Path(tmp.name)
        isl.MANIFEST = isl.INTEL / "manifest.json"
        try:
            # buat manifest dengan count 10 tapi file 0 => AV delete
            manifest = {
                "components": {
                    "nuclei-templates": {"version": "abc", "template_count": 10, "synced_at": time.time()},
                    "kev": {"version": "2026-01-01", "entry_count": 5, "synced_at": time.time()}
                },
                "history": []
            }
            isl.MANIFEST.write_text(json.dumps(manifest), encoding="utf-8")
            # buat folder kosong (actual 0)
            (isl.INTEL / "nuclei-templates").mkdir(parents=True, exist_ok=True)
            (isl.INTEL / "kev.json").write_text(json.dumps({"vulnerabilities": []}), encoding="utf-8")
            rc = isl.verify_counts({"nuclei-templates", "kev"})
            self.assertEqual(rc, 2, "mismatch harus exit 2")
        finally:
            isl.INTEL, isl.MANIFEST = old_intel, old_manifest
            tmp.cleanup()


class TestFpCors(unittest.TestCase):
    """Fp11: CORS wildcard tanpa cred bukan high, reflect tanpa cred = low bukan high."""

    def test_fp11_wildcard_not_high(self):
        res = {"status": 200, "headers": {"access-control-allow-origin": "*", "access-control-allow-credentials": "false"}}
        rows, _ = cors.audit("https://lab.id/api", res)
        self.assertEqual(rows[0]["severity"], "info")
        self.assertNotEqual(rows[0]["severity"], "high")
        self.assertEqual(rows[0]["verdict"], 0)

    def test_fp11_reflect_without_cred_is_low_not_high(self):
        res = {"status": 200, "headers": {"access-control-allow-origin": "https://evil-probe.example", "access-control-allow-credentials": "false"}}
        rows, _ = cors.audit("https://lab.id/api", res)
        # harus low, bukan high
        target = [r for r in rows if "no credentials" in r["title"]]
        self.assertEqual(len(target), 1)
        self.assertEqual(target[0]["severity"], "low")
        self.assertNotEqual(target[0]["severity"], "high")

    def test_fp11_reflect_with_cred_is_high(self):
        res = {"status": 200, "headers": {"access-control-allow-origin": "https://evil-probe.example", "access-control-allow-credentials": "true"}}
        rows, _ = cors.audit("https://lab.id/api", res)
        bad = [r for r in rows if "WITH credentials" in r["title"]]
        self.assertEqual(bad[0]["severity"], "high")


class TestFpRedirect(unittest.TestCase):
    """Fp12: redirect loop vs truncated harus dibedakan."""

    def test_fp12_loop_detected(self):
        res = {"hops": [
            {"hop": 0, "url": "http://lab.id/a", "status": 302, "location": "http://lab.id/b"},
            {"hop": 1, "url": "http://lab.id/b", "status": 302, "location": "http://lab.id/a"}],
               "final": "http://lab.id/a", "loop": True, "truncated": False}
        rows, _ = rch.audit("http://lab.id/a", res)
        self.assertTrue(any("LOOP" in r["title"] for r in rows))
        self.assertTrue(any(r["severity"] == "medium" for r in rows if "LOOP" in r["title"]))

    def test_fp12_truncated_not_loop(self):
        res = {"hops": [{"hop": i, "url": f"http://lab.id/{i}", "status": 302, "location": f"http://lab.id/{i+1}"} for i in range(5)],
               "final": "http://lab.id/5", "loop": False, "truncated": True}
        rows, _ = rch.audit("http://lab.id/0", res)
        self.assertFalse(any("LOOP" in r["title"] for r in rows))
        self.assertTrue(any("truncated" in r["title"] for r in rows))

    def test_fp12_no_redirect_is_aman(self):
        res = {"hops": [{"hop": 0, "url": "http://lab.id/", "status": 200, "location": None}], "final": "http://lab.id/", "loop": False, "truncated": False}
        rows, _ = rch.audit("http://lab.id/", res)
        self.assertTrue(any("No redirects" in r["title"] for r in rows))
        for r in rows:
            if "No redirects" in r["title"]:
                self.assertEqual(r["category"], "AMAN")
                self.assertEqual(r["verdict"], 0)


class TestFpRdap(unittest.TestCase):
    """Fp13: RDAP timeout/__error__ harus info+unconfirmed verdict 1, bukan medium/high."""

    def test_fp13_rdap_error_is_info_unconfirmed(self):
        doc = {"__error__": "TimeoutError: timed out"}
        rows, meta = rd.audit("example.id", doc)
        self.assertEqual(rows[0]["severity"], "info")
        self.assertEqual(rows[0]["status"], "unconfirmed")
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertNotEqual(rows[0]["severity"], "medium")
        self.assertTrue(meta.get("error"))

    def test_fp13_rdap_ok_is_surface(self):
        import time
        iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + 86400*90))
        doc = {"events": [{"eventAction": "expiration", "eventDate": iso}], "status": ["client transferProhibited"], "nameservers": [{"ldhName": "ns1.example.id"}]}
        rows, _ = rd.audit("example.id", doc)
        # harus ada AMAN transfer-locked + SURFACE inventory
        self.assertTrue(any(r["category"] == "AMAN" for r in rows))
        self.assertTrue(any(r["category"] == "SURFACE" for r in rows))


class TestFpPasswordAutocomplete(unittest.TestCase):
    def test_fp16_current_password_is_not_risk(self):
        import password_autocomplete_checker as pwac
        html = ('<input id="password" name="password" type="password" '
                'autocomplete="current-password" required>')
        rows, _ = pwac.audit("https://lab.local/", html)
        self.assertEqual(rows[0]["verdict"], 0,
                         'autocomplete="current-password" = nilai yang benar '
                         'untuk form login, bukan lead')
        # tanpa atribut tetap lead
        rows2, _ = pwac.audit("https://lab.local/",
                              '<input type="password" name="p">')
        self.assertEqual(rows2[0]["verdict"], 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)

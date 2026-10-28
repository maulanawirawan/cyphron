"""Test F61 — Black October hardening: watchlist breaking-CVE +
gitlab-posture + beyondtrust-posture + KB GitLab/Node.

NOL jaringan (fetch/urlopen di-mock). Yang dikunci:
  - intel_sync: seed loader fail-closed (entri cacat ditolak), parser
    NVD defensif, sync_watchlist staging atomic + dedup seed/NVD,
    verify_counts watchlist;
  - cve-matcher: seed watchlist (token eksplisit) -> lead via
    "watchlist" MAKS L1 tanpa klaim versi; TIDAK mendobel KB/KEV;
    entri tanpa token/source_url ditolak;
  - gitlab-posture: marker 'gitlab' = L1 + fakta "gitlab <versi>"
    bersebelahan; rantai KB CVE-2026-110264 in-range (18.11.2) /
    out-of-range (19.5.1 = zero-FP); semua-probe-gagal = tanpa klaim
    AMAN;
  - beyondtrust-posture: token 'bomgar'/'beyondtrust' = L1; frasa
    generik 'remote support' SAJA = bukan marker (signature ketat);
    rantai alias KEV BeyondTrust::Remote Support + watchlist;
  - KB Node.js CVE-2026-111497: in-range/out-of-range/legacy EOL.
"""
from __future__ import annotations

import io
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import intel_sync  # noqa: E402
import cve_matcher as cm  # noqa: E402
import gitlab_posture as gp  # noqa: E402
import beyondtrust_posture as bp  # noqa: E402
from findings import validate_finding  # noqa: E402

KB = json.load(open(ROOT / "assets/intel/cve-kb.json",
                    encoding="utf-8"))["entries"]


def kb_valid():
    out = []
    for e in KB:
        fixed = cm.parse_version(str(e["fixed"]))
        if fixed is None:
            continue
        out.append({**e, "_product": cm.norm_text(e["product"]),
                    "_fixed": fixed,
                    "_introduced": (cm.parse_version(e["introduced"])
                                    if e.get("introduced") else None)})
    return out


def _fact_row(tool: str, text: str):
    return {"tool": tool, "response": text, "title": text,
            "status": "confirmed", "target_url": "http://t.local",
            "extra": {}}


# ---------------------------------------------------------------- intel

class _FakeResp(io.BytesIO):
    status = 200

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


NVD_DOC = {"vulnerabilities": [
    {"cve": {"id": "CVE-2026-99999",
             "published": "2026-10-20T10:00:00.000",
             "descriptions": [{"lang": "en", "value": "Critical flaw"}],
             "metrics": {"cvssMetricV31":
                         [{"cvssData": {"baseScore": 9.8}}]}},
     },
    {"cve": {"id": "CVE-2026-109618",
             "published": "2026-10-21T09:00:00.000",
             "descriptions": [{"lang": "en", "value": "php2shell"}],
             "metrics": {}},
     },  # duplikat seed -> difilter
]}

SEEDS_DOC = {"seeds": [
    {"cve": "CVE-2026-109618", "vendor": "PHP Group",
     "product": "PHP (php2shell)", "tokens": ["php"],
     "note": "php2shell", "source_url": "https://example.com/cisa",
     "added": "2026-10-26"},
    {"cve": "CVE-2026-110264", "vendor": "GitLab",
     "product": "GitLab CE/EE", "tokens": ["gitlab"],
     "note": "RCE CVSS 10.0", "source_url": "https://example.com/gl",
     "added": "2026-10-26"},
    {"cve": "CVE-2026-XXXXX", "product": "tanpa-token",
     "note": "cacat: tanpa tokens + source_url"},  # ditolak
]}


class IntelSyncWatchlistTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron-f61-"))
        self._old = {k: getattr(intel_sync, k)
                     for k in ("INTEL", "MANIFEST", "WATCHLIST_SEEDS",
                               "WATCHLIST_OUT")}
        intel_sync.INTEL = self.tmp
        intel_sync.MANIFEST = self.tmp / "manifest.json"
        intel_sync.WATCHLIST_SEEDS = self.tmp / "watchlist-seeds.json"
        intel_sync.WATCHLIST_OUT = self.tmp / "watchlist.json"
        (self.tmp / "watchlist-seeds.json").write_text(
            json.dumps(SEEDS_DOC), encoding="utf-8")

    def tearDown(self):
        for k, v in self._old.items():
            setattr(intel_sync, k, v)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_seed_loader_rejects_incomplete(self):
        seeds = intel_sync.load_watchlist_seeds()
        self.assertEqual([s["cve"] for s in seeds],
                         ["CVE-2026-109618", "CVE-2026-110264"])

    def test_sync_merges_seeds_and_nvd_with_dedup(self):
        with patch.object(intel_sync, "fetch",
                          lambda url, timeout=60.0:
                          json.dumps(NVD_DOC).encode()):
            res = intel_sync.sync_watchlist(force=True)
        self.assertTrue(res["synced"])
        self.assertEqual(res["seed_count"], 2)
        self.assertEqual(res["nvd_count"], 1)  # duplikat seed difilter
        wl = json.loads(
            intel_sync.WATCHLIST_OUT.read_text(encoding="utf-8"))
        self.assertEqual(wl["nvd_critical"][0]["cve"], "CVE-2026-99999")
        self.assertEqual(wl["nvd_critical"][0]["cvss"], 9.8)
        self.assertEqual(len(intel_sync.load_watchlist_seeds()), 2)

    def test_verify_counts_watchlist_ok_after_sync(self):
        with patch.object(intel_sync, "fetch",
                          lambda url, timeout=60.0:
                          json.dumps(NVD_DOC).encode()):
            intel_sync.sync_watchlist(force=True)
        rc = intel_sync.verify_counts({"watchlist"})
        self.assertEqual(rc, 0)

    def test_ttl_fresh_skips(self):
        with patch.object(intel_sync, "fetch",
                          lambda url, timeout=60.0:
                          json.dumps(NVD_DOC).encode()):
            intel_sync.sync_watchlist(force=True)
            res = intel_sync.sync_watchlist(False)
        self.assertTrue(res.get("skipped"))


# ------------------------------------------------------------- matcher

WL_DOC = {"seeds": SEEDS_DOC["seeds"]}


class MatcherWatchlistTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cyphron-f61b-"))
        self.wl_path = self.tmp / "watchlist.json"
        self.wl_path.write_text(json.dumps(WL_DOC), encoding="utf-8")
        self.wl, self.rejected = cm.load_watchlist(self.wl_path)
        self.assertEqual(len(self.wl), 2)
        self.assertEqual(len(self.rejected), 1)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_watchlist_lead_max_l1_no_version_claim(self):
        rows = [_fact_row("beyondtrust-posture",
                          "beyondtrust remote support 24.1.2 appliance")]
        out, meta = cm.match_cves(rows, [], [], [], None, self.wl)
        wl_rows = [r for r in out if r.get("via") == "watchlist"]
        # seed token 'php'/'gitlab' tidak kena; beyondtrust bukan seed
        # di fixture ini -> 0; pakai seed php utk uji jalur utama:
        rows2 = [_fact_row("banner-posture", "Server: Apache PHP/8.2.34")]
        out2, meta2 = cm.match_cves(rows2, [], [], [], None, self.wl)
        wl2 = [r for r in out2 if r.get("via") == "watchlist"]
        self.assertEqual({r["cve"] for r in wl2},
                         {"CVE-2026-109618"})
        self.assertTrue(all(r["verdict"] == 1 for r in wl2))
        self.assertTrue(all(not r["version_claim"] for r in wl2))
        self.assertTrue(all(validate_finding(r) == [] for r in out2))

    def test_watchlist_does_not_duplicate_kev(self):
        kev = [{"cveID": "CVE-2026-109618", "vendorProject": "PHP Group",
                "product": "PHP", "vulnerabilityName": "RCE",
                "knownRansomwareCampaignUse": "Unknown", "cwes": []}]
        rows = [_fact_row("banner-posture", "Server: Apache PHP/8.2.34")]
        out, meta = cm.match_cves(rows, kev, [], [], None, self.wl)
        self.assertEqual(meta["watchlist_matches"], 0)
        kev_rows = [r for r in out if r.get("cve") == "CVE-2026-109618"]
        self.assertEqual(len(kev_rows), 1)
        self.assertIn(kev_rows[0]["via"], ("direct", "alias:php"))

    def test_no_token_hit_is_silent(self):
        rows = [_fact_row("tech-fingerprint", "nginx openssh")]
        out, meta = cm.match_cves(rows, [], [], [], None, self.wl)
        self.assertEqual(meta["watchlist_matches"], 0)


# ------------------------------------------------------------ gitlab

GL_BODIES = {
    "/users/sign_in": "<html><title>Sign in · GitLab</title>"
                      "<meta content='GitLab 18.11.2'></html>",
    "/help": "<html>GitLab docs</html>",
    "/explore": "<html>Explore GitLab</html>",
}


class _UrlOpenMixin:
    def _patch(self, skill, bodies, status=200):
        def fake_urlopen(req, timeout=None):
            path = req.full_url.split("://", 1)[1]
            path = "/" + path.split("/", 1)[1] if "/" in \
                path.split("://", 1)[-1] else "/"
            for key, body in bodies.items():
                if path.startswith(key):
                    resp = _FakeResp(body.encode())
                    resp.status = status
                    resp.headers = {"content-type": "text/html"}
                    return resp
            resp = _FakeResp(b"not found")
            resp.status = 404
            resp.headers = {}
            return resp
        return patch.object(skill.urllib.request, "urlopen",
                            fake_urlopen)


class GitlabPostureTest(_UrlOpenMixin, unittest.TestCase):
    def test_marker_and_version_fact(self):
        with self._patch(gp, GL_BODIES):
            rows, meta = gp.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["18.11.2"])
        self.assertEqual(rows[0]["verdict"], 1)
        self.assertIn("gitlab 18.11.2", rows[1]["title"].lower())
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_no_marker_is_aman(self):
        bodies = {p: "<html>nothing here</html>"
                  for p in ("/users/sign_in", "/help", "/explore")}
        with self._patch(gp, bodies):
            rows, meta = gp.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)
        self.assertEqual(rows[0]["category"], "AMAN")

    def test_all_network_error_no_aman_claim(self):
        def fake_urlopen(req, timeout=None):
            raise OSError("conn refused")
        with patch.object(gp.urllib.request, "urlopen", fake_urlopen):
            rows, meta = gp.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertTrue(rows[0].get("network_error"))
        self.assertNotIn("AMAN/inventaris", rows[0]["description"])

    def test_kb_chain_110264_in_range_and_patched(self):
        valid = [e for e in kb_valid() if e["cve"] == "CVE-2026-110264"]
        self.assertEqual(len(valid), 7)
        rows = [_fact_row("gitlab-posture",
                          "gitlab 18.11.2 instance terdeteksi di t")]
        out, meta = cm.match_cves(rows, [], valid)
        kb_rows = [r for r in out if r.get("via") == "operator-kb"]
        self.assertEqual(len(kb_rows), 1)
        self.assertEqual(kb_rows[0]["cve"], "CVE-2026-110264")
        self.assertEqual(kb_rows[0]["version_detected"], "18.11.2")
        # patched 19.5.1 = tanpa klaim KB (zero-FP)
        rows2 = [_fact_row("gitlab-posture",
                           "gitlab 19.5.1 instance terdeteksi di t")]
        out2, _ = cm.match_cves(rows2, [], valid)
        self.assertEqual(
            [r for r in out2 if r.get("via") == "operator-kb"], [])
        # branch lain: 19.3.5 rentan, 19.3.6 fix
        rows3 = [_fact_row("gitlab-posture",
                           "gitlab 19.3.5 instance terdeteksi di t")]
        out3, _ = cm.match_cves(rows3, [], valid)
        self.assertEqual(
            len([r for r in out3 if r.get("via") == "operator-kb"]), 1)


# -------------------------------------------------------- beyondtrust

class BeyondtrustPostureTest(_UrlOpenMixin, unittest.TestCase):
    def test_bomgar_token_marker(self):
        bodies = {"/login": "<html><title>Bomgar Remote Support</title>"
                            "BeyondTrust 24.1.2</html>",
                  "/appliance/login": "404", "/": "404"}
        with self._patch(bp, bodies):
            rows, meta = bp.audit("http://t.local")
        self.assertTrue(meta["detected"])
        self.assertEqual(meta["versions"], ["24.1.2"])
        self.assertIn("beyondtrust remote support 24.1.2",
                      rows[1]["title"].lower())
        self.assertTrue(all(validate_finding(r) == [] for r in rows))

    def test_generic_remote_support_phrase_not_marker(self):
        bodies = {"/login": "<html>Remote support portal for staff"
                            "</html>",
                  "/appliance/login": "404", "/": "404"}
        with self._patch(bp, bodies):
            rows, meta = bp.audit("http://t.local")
        self.assertFalse(meta["detected"])
        self.assertEqual(rows[0]["verdict"], 0)

    def test_alias_chain_kev_product_level(self):
        kev = [{"cveID": "CVE-2026-102764", "vendorProject": "BeyondTrust",
                "product": "Remote Support", "vulnerabilityName": "x",
                "knownRansomwareCampaignUse": "Unknown", "cwes": []}]
        rows = [_fact_row(
            "beyondtrust-posture",
            "beyondtrust remote support 24.1.2 appliance terdeteksi")]
        out, meta = cm.match_cves(rows, kev, [], [], None, [])
        kev_rows = [r for r in out if r.get("cve") == "CVE-2026-102764"]
        self.assertEqual(len(kev_rows), 1)
        self.assertIn(kev_rows[0]["via"], ("direct", "alias:bomgar"))
        self.assertEqual(kev_rows[0]["version_detected"], "24.1.2")

    def test_watchlist_seed_bt_lead(self):
        wl = [{"cve": "CVE-2026-102764", "vendor": "BeyondTrust",
               "product": "Remote Support / PRA",
               "_tokens": ["beyondtrust", "bomgar"],
               "_product": "remote support pra",
               "note": "auth bypass zero-day",
               "source_url": "https://example.com/bt26-05"}]
        rows = [_fact_row(
            "beyondtrust-posture",
            "beyondtrust remote support 24.1.2 appliance terdeteksi")]
        out, meta = cm.match_cves(rows, [], [], [], None, wl)
        wl_rows = [r for r in out if r.get("via") == "watchlist"]
        self.assertEqual(len(wl_rows), 1)
        self.assertEqual(wl_rows[0]["verdict"], 1)


# ---------------------------------------------------------- node.js KB

class NodeKbTest(unittest.TestCase):
    def test_node_brotli_ranges(self):
        valid = [e for e in kb_valid() if e["cve"] == "CVE-2026-111497"]
        self.assertEqual(len(valid), 5)

        def probe(version):
            rows = [_fact_row("server-version-disclosure",
                              f"node.js {version} server")]
            out, _ = cm.match_cves(rows, [], valid)
            return [r for r in out if r.get("via") == "operator-kb"]

        self.assertEqual(len(probe("24.21.0")), 1)      # branch 24 rentan
        self.assertEqual(probe("24.22.1"), [])          # fix zero-FP
        self.assertEqual(len(probe("20.18.0")), 1)      # legacy EOL
        self.assertEqual(len(probe("22.22.0")), 1)      # branch 22 rentan
        self.assertEqual(probe("22.23.4"), [])          # fix
        self.assertEqual(len(probe("23.5.0")), 1)       # jalur ganjil EOL


# ---------------------------------------------------------- Java KB (F61f)

class JavaKbTest(unittest.TestCase):
    """CVE-2026-91403 (JSSE trust-store, fix OpenJDK 2026-10-21): branch
    11/17/21/25/27 dimodelkan; skema 8u (8u521) tak terurai = aman
    tanpa klaim (fail-closed, tanpa FP)."""

    def test_java_jsse_ranges(self):
        valid = [e for e in kb_valid() if e["cve"] == "CVE-2026-91403"]
        self.assertEqual(len(valid), 5)

        def probe(text):
            rows = [_fact_row("tech-fingerprint", text)]
            out, _ = cm.match_cves(rows, [], valid)
            return [r for r in out if r.get("via") == "operator-kb"]

        self.assertEqual(len(probe("java 21.0.13 runtime")), 1)
        self.assertEqual(probe("java 21.0.14 runtime"), [])
        self.assertEqual(len(probe("java 11.0.33 runtime")), 1)
        self.assertEqual(probe("java 25.0.6 runtime"), [])
        self.assertEqual(len(probe("graalvm 21.0.13")), 0)  # token beda

    def test_java_8u_scheme_unparsed_no_claim(self):
        valid = [e for e in kb_valid() if e["cve"] == "CVE-2026-91403"]
        rows = [_fact_row("tech-fingerprint", "java 8u521 runtime")]
        out, meta = cm.match_cves(rows, [], valid)
        self.assertEqual(
            [r for r in out if r.get("via") == "operator-kb"], [])
        self.assertEqual(meta["ranges_skipped"], 5)  # 5 branch dievaluasi, versi 8u tak terurai


if __name__ == "__main__":
    unittest.main()

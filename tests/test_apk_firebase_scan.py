"""Nol jaringan — test apk_firebase_scan (#0030, APK = ZIP via stdlib)."""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import apk_firebase_scan as afs  # noqa: E402

GOOGLE_JSON = json.dumps({
    "project_info": {
        "project_id": "my-app-prod",
        "database_url": "https://my-app-prod-default-rtdb.firebaseio.com",
    },
    "client": [{"api_key": [{"current_key": "AIzaSyD-abcdefghij0123456789"}]}],
})


def _make_apk(tmp: Path, entries: dict[str, bytes], name="app.apk") -> Path:
    p = tmp / name
    with zipfile.ZipFile(p, "w") as z:
        for n, b in entries.items():
            z.writestr(n, b)
    return p


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: None)


class TestScan(Base):
    def test_google_services_terdeteksi(self):
        apk = _make_apk(self.tmp, {
            "resources/google-services.json": GOOGLE_JSON.encode()})
        res = afs.scan_apk(str(apk))
        cats = res["by_category"]
        self.assertIn("firebase-api-key", cats)
        self.assertIn("rtdb-url-exposed", cats)
        self.assertIn("default-rtdb", cats)
        f = [x for x in res["findings"]
             if x["category"] == "firebase-api-key"][0]
        self.assertIn("***", f["value_masked"])
        self.assertNotIn("AIzaSyD-abcdefghij0123456789", f["value_masked"])

    def test_keystore_dibawa_diflag_high(self):
        apk = _make_apk(self.tmp, {"res/values/strings.xml": b"<r/>",
                                   "assets/upload.keystore": b"\x02jks"})
        res = afs.scan_apk(str(apk))
        keystore = [f for f in res["findings"]
                    if f["category"] == "sensitive-file"]
        self.assertEqual(len(keystore), 1)
        self.assertEqual(keystore[0]["severity"], "high")

    def test_cleartext_manifest(self):
        manifest = (b'<manifest><application android:usesCleartextTraffic='
                    b'"true"></application></manifest>')
        apk = _make_apk(self.tmp, {"AndroidManifest.xml": manifest})
        res = afs.scan_apk(str(apk))
        self.assertIn("cleartext-traffic", res["by_category"])

    def test_key_di_xml_resource(self):
        apk = _make_apk(self.tmp, {
            "res/values/strings.xml": b"<string name=\"k\">"
                                      b"AIzaSyZz1234567890abcdefghijklmnop"
                                      b"</string>"})
        res = afs.scan_apk(str(apk))
        self.assertIn("key-in-xml", res["by_category"])

    def test_apk_bersih_tanpa_temuan(self):
        apk = _make_apk(self.tmp, {"classes.dex": b"\x64\x65\x78\x0a",
                                   "res/scene.png": b"\x89PNG"})
        res = afs.scan_apk(str(apk))
        self.assertEqual(res["findings_total"], 0)

    def test_masking_tanpa_nilai_penuh_di_json(self):
        apk = _make_apk(self.tmp, {"google-services.json":
                                   GOOGLE_JSON.encode()})
        res = afs.scan_apk(str(apk))
        blob = json.dumps(res)
        self.assertNotIn("AIzaSyD-abcdefghij0123456789", blob)


class TestCli(Base):
    def test_bukan_zip_exit2(self):
        p = self.tmp / "not.apk"
        p.write_bytes(b"MZ bukan zip")
        rc = afs.main(["--source", str(p)])
        self.assertEqual(rc, 2)

    def test_tidak_ada_exit2(self):
        rc = afs.main(["--source", str(self.tmp / "ghost.apk")])
        self.assertEqual(rc, 2)

    def test_bersih_exit0(self):
        apk = _make_apk(self.tmp, {"classes.dex": b"dex\n"})
        rc = afs.main(["--source", str(apk)])
        self.assertEqual(rc, 0)

    def test_temuan_exit1_dan_out_json(self):
        apk = _make_apk(self.tmp, {"google-services.json":
                                   GOOGLE_JSON.encode()})
        out = self.tmp / "r.json"
        rc = afs.main(["--source", str(apk), "--out", str(out)])
        self.assertEqual(rc, 1)
        d = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(d["schema"], "secai.apk-firebase/1")


if __name__ == "__main__":
    unittest.main()

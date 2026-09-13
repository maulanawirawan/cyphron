"""Unit tests — kb_sync (pustakawan KB): unduhan fixture, verifikasi hash,
manifest, ketahanan terhadap kegagalan jaringan (KB lama tetap utuh).
Semua offline — fetch di-patch, tanpa jaringan."""

from __future__ import annotations

import gzip
import io
import json
import sys
import tarfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.kb import kb_sync, paths


def _tarball_bytes() -> bytes:
    """Tarball ala nuclei-templates: akar repo + 2 template."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(name: str, data: str):
            raw = data.encode()
            info = tarfile.TarInfo(name=name)
            info.size = len(raw)
            tar.addfile(info, io.BytesIO(raw))

        add("nuclei-templates-main/README.md", "# readme\n")
        add("nuclei-templates-main/http/cves/2021/CVE-2021-1.yaml",
            "id: CVE-2021-1\ninfo:\n  name: X\n  severity: info\n"
            "  tags: cve\nhttp:\n  - method: GET\n    path:\n"
            "      - '{{BaseURL}}/a'\n    matchers:\n"
            "      - type: word\n        words:\n          - 'ok'\n")
        add("nuclei-templates-main/http/misconfig/b.yaml",
            "id: b\ninfo:\n  name: B\n  severity: low\n  tags: exposure\n")
    return buf.getvalue()


class FakeFetcher:
    def __init__(self, mapping: dict[str, bytes], fail: set[str] | None = None):
        self.mapping = mapping
        self.fail = fail or set()
        self.calls: list[str] = []

    def __call__(self, url: str, timeout: float = 180.0) -> bytes:
        self.calls.append(url)
        if url in self.fail:
            raise ConnectionError(f"jaringan turun: {url}")
        if url not in self.mapping:
            raise ConnectionError(f"URL tak terduga: {url}")
        return self.mapping[url]


def _mini_feed(year: int, n: int = 2) -> bytes:
    data = {"CVE_Items": [{"cve": {"CVE_data_meta": {"ID": f"CVE-{year}-000{i}"}}}
                          for i in range(n)]}
    return gzip.compress(json.dumps(data).encode())


class TestKbSync(unittest.TestCase):
    def setUp(self):
        import tempfile
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.kb_dir = Path(self._tmp.name) / "kb"

    def test_sync_edb_writes_csv_and_manifest(self):
        csv_bytes = b"id,file,description\n1,e1.sh,'Exploit A'\n2,e2.py,'Exploit B'\n"
        fake = FakeFetcher({kb_sync.EDB_CSV_URL: csv_bytes})
        manifest = kb_sync.sync("edb", kb_dir=self.kb_dir, fetch=fake)
        out = self.kb_dir / "edb" / "files_exploits.csv"
        self.assertTrue(out.exists())
        self.assertEqual(out.read_bytes(), csv_bytes)
        self.assertEqual(manifest["sources"]["edb"]["rows"], 2)
        self.assertEqual(manifest["sources"]["edb"]["sha256"],
                         paths.sha256_bytes(csv_bytes))
        self.assertTrue(manifest["ok"])

    def test_sync_nvd_feeds_and_counts(self):
        fake = FakeFetcher({
            kb_sync.NVD_FEED_URL.format(year=2026): _mini_feed(2026, 2),
            kb_sync.NVD_FEED_URL.format(year=2025): _mini_feed(2025, 3),
        })
        manifest = kb_sync.sync("nvd", kb_dir=self.kb_dir, fetch=fake,
                                years=range(2025, 2027))
        self.assertTrue((self.kb_dir / "nvd" /
                         "nvdcve-1.1-2026.json.gz").exists())
        self.assertEqual(manifest["sources"]["nvd"]["cves"], 5)
        self.assertEqual(manifest["sources"]["nvd"]["years"], [2025, 2026])

    def test_sync_nuclei_tarball_extracted(self):
        fake = FakeFetcher({kb_sync.NUCLEI_TARBALL_URL: _tarball_bytes()})
        manifest = kb_sync.sync("nuclei", kb_dir=self.kb_dir, fetch=fake)
        root = self.kb_dir / "nuclei"
        self.assertTrue((root / "http" / "cves" / "2021" /
                         "CVE-2021-1.yaml").exists())
        self.assertTrue((root / "http" / "misconfig" / "b.yaml").exists())
        self.assertEqual(manifest["sources"]["nuclei"]["files"], 3)

    def test_failure_keeps_old_kb_and_manifest(self):
        csv_bytes = b"id,file\n9,old.csv\n"
        ok = FakeFetcher({kb_sync.EDB_CSV_URL: csv_bytes})
        kb_sync.sync("edb", kb_dir=self.kb_dir, fetch=ok)
        old_manifest = paths.load_manifest(self.kb_dir)
        # sinkron ulang dengan jaringan mati
        bad = FakeFetcher({}, fail={kb_sync.EDB_CSV_URL})
        manifest = kb_sync.sync("edb", kb_dir=self.kb_dir, fetch=bad)
        self.assertFalse(manifest["ok"])
        self.assertIn("edb", manifest["errors"][0])
        # KB lama + entri manifest lama TETAP utuh
        self.assertEqual((self.kb_dir / "edb" /
                          "files_exploits.csv").read_bytes(), csv_bytes)
        self.assertEqual(manifest["sources"]["edb"]["sha256"],
                         old_manifest["sources"]["edb"]["sha256"])

    def test_sync_all_partial_failure(self):
        mapping = {kb_sync.EDB_CSV_URL: b"id,file\n1,x\n",
                   kb_sync.NUCLEI_TARBALL_URL: _tarball_bytes()}
        for y in range(2018, 2027):
            mapping[kb_sync.NVD_FEED_URL.format(year=y)] = _mini_feed(y, 1)
        fake = FakeFetcher(
            mapping,
            fail={kb_sync.NVD_FEED_URL.format(year=y)
                  for y in range(2018, 2027)})

        def api_mati(url, timeout=180.0):
            raise ConnectionError("api tidak tersedia (fixture)")

        manifest = kb_sync.sync("all", kb_dir=self.kb_dir, fetch=fake,
                                api_fetch=api_mati)
        self.assertIn("edb", manifest["sources"])
        self.assertIn("nuclei", manifest["sources"])
        self.assertNotIn("nvd", manifest["sources"])
        self.assertTrue(any(e.startswith("nvd:") for e in manifest["errors"]))
        self.assertFalse(manifest["ok"])

    def test_unknown_source_raises(self):
        with self.assertRaises(kb_sync.KbSyncError):
            kb_sync.sync("pastebin", kb_dir=self.kb_dir, fetch=FakeFetcher({}))

    def test_nvd_auto_falls_back_to_api(self):
        # feed 1.1 mati (403 di dunia nyata) -> auto jatuh ke API 2.0

        def feed_403(url, timeout=180.0):
            raise ConnectionError("HTTP 403 (feed tidak lagi dilayani)")

        def fake_api_fetch(url, timeout=180.0):
            assert "services.nvd.nist.gov" in url
            body = {"resultsPerPage": 2000, "totalResults": 1,
                    "vulnerabilities": [{
                        "cve": {
                            "id": "CVE-2026-9999",
                            "descriptions": [{"lang": "en", "value": "uji"}],
                            "metrics": {"cvssMetricV31": [{
                                "cvssData": {"baseScore": 9.8,
                                             "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]},
                            "configurations": [{"nodes": [{"cpeMatch": [
                                {"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                                 "versionStartIncluding": "8.1.0",
                                 "versionEndExcluding": "8.2.0"}]}]}],
                        }}]}
            return json.dumps(body).encode()

        kb_sync.sync("nvd", kb_dir=self.kb_dir, years=range(2026, 2027),
                     fetch=feed_403, api_fetch=fake_api_fetch,
                     nvd_throttle=0.0)
        out = self.kb_dir / "nvd" / "nvd-api-2026.json.gz"
        self.assertTrue(out.exists(), "fallback API harus menulis file")
        data = json.loads(gzip.decompress(out.read_bytes()))
        self.assertEqual(data["CVE_Items"][0]["cve"]["CVE_data_meta"]["ID"],
                         "CVE-2026-9999")
        # hasil API terbaca oleh builder sqlite
        from cyphron.kb import nvd_sqlite
        built = nvd_sqlite.build_sqlite(self.kb_dir)
        self.assertGreaterEqual(built["cves"], 1)

    def test_api_to_feed_item_conversion(self):
        from cyphron.kb.nvd_api import api_to_feed_item
        item = api_to_feed_item({
            "cve": {
                "id": "CVE-2026-4444",
                "descriptions": [{"lang": "es", "value": "x"},
                                 {"lang": "en", "value": "php bug"}],
                "weaknesses": [{"description": [{"value": "NVD-CWE-Other"},
                                                {"value": "CWE-22"}]}],
                "metrics": {"cvssMetricV31": [{"cvssData": {
                    "baseScore": 8.2, "vectorString": "CVSS:3.1/AV:N"}}]},
                "configurations": [{"nodes": [{"cpeMatch": [
                    {"criteria": "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*",
                     "versionEndExcluding": "8.2.0"}]}]}],
                "published": "2026-03-01T00:00:00.000",
                "lastModified": "2026-03-02T00:00:00.000"}})
        self.assertEqual(item["cve"]["CVE_data_meta"]["ID"], "CVE-2026-4444")
        self.assertEqual(item["cve"]["description"]["description_data"][0]["value"],
                         "php bug")
        self.assertEqual(
            item["cve"]["problemtype"]["problemtype_data"][0]["description"][0]["value"],
            "CWE-22")  # ambil CWE asli, bukan noinfo
        self.assertEqual(item["impact"]["baseMetricV3"]["cvssV3"]["baseScore"], 8.2)
        self.assertEqual(item["config"]["nodes"][0]["cpe_match"][0]["cpe23Uri"],
                         "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*")
        self.assertEqual(item["config"]["nodes"][0]["cpe_match"][0]["versionEndExcluding"],
                         "8.2.0")
        self.assertIsNone(api_to_feed_item({"cve": {}}))

    def test_cli_kb_subcommand_reports(self):
        from cyphron.cli import main
        fake = FakeFetcher({kb_sync.EDB_CSV_URL: b"id,file\n1,x\n"})
        orig = kb_sync.sync

        def patched(*a, **kw):
            kw["fetch"] = fake
            return orig(*a, **kw)

        kb_sync.sync = patched
        self.addCleanup(setattr, kb_sync, "sync", orig)
        rc = main(["kb", "--source", "edb",
                   "--kb-dir", str(self.kb_dir)])
        self.assertEqual(rc, 0)
        self.assertTrue((self.kb_dir / "edb" /
                         "files_exploits.csv").exists())


if __name__ == "__main__":
    unittest.main()

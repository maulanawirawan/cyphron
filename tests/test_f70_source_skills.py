"""F70 — skill source-review: repo-secret-scan + infra-config-audit.

Semua uji tanpa jaringan (0 request): fixture tmp dir dengan konten
positif/negatif. Fokus: presisi (zero-FP) — placeholder TIDAK boleh
menjadi temuan; nilai selalu disensor; gating needs=source via registry.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "skills"))
sys.path.insert(0, str(ROOT / "core"))

import repo_secret_scan as rss  # noqa: E402
import infra_config_audit as ica  # noqa: E402


class RepoSecretScanTest(unittest.TestCase):
    def _scan(self, files: dict[str, str]) -> tuple[list[dict], dict]:
        with tempfile.TemporaryDirectory() as td:
            for rel, content in files.items():
                p = Path(td) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            return rss.audit(td)

    def test_strong_patterns_flagged_and_masked(self):
        rows, meta = self._scan({
            "app/config.py": 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        })
        self.assertEqual(len(rows), 1)
        self.assertIn("aws-access-key", rows[0]["title"])
        # masking: nilai penuh TIDAK boleh muncul di finding
        blob = json.dumps(rows)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", blob)
        self.assertEqual(rows[0]["status"], "unconfirmed")

    def test_placeholder_suppressed_zero_fp(self):
        rows, _ = self._scan({
            "app/config.py": (
                'API_KEY = "YOUR_API_KEY_HERE"\n'
                'SECRET = "{{ secrets.prod }}"\n'
                "PASSWORD = 'changeme-please'\n"
                'TOKEN = "example_dummy_value"\n'
                'PWD = "short"\n'
            ),
        })
        self.assertEqual(rows, [],
                         f"placeholder tidak boleh jadi temuan: {rows}")

    def test_low_entropy_suppressed(self):
        rows, _ = self._scan({
            "app/config.py": 'password = "passwordpassword"\n',
        })
        # "passwordpassword" = satu token diulang -> entropi rendah -> no hit
        self.assertEqual([r for r in rows if "generic" in r["title"]], [])

    def test_private_key_block_flagged(self):
        rows, _ = self._scan({
            "deploy/key.pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIB\n",
        })
        self.assertEqual(len(rows), 1)
        self.assertIn("private-key-block", rows[0]["title"])

    def test_node_modules_skipped(self):
        rows, meta = self._scan({
            "node_modules/pkg/index.js": 'KEY = "AKIAIOSFODNN7EXAMPLE"\n',
        })
        self.assertEqual(rows, [])
        self.assertEqual(meta["files_scanned"], 0)

    def test_missing_path_fail_closed(self):
        rows, meta = rss.audit(r"D:\TIDAK\ADA\path")
        self.assertFalse(meta["ok"])


class InfraConfigAuditTest(unittest.TestCase):
    def _audit(self, files: dict[str, str]) -> tuple[list[dict], dict]:
        with tempfile.TemporaryDirectory() as td:
            for rel, content in files.items():
                p = Path(td) / rel
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_text(content, encoding="utf-8")
            return ica.audit(td)

    def test_public_port_flagged_localhost_clean(self):
        rows, _ = self._audit({
            "docker-compose.yml": (
                "services:\n"
                "  db:\n"
                "    image: postgres\n"
                "    ports:\n"
                '      - "5432:5432"\n'
                "  web:\n"
                "    image: web\n"
                "    ports:\n"
                '      - "127.0.0.1:8080:80"\n'
            ),
        })
        self.assertEqual(len(rows), 1)
        self.assertIn("5432:5432", rows[0]["title"])
        # port terikat localhost TIDAK boleh menjadi temuan (zero-FP)
        self.assertNotIn("127.0.0.1:8080:80", rows[0]["title"])

    def test_hardcoded_db_password_flagged_env_ref_clean(self):
        rows, _ = self._audit({
            "docker-compose.yml": (
                "services:\n"
                "  db:\n"
                "    image: postgres\n"
                "    environment:\n"
                "      POSTGRES_PASSWORD: supersecret99x\n"
                "  db2:\n"
                "    image: postgres\n"
                "    environment:\n"
                "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n"
            ),
        })
        self.assertEqual(len(rows), 1)  # hanya yang hardcoded
        self.assertIn("tertulis langsung", rows[0]["title"])

    def test_privileged_and_host_network_flagged(self):
        rows, _ = self._audit({
            "docker-compose.yml": (
                "services:\n"
                "  x:\n"
                "    image: x\n"
                "    privileged: true\n"
                "    network_mode: host\n"
            ),
        })
        self.assertEqual(len(rows), 2)

    def test_nginx_missing_header_and_old_tls(self):
        rows, _ = self._audit({
            "nginx.conf": (
                "server {\n"
                "  listen 443 ssl;\n"
                "  ssl_protocols TLSv1.0 TLSv1.2;\n"
                "  add_header X-Content-Type-Options nosniff;\n"
                "}\n"
            ),
        })
        titles = " ".join(r["title"] for r in rows)
        self.assertIn("TLS usang", titles)
        self.assertIn("Strict-Transport-Security", titles)  # header hilang
        self.assertNotIn("X-Content-Type-Options tidak diatur", titles)

    def test_real_secret_in_env_example_flagged_placeholder_clean(self):
        rows, _ = self._audit({
            ".env.example": (
                "JWT_SECRET=realsecretvalue-9f8e7d6c\n"
                "API_KEY=YOUR_API_KEY_HERE\n"
            ),
        })
        self.assertEqual(len(rows), 1)
        self.assertIn(".env.example", rows[0]["title"])

    def test_clean_config_zero_finding(self):
        rows, meta = self._audit({
            "docker-compose.yml": (
                "services:\n"
                "  web:\n"
                "    image: web\n"
                "    ports:\n"
                '      - "127.0.0.1:8080:80"\n'
                "    environment:\n"
                "      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}\n"
            ),
            "nginx.conf": (
                "server {\n"
                "  listen 443 ssl;\n"
                "  add_header Strict-Transport-Security 'max-age=31536000';\n"
                "  add_header X-Content-Type-Options nosniff;\n"
                "  add_header X-Frame-Options SAMEORIGIN;\n"
                "  add_header Referrer-Policy strict-origin;\n"
                "}\n"
            ),
        })
        self.assertEqual(rows, [],
                         f"konfigurasi bersih tidak boleh bertemuan: {rows}")


class RegistryGateTest(unittest.TestCase):
    def test_source_skills_in_registry_with_source_need(self):
        reg = json.loads((ROOT / "skills" / "registry.json")
                         .read_text(encoding="utf-8"))
        by = {s["name"]: s for s in reg["skills"]}
        for name in ("repo-secret-scan", "infra-config-audit"):
            self.assertIn(name, by)
            self.assertEqual(by[name]["needs"], "source")
            self.assertEqual(by[name]["safety_class"], "read-only")
            self.assertTrue(any("@SOURCE@" in a for a in by[name]["cmd"]))


if __name__ == "__main__":
    unittest.main()

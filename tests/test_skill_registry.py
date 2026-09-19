import unittest
from pathlib import Path

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.config import default_kimchi_dir, load
from cyphron.skills.registry import SkillRegistry


class TestSkillRegistry(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = load(default_kimchi_dir())
        cls.registry = SkillRegistry(cls.config)

    def test_all_skills_loaded(self):
        # 65 original + 8 harvested (66-73) + 1 forensics (74)
        # + 7 gap-port (75-81) + 1 recon (82) + 3 intel (83-85) + 2 teknik (86-87) = 87
        self.assertEqual(len(self.registry), 87, "must load all .cyphron skills")
        ids = {s.id for s in self.registry.skills}
        self.assertTrue({"66", "67", "68", "69", "70", "71", "72", "73",
                         "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87"} <= ids)
        inventory = self.registry.inventory()
        self.assertTrue(all(mode == "defensive" for _i, _n, mode in inventory))

    def test_gap_port_skills_content(self):
        """Skill 75-81: file ada, non-trivial, struktur minimal terpenuhi."""
        root = default_kimchi_dir()
        for sid, stem in [("75", "75-forensik-memori"),
                          ("76", "76-analisis-event-log"),
                          ("77", "77-threat-hunting"),
                          ("78", "78-deteksi-phishing-bec"),
                          ("79", "79-audit-cloud-iam"),
                          ("80", "80-rekomendasi-pertahanan"),
                          ("81", "81-playbook-fraud")]:
            p = root / "skills" / f"{stem}.md"
            self.assertTrue(p.exists(), f"{stem}.md harus ada")
            body = p.read_text(encoding="utf-8")
            self.assertGreater(len(body), 2000, f"{stem} terlalu tipis")
            self.assertIn("WHEN TO ACTIVATE", body, stem)
            self.assertIn("METHODOLOGY", body, stem)

    def test_harvested_skills_retrieve(self):
        top = [s.id for s, _ in self.registry.retrieve("webhook replay idempotency", top_k=1)]
        self.assertEqual(top[0], "67")
        top = [s.id for s, _ in self.registry.retrieve("ssrf url ingestion metadata", top_k=1)]
        self.assertEqual(top[0], "68")

    def test_sqli_query_hits_right_skills(self):
        top = [s.id for s, _ in self.registry.retrieve("sql injection di form login", top_k=3)]
        self.assertIn("12", top, "OWASP Top 10 (injection) should rank")
        self.assertTrue({"03", "12"} & set(top))

    def test_idor_query(self):
        top = [s.id for s, _ in self.registry.retrieve("idor pada endpoint order", top_k=3)]
        self.assertTrue(top)

    def test_secrets_query(self):
        top = [s.id for s, _ in self.registry.retrieve("secret api key ke-commit di repo", top_k=3)]
        self.assertIn("20", top, "Secrets Management should rank for secret queries")

    def test_tool_builder_query(self):
        top = [s.id for s, _ in self.registry.retrieve("build a scanner tool for xss", top_k=3)]
        self.assertIn("04", top)


if __name__ == "__main__":
    unittest.main()

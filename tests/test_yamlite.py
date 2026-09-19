import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron import yamlite

SAMPLE = """
agent:
  name: "Cyphron"
  version: "2.0.0"
  description: >
    A sophisticated agent with two modes:
    defensive and offensive.
skills:
  - id: "01"
    name: "Secure Code Review"
    triggers: ["review", "is this secure"]
    priority: 1
    mode: defensive
  - id: "02"
    name: "Threat Modeling"
    triggers: ["threat model"]
    priority: 2
    mode: defensive
commands:
  run_single: 'ollama run Cyphron "your prompt here"'
  api: 'curl -d ''{"model":"Cyphron"}'''
"""


class TestYamlite(unittest.TestCase):
    def test_nested_mapping(self):
        data = yamlite.parse(SAMPLE)
        self.assertEqual(data["agent"]["name"], "Cyphron")
        self.assertEqual(data["agent"]["version"], "2.0.0")
        self.assertIn("defensive and offensive.", data["agent"]["description"])

    def test_list_of_mappings(self):
        data = yamlite.parse(SAMPLE)
        self.assertEqual(len(data["skills"]), 2)
        first = data["skills"][0]
        self.assertEqual(first["id"], "01")
        self.assertEqual(first["triggers"], ["review", "is this secure"])
        self.assertEqual(first["priority"], 1)

    def test_single_quote_escaping(self):
        data = yamlite.parse(SAMPLE)
        self.assertEqual(data["commands"]["api"], 'curl -d \'{"model":"Cyphron"}\'')

    def test_block_scalar_in_list_item(self):
        # pola template nuclei: raw: - |  (block scalar sebagai item list)
        data = yamlite.parse(
            "a:\n"
            "  raw:\n"
            "    - |\n"
            "      GET /x HTTP/1.1\n"
            "      Host: {{Hostname}}\n"
        )
        self.assertEqual(data["a"]["raw"][0],
                         "GET /x HTTP/1.1\nHost: {{Hostname}}")

    def test_block_scalar_chomping_variants(self):
        data = yamlite.parse("d: |-\n  baris satu\n  baris dua\n")
        self.assertEqual(data["d"], "baris satu\nbaris dua")


if __name__ == "__main__":
    unittest.main()

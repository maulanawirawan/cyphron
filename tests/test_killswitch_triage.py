"""Nol jaringan — test killswitch_triage (triase kill-switch ransomware).

Fixture dibangun inline: ekspor XML Windows ala Sysmon (EID 17/18/1/4104)
+ log DNS teks + DB indikator JSON. Perilaku pencocokan exact/substring
ekstotik diuji, termasuk anti-FP (domain umum TIDAK dicocokkan; event
tidak terkait TIDAK menyala). Tidak ada request jaringan.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for sub in ("core", "tools"):
    sys.path.insert(0, str(ROOT / sub))

import killswitch_triage as kt  # noqa: E402
from findings import validate_finding  # noqa: E402

WANNACRY_MTX = "Global\\MsWinZonesCacheCounterMutexA"
WANNACRY_DOM = "iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com"
CONTI_MTX = "Global\\kasKDJSAFJauisiudUASIIQWUA82"


def _tmpfile(content: str, suffix: str = ".txt") -> Path:
    with tempfile.NamedTemporaryFile(mode="w", suffix=suffix, delete=False,
                                     encoding="utf-8") as fh:
        fh.write(content)
        return Path(fh.name)


def _sysmon_xml(pipes: list[str] | None = None,
                cmds: list[str] | None = None,
                scripts: list[str] | None = None) -> str:
    blocks = []
    for p in pipes or []:
        blocks.append(
            "<Event><System><EventID>17</EventID></System>"
            f"<EventData><Data Name=\"PipeName\">{p}</Data></EventData>"
            "</Event>")
    for c in cmds or []:
        blocks.append(
            "<Event><System><EventID>1</EventID></System>"
            f"<EventData><Data Name=\"CommandLine\">{c}</Data></EventData>"
            "</Event>")
    for s in scripts or []:
        blocks.append(
            "<Event><System><EventID>4104</EventID></System>"
            f"<EventData><Data Name=\"ScriptBlockText\">{s}</Data>"
            "</EventData></Event>")
    return "\n".join(blocks)


class TestDb(unittest.TestCase):
    def test_seed_load(self):
        entries, meta = kt.load_db(None)
        fams = {e["family"] for e in entries}
        self.assertIn("WannaCry", fams)
        self.assertEqual(meta["seed_families"], 4)
        self.assertEqual(meta["extra_families"], 0)
        # seed minimal punya channel untuk semua entri
        self.assertTrue(all(e["type"] in kt.CHANNEL_TYPES for e in entries))

    def test_extra_replaces_family_and_appends(self):
        dbf = _tmpfile(json.dumps({"families": [
            {"family": "WannaCry", "indicators": [
                {"type": "mutex", "value": "Global\\XTESTNEW"}]},
            {"family": "Bad", "indicators": [{"type": "nope", "value": "x"}]},
            {"family": "Bad2", "indicators": "bukan-list"},
        ]}), ".json")
        entries, meta = kt.load_db(str(dbf))
        wc = [e for e in entries if e["family"] == "WannaCry"]
        self.assertEqual([e["value"] for e in wc], ["Global\\XTESTNEW"])
        # famili dict valid dengan indikator disaring tetap dihitung;
        # "Bad2" (indicators bukan list) = invalid
        self.assertEqual(meta["extra_families"], 2)
        self.assertEqual(meta["extra_invalid"], 1)

    def test_db_broken_exits(self):
        dbf = _tmpfile("bukan json", ".json")
        with self.assertRaises(SystemExit):
            kt.load_db(str(dbf))

    def test_dup_dropped(self):
        # nilai SAMA pada famili BERBEDA = dup (famili sama = replace)
        dbf = _tmpfile(json.dumps({"families": [
            {"family": "Other", "indicators": [
                {"type": "mutex", "value": WANNACRY_MTX}]}]}), ".json")
        entries, meta = kt.load_db(str(dbf))
        n = sum(1 for e in entries
                if e["value"].lower() == WANNACRY_MTX.lower())
        self.assertEqual(n, 1)
        self.assertEqual(meta["dup_dropped"], 1)


class TestDnsParse(unittest.TestCase):
    def test_token_and_qname(self):
        f = _tmpfile(
            "1700000000 client 10.1.2.3 " + WANNACRY_DOM + " A\n"
            "qname=Example.COM. 10.0.0.9\n"
            "1700000005 client 10.1.2.3 contoso.example A\n")
        doms, meta = kt.parse_dns_file(str(f))
        self.assertEqual(meta["lines"], 3)
        self.assertIn(WANNACRY_DOM, doms)
        self.assertIn("example.com", doms)
        self.assertIn("contoso.example", doms)

    def test_binary_fail_closed(self):
        f = _tmpfile("\x00\x01 binary", ".log")
        doms, meta = kt.parse_dns_file(str(f))
        self.assertEqual(doms, [])
        self.assertTrue(meta["binary"])


class TestEventsParse(unittest.TestCase):
    def test_parse_fields(self):
        f = _tmpfile(_sysmon_xml(
            pipes=["\\??\\GLOBAL\\x"], cmds=["cmd.exe /c dir"],
            scripts=["CreateMutex(\"" + WANNACRY_MTX + "\")"]), ".xml")
        evs, meta = kt.parse_events_file(str(f))
        self.assertEqual(meta["events_parsed"], 3)
        self.assertEqual(evs[0]["pipe_name"], "\\??\\GLOBAL\\x")
        self.assertIn("CreateMutex", evs[2]["script_block"])

    def test_not_xml_exits(self):
        f = _tmpfile("plain text log\nno events here\n", ".xml")
        with self.assertRaises(SystemExit):
            kt.parse_events_file(str(f))


class TestMatch(unittest.TestCase):
    def _entries(self) -> list[dict]:
        entries, _ = kt.load_db(None)
        return entries

    def test_pipe_exact_match(self):
        evs = [{"eid": 17, "idx": 0,
                "pipe_name": "\\??\\GLOBAL\\" + CONTI_MTX.split("\\")[-1]}]
        m, _ = kt.match(evs, [], self._entries())
        hit = [x for x in m if x["family"] == "Conti"]
        self.assertEqual(len(hit), 1)
        self.assertEqual(hit[0]["mode"], "pipe-exact")

    def test_cmdline_substring_match(self):
        evs = [{"eid": 1, "idx": 1,
                "command_line": "powershell -c CreateMutex(\""
                                + WANNACRY_MTX + "\")"}]
        m, _ = kt.match(evs, [], self._entries())
        # hanya mutexA yang cocok; mutexB/keluarga lain tidak
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["family"], "WannaCry")
        self.assertEqual(m[0]["mode"], "cmd-substring")

    def test_dns_exact_match(self):
        m, _ = kt.match([], [WANNACRY_DOM], self._entries())
        self.assertEqual(len(m), 1)
        self.assertEqual(m[0]["channel"], "dns")

    def test_common_domain_no_match(self):
        m, _ = kt.match([], ["example.com", "wannacry.example.com"],
                        self._entries())
        self.assertEqual(m, [])

    def test_registry_type_no_channel(self):
        entries = [{"family": "Test", "type": "registry",
                    "value": "HKLM\\X"}]
        m, ncm = kt.match([], [], entries)
        self.assertEqual(m, [])
        self.assertEqual(ncm["indicators_without_channel"], 1)
        self.assertEqual(ncm["no_channel_types"], ["registry"])


class TestMainAndContract(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, Path]:
        out = Path(tempfile.mkdtemp()) / "findings.json"
        rc = kt.main(argv + ["--out", str(out)])
        return rc, out

    def test_clean_run_exit0(self):
        evf = _tmpfile(_sysmon_xml(cmds=["notepad.exe readme.txt"]), ".xml")
        dnsf = _tmpfile("10.0.0.1 contoso.example A\n", ".log")
        rc, out = self._run(["--events", str(evf), "--dns", str(dnsf)])
        self.assertEqual(rc, 0)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(doc["findings"], [])
        self.assertEqual(doc["data"]["matches"], 0)
        self.assertTrue(doc["data"]["vaccination_manifest"]
                        ["mutexes_to_precreate"])

    def test_match_run_exit1(self):
        evf = _tmpfile(_sysmon_xml(scripts=[
            "kernel32.CreateMutexW(\"" + WANNACRY_MTX + "\")"]), ".xml")
        dnsf = _tmpfile("qname=" + WANNACRY_DOM + "\n", ".log")
        rc, out = self._run(["--events", str(evf), "--dns", str(dnsf)])
        self.assertEqual(rc, 1)
        doc = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(len(doc["findings"]), 2)
        for f in doc["findings"]:
            self.assertEqual(validate_finding(f), [])
            self.assertEqual(f["verdict"], 2)
            self.assertFalse(f["reportable"])
        titles = {f["title"] for f in doc["findings"]}
        self.assertTrue(any("mutex" in t for t in titles))
        self.assertTrue(any("domain" in t for t in titles))

    def test_no_input_exit2(self):
        rc, _ = self._run([])
        self.assertEqual(rc, 2)

    def test_bad_events_exit2(self):
        evf = _tmpfile("bukan xml", ".xml")
        rc, _ = self._run(["--events", str(evf)])
        self.assertEqual(rc, 2)

    def test_bad_db_exit2(self):
        evf = _tmpfile(_sysmon_xml(cmds=["x"]), ".xml")
        dbf = _tmpfile("{{{", ".json")
        rc, _ = self._run(["--events", str(evf), "--db", str(dbf)])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()

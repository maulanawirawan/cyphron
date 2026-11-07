"""Test tools/antidup_check.py — pre-flight anti-dup v2.

Nol jaringan: AntidupClient menerima fetcher/search tersuntik; semua cek
diuji dengan respons GitHub API sintetis. Pencocokan suntikan pakai
SUBSTRING query (bukan kunci persis) supaya tanggal `merged:>=` dinamis
tidak bikin test rapuh. Yang dijamin: fail-closed (error = UNKNOWN, bukan
PASS), verdict tersusun (STOP > UNKNOWN > CAUTION > GO), dan sinyal niat
author terdeteksi.
"""
from __future__ import annotations

import base64
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import antidup_check  # noqa: E402


def pr_item(number, title, state="closed", kind="pr"):
    """Item search API sintetis."""
    item = {"number": number, "title": title, "state": state,
            "html_url": f"https://github.com/a/b/{'pull' if kind == 'pr' else 'issues'}/{number}",
            "closed_at": "2026-11-06T00:00:00Z"}
    if kind == "pr":
        item["pull_request"] = {"url": "x"}
    return item


class FakeClient(antidup_check.AntidupClient):
    """Client suntik: pencocokan substring query/url, jaringan nol."""

    def __init__(self, search_map=None, fetch_map=None):
        self.search_map = search_map or {}
        self.fetch_map = fetch_map or {}
        self.search_calls: list[str] = []
        self.fetch_calls: list[str] = []
        super().__init__(token="fake-token")
        # super().__init__ memasang lambda instance yang menutupi method —
        # timpa kembali dengan fungsi suntik di sini (urutan penting).
        self._search = self._injected_search
        self._fetch_json = self._injected_fetch

    def _injected_search(self, query):
        self.search_calls.append(query)
        for pattern, items in self.search_map.items():
            if pattern in query:
                return items
        return []

    def _injected_fetch(self, url):
        self.fetch_calls.append(url)
        result = self.fetch_map.get(url)
        if isinstance(result, Exception):
            raise result
        return result


class PrRefsIssueTest(unittest.TestCase):
    def test_stop_when_pr_references_issue(self):
        client = FakeClient(search_map={
            '"182" type:pr repo:a/b': [pr_item(183, "fix #182 thing")]})
        check = client.check_pr_refs_issue("a/b", 182)
        self.assertEqual(check["verdict"], "STOP")
        self.assertEqual(check["hits"][0]["number"], 183)

    def test_pass_when_clean(self):
        check = FakeClient().check_pr_refs_issue("a/b", 182)
        self.assertEqual(check["verdict"], "GO")
        self.assertEqual(check["hits"], [])


class RecentMergedTest(unittest.TestCase):
    def test_stop_on_recent_merged_with_same_keyword(self):
        client = FakeClient(search_map={
            '"kroki" type:pr repo:a/b': [pr_item(10, "Add kroki template")]})
        check = client.check_recent_merged("a/b", ["kroki"])
        self.assertEqual(check["verdict"], "STOP")
        # query harus memuat batas tanggal merged (protokol 14 hari)
        self.assertIn("merged:>=", client.search_calls[0])

    def test_dedup_between_keywords(self):
        client = FakeClient(search_map={
            '"kroki" type:pr repo:a/b': [pr_item(10, "kroki one"),
                                         pr_item(10, "kroki again")]})
        check = client.check_recent_merged("a/b", ["kroki", "kroki tikz"])
        self.assertEqual(len(check["hits"]), 1)


class KeywordSearchTest(unittest.TestCase):
    def test_stop_when_open_issue_mentions_cve(self):
        client = FakeClient(search_map={
            '"CVE-2026-1" repo:a/b': [pr_item(9, "handle CVE-2026-1",
                                              state="open", kind="issue")]})
        check = client.check_keyword("a/b", ["CVE-2026-1"])
        self.assertEqual(check["verdict"], "STOP")

    def test_caution_when_only_closed(self):
        client = FakeClient(search_map={
            '"CVE-2026-1" repo:a/b': [pr_item(9, "old cve work",
                                              state="closed")]})
        check = client.check_keyword("a/b", ["CVE-2026-1"])
        self.assertEqual(check["verdict"], "CAUTION")

    def test_pass_when_nothing(self):
        check = FakeClient().check_keyword("a/b", ["CVE-2026-1"])
        self.assertEqual(check["verdict"], "GO")


class ExistingFileTest(unittest.TestCase):
    URL = "https://api.github.com/repos/a/b/contents/x.yaml?ref=main"

    @staticmethod
    def contents(text):
        return {"content": base64.b64encode(text.encode()).decode()}

    def test_pass_when_missing(self):
        client = FakeClient(fetch_map={self.URL: {}})
        check = client.check_existing_file("a/b", "main", "x.yaml")
        self.assertEqual(check["verdict"], "GO")

    def test_stop_when_file_exists(self):
        client = FakeClient(fetch_map={self.URL: self.contents(
            "id: CVE-1\nhttp: []\n")})
        check = client.check_existing_file("a/b", "main", "x.yaml")
        self.assertEqual(check["verdict"], "STOP")

    def test_stop_when_autogen_marker(self):
        client = FakeClient(fetch_map={self.URL: self.contents(
            "id: CVE-1\n# digest: 4a0a004730...\n")})
        check = client.check_existing_file("a/b", "main", "x.yaml")
        self.assertEqual(check["verdict"], "STOP")
        self.assertIn("# digest:", check["hits"][0])


class AuthorIntentTest(unittest.TestCase):
    REPO_URL = "https://api.github.com/repos/a/b/issues/182"
    COMMENTS_URL = "https://api.github.com/repos/a/b/issues/182/comments"

    def test_stop_on_intent_in_body(self):
        client = FakeClient(fetch_map={
            self.REPO_URL: {"body": "I'd like to add a template for this."},
            self.COMMENTS_URL: []})
        check = client.check_author_intent("a/b", 182)
        self.assertEqual(check["verdict"], "STOP")
        self.assertTrue(check["hits"])

    def test_stop_on_intent_in_comment(self):
        client = FakeClient(fetch_map={
            self.REPO_URL: {"body": "Found an issue here."},
            self.COMMENTS_URL: [
                {"body": "I'm working on a fix, will open a PR soon."}]})
        check = client.check_author_intent("a/b", 182)
        self.assertEqual(check["verdict"], "STOP")

    def test_pass_when_no_intent(self):
        client = FakeClient(fetch_map={
            self.REPO_URL: {"body": "This endpoint discloses data."},
            self.COMMENTS_URL: [{"body": "Confirmed upstream."}]})
        check = client.check_author_intent("a/b", 182)
        self.assertEqual(check["verdict"], "GO")

    def test_unknown_when_issue_unreadable(self):
        client = FakeClient(fetch_map={
            "https://api.github.com/repos/a/b/issues/999": {},
            "https://api.github.com/repos/a/b/issues/999/comments": []})
        check = client.check_author_intent("a/b", 999)
        self.assertEqual(check["verdict"], "UNKNOWN")


class MergeVerdictTest(unittest.TestCase):
    def test_worst_wins(self):
        final, reasons = antidup_check.merge_verdict([
            {"check": "a", "verdict": "PASS"},
            {"check": "b", "verdict": "CAUTION"},
            {"check": "c", "verdict": "STOP"}])
        self.assertEqual(final, "STOP")
        self.assertEqual(len(reasons), 2)

    def test_pass_normalized_to_go(self):
        final, _ = antidup_check.merge_verdict(
            [{"check": "a", "verdict": "PASS"}])
        self.assertEqual(final, "GO")

    def test_unknown_beats_caution(self):
        final, _ = antidup_check.merge_verdict(
            [{"check": "a", "verdict": "CAUTION"},
             {"check": "b", "verdict": "UNKNOWN"}])
        self.assertEqual(final, "UNKNOWN")

    def test_unknown_verdict_string_fails_closed(self):
        # verdict tak dikenal (mis. data korup) TIDAK boleh dianggap aman
        final, _ = antidup_check.merge_verdict(
            [{"check": "a", "verdict": "hujan"}])
        self.assertEqual(final, "UNKNOWN")


class RunTest(unittest.TestCase):
    def test_error_check_becomes_unknown_not_pass(self):
        class BoomClient(antidup_check.AntidupClient):
            def _search(self, query):
                raise RuntimeError("simulasi jaringan mati")

        report = antidup_check.run("a/b", ["CVE-2026-1"], None, None,
                                   "main", "fake-token",
                                   client=BoomClient(token="fake-token"))
        self.assertEqual(report["final_verdict"], "UNKNOWN")
        self.assertTrue(report["api_errors"])
        self.assertTrue(all(c["verdict"] == "UNKNOWN"
                            for c in report["checks"]))

    def test_no_checks_is_unknown(self):
        report = antidup_check.run("a/b", [], None, None, "main", "tok",
                                   client=FakeClient())
        self.assertEqual(report["final_verdict"], "UNKNOWN")

    def test_full_go(self):
        report = antidup_check.run("a/b", ["CVE-2026-1"], None, None,
                                   "main", "fake-token",
                                   client=FakeClient())
        self.assertEqual(report["final_verdict"], "GO")
        self.assertEqual(len(report["checks"]), 2)  # recent_merged+keyword

    def test_issue_activates_checks_1_and_5(self):
        report = antidup_check.run("a/b", ["CVE-2026-1"], 182, None,
                                   "main", "fake-token", client=FakeClient())
        names = [c["check"] for c in report["checks"]]
        self.assertIn("pr_refs_issue", names)
        self.assertIn("author_intent", names)

    def test_report_serializable(self):
        client = FakeClient(search_map={
            '"182" type:pr repo:a/b': [pr_item(183, "dup")]})
        report = antidup_check.run("a/b", ["CVE-2026-1"], 182, None,
                                   "main", "fake-token", client=client)
        payload = json.dumps(report)  # tanpa TypeError
        self.assertIn("STOP", payload)


if __name__ == "__main__":
    unittest.main()

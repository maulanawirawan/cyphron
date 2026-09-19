"""Tests for cyphron.anomaly — baseline anomaly detector + invariant library."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from cyphron.anomaly import (
    InvariantLibrary, ResponseBaseline, zero_day_candidates)
from cyphron.world.model import Endpoint, WorldModel


def make_world(*endpoints, notes=None):
    """Build a synthetic WorldModel from (url, status) pairs + notes."""
    world = WorldModel()
    for url, status in endpoints:
        world.endpoints[url] = Endpoint(url=url, status=status)
    for note in notes or []:
        world.note(note)
    return world


def violation_ids(library, world):
    return [v["id"] for v in library.run_all(world)]


class TestClassifyPath(unittest.TestCase):
    def test_four_classes(self):
        classify = ResponseBaseline.classify_path
        self.assertEqual(classify("/api/v1/users"), "api")
        self.assertEqual(classify("/admin/panel"), "admin")
        self.assertEqual(classify("/login"), "auth")
        self.assertEqual(classify("/about"), "public")

    def test_auth_variants(self):
        classify = ResponseBaseline.classify_path
        self.assertEqual(classify("/auth/token"), "auth")
        self.assertEqual(classify("/signin"), "auth")

    def test_api_takes_precedence_over_admin(self):
        self.assertEqual(ResponseBaseline.classify_path("/api/admin"), "api")


class TestResponseBaseline(unittest.TestCase):
    def setUp(self):
        self.baseline = ResponseBaseline()
        body = "A" * 100
        for _ in range(5):
            self.baseline.learn("public", 200, body)

    def test_normal_response_is_not_anomaly(self):
        self.assertIsNone(self.baseline.check("public", 200, "A" * 100))

    def test_status_deviation_is_anomaly(self):
        result = self.baseline.check("public", 500, "A" * 100)
        self.assertIsNotNone(result)
        self.assertEqual(result["url_class"], "public")
        self.assertEqual(result["expected_status"], 200)
        self.assertEqual(result["status"], 500)
        self.assertIn("reason", result)
        self.assertIn("len_delta_pct", result)

    def test_length_deviation_is_anomaly(self):
        result = self.baseline.check("public", 200, "B" * 900)
        self.assertIsNotNone(result)
        self.assertGreater(result["len_delta_pct"], 300)

    def test_unknown_class_returns_none(self):
        self.assertIsNone(self.baseline.check("auth", 200, ""))


class TestInvariantNoWriteAnon(unittest.TestCase):
    def test_confirmed_anon_write_violates(self):
        world = make_world(
            notes=["anonymous write confirmed on /api/items via POST"])
        self.assertIn("INV-NO-WRITE-ANON", violation_ids(InvariantLibrary(), world))

    def test_confirmed_anon_delete_violates(self):
        world = make_world(
            notes=["anonymous delete confirmed on /api/items/42"])
        self.assertIn("INV-NO-WRITE-ANON", violation_ids(InvariantLibrary(), world))

    def test_unconfirmed_note_is_not_violation(self):
        world = make_world(notes=["write attempt failed", "delete blocked"])
        self.assertNotIn(
            "INV-NO-WRITE-ANON", violation_ids(InvariantLibrary(), world))


class TestInvariantAdminNotPublic(unittest.TestCase):
    def test_admin_200_with_sensitive_body_violates(self):
        world = make_world(("/admin", 200))
        lib = InvariantLibrary()
        lib.record("/admin", 200, "user list dashboard")
        self.assertIn("INV-ADMIN-NOT-PUBLIC", violation_ids(lib, world))

    def test_admin_200_without_sensitive_body_no_violation(self):
        world = make_world(("/admin", 200))
        lib = InvariantLibrary()
        lib.record("/admin", 200, "welcome to the admin login page")
        self.assertNotIn("INV-ADMIN-NOT-PUBLIC", violation_ids(lib, world))

    def test_admin_403_no_violation(self):
        world = make_world(("/admin", 403))
        lib = InvariantLibrary()
        lib.record("/admin", 403, "user list dashboard")
        self.assertNotIn("INV-ADMIN-NOT-PUBLIC", violation_ids(lib, world))

    def test_clean_world_no_violation(self):
        world = make_world(("/", 200), ("/about", 200))
        self.assertEqual(InvariantLibrary().run_all(world), [])

    def test_body_matched_by_path_fallback(self):
        world = make_world(("http://target.test/admin", 200))
        lib = InvariantLibrary()
        lib.record("/admin", 200, "user list")
        self.assertIn("INV-ADMIN-NOT-PUBLIC", violation_ids(lib, world))


class TestInvariantStatusConsistency(unittest.TestCase):
    def test_three_unique_statuses_violate(self):
        lib = InvariantLibrary()
        lib.record("/flap", 200)
        lib.record("/flap", 500)
        lib.record("/flap", 302)
        self.assertIn(
            "INV-STATUS-CONSISTENCY", violation_ids(lib, make_world()))

    def test_two_statuses_is_allowed(self):
        lib = InvariantLibrary()
        lib.record("/ok", 200)
        lib.record("/ok", 500)
        self.assertNotIn(
            "INV-STATUS-CONSISTENCY", violation_ids(lib, make_world()))


class TestZeroDayCandidates(unittest.TestCase):
    def test_returns_candidates_with_required_keys(self):
        world = make_world(
            ("/", 200), ("/about", 200), ("/contact", 200), ("/health", 500),
            notes=["anonymous delete confirmed on /api/items"],
        )
        candidates = zero_day_candidates(world)
        self.assertIsInstance(candidates, list)
        self.assertTrue(candidates)
        for cand in candidates:
            self.assertIn("source", cand)
            self.assertIn("hypothesis", cand)
            self.assertIn("safe_validation", cand)
        sources = {cand["source"] for cand in candidates}
        self.assertIn("anomaly", sources)
        self.assertIn("invariant", sources)

    def test_quiet_world_yields_no_candidates(self):
        world = make_world(("/", 200), ("/about", 200), ("/login", 200))
        self.assertEqual(zero_day_candidates(world), [])

    def test_baseline_and_library_can_be_shared(self):
        world = make_world(("/api/items", 200), ("/api/items2", 200),
                           ("/api/items3", 500))
        baseline = ResponseBaseline()
        library = InvariantLibrary()
        candidates = zero_day_candidates(world, baseline=baseline, library=library)
        anomalies = [c for c in candidates if c["source"] == "anomaly"]
        self.assertEqual(len(anomalies), 1)
        self.assertEqual(anomalies[0]["url"], "/api/items3")
        self.assertEqual(anomalies[0]["expected_status"], 200)


if __name__ == "__main__":
    unittest.main()

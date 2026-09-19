"""Anomaly detector + business-invariant library (FAZ 3 zero-day research).

Deterministic, zero-LLM generation of zero-day candidate hypotheses:

- ResponseBaseline learns per-path-class response profiles (majority status,
  median body length) and flags responses that deviate from their class.
- InvariantLibrary encodes business invariants that must hold on any sane
  target and reports violations as candidates.
- zero_day_candidates() wires both together over a WorldModel.

Pure stdlib, no network access. Every candidate carries a read-only
``safe_validation`` recipe so verification never mutates the target.
"""

from __future__ import annotations

import statistics
from collections import Counter
from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:  # pragma: no cover - typing only, keeps module standalone
    from cyphron.world.model import WorldModel

__all__ = ["ResponseBaseline", "InvariantLibrary", "zero_day_candidates"]

# Body length is anomalous when it deviates more than this % from the median
# length observed for the same path class.
LEN_DELTA_PCT_THRESHOLD = 300.0

ANOMALY_HYPOTHESIS = "Respons menyimpang dari baseline kelasnya"
ANOMALY_SAFE_VALIDATION = "Uji ulang manual 3x dan bandingkan body"

_CLAIM_NO_WRITE_ANON = "Resource anonim tidak boleh dibuat/dihapus tanpa auth"
_CLAIM_ADMIN_NOT_PUBLIC = "Panel admin tidak menyajikan data tanpa auth"
_CLAIM_STATUS_CONSISTENCY = "URL sama tidak boleh berpindah status acak"

_AUTH_WORDS = ("login", "auth", "signin")
_ADMIN_BODY_MARKERS = ("user list", "dashboard")


def _endpoints_of(world: "WorldModel") -> list[tuple[str, object]]:
    """Duck-typed (url, endpoint) pairs from a WorldModel-like object."""
    endpoints = getattr(world, "endpoints", None) or {}
    return list(endpoints.items())


class ResponseBaseline:
    """Learns normal response behaviour per URL class and flags deviations.

    A class is derived from the URL path via :meth:`classify_path`. For each
    class we track observed statuses (majority = expected status) and body
    lengths (median = expected length). ``check`` reports an anomaly dict when
    a response's status differs from the class majority or its length deviates
    more than :data:`LEN_DELTA_PCT_THRESHOLD` percent from the median.
    """

    def __init__(self) -> None:
        self._statuses: dict[str, list[int]] = {}
        self._lengths: dict[str, list[int]] = {}

    @staticmethod
    def classify_path(path: str) -> str:
        """Map a URL path to one of the baseline classes."""
        p = (path or "").lower()
        if "/api/" in p:
            return "api"
        if "admin" in p:
            return "admin"
        if any(word in p for word in _AUTH_WORDS):
            return "auth"
        return "public"

    def learn(self, url_class: str, status: int, body: str) -> None:
        """Record one observed response for ``url_class``."""
        self._statuses.setdefault(url_class, []).append(int(status))
        self._lengths.setdefault(url_class, []).append(len(body or ""))

    def majority_status(self, url_class: str) -> int | None:
        """Most frequently observed status for the class (None if unlearned)."""
        statuses = self._statuses.get(url_class)
        if not statuses:
            return None
        # Counter.most_common breaks ties by insertion order -> deterministic.
        return Counter(statuses).most_common(1)[0][0]

    def median_length(self, url_class: str) -> float:
        """Median observed body length for the class (0.0 if unlearned)."""
        lengths = self._lengths.get(url_class)
        if not lengths:
            return 0.0
        return statistics.median(lengths)

    def check(self, url_class: str, status: int, body: str) -> dict | None:
        """Return an anomaly dict if the response deviates from its class.

        Anomaly dict keys: ``url_class``, ``expected_status``, ``status``,
        ``len_delta_pct``, ``reason``. Returns None when the class has no
        learned baseline or the response matches it.
        """
        statuses = self._statuses.get(url_class) or []
        lengths = self._lengths.get(url_class) or []
        if not statuses and not lengths:
            return None  # nothing learned for this class yet

        expected = self.majority_status(url_class)
        status_anomaly = bool(statuses) and int(status) != expected

        body_len = len(body or "")
        median = self.median_length(url_class)
        if median > 0:
            delta_pct = abs(body_len - median) / median * 100.0
        else:
            delta_pct = 0.0 if body_len == 0 else float("inf")
        length_anomaly = bool(lengths) and delta_pct > LEN_DELTA_PCT_THRESHOLD

        if not (status_anomaly or length_anomaly):
            return None

        reasons: list[str] = []
        if status_anomaly:
            reasons.append(
                f"status {status} differs from baseline majority {expected} "
                f"for class '{url_class}'")
        if length_anomaly:
            reasons.append(
                f"body length deviates {round(delta_pct, 1)}% from median "
                f"{median} (> {LEN_DELTA_PCT_THRESHOLD:g}% threshold)")
        return {
            "url_class": url_class,
            "expected_status": expected,
            "status": int(status),
            "len_delta_pct": round(delta_pct, 1),
            "reason": "; ".join(reasons),
        }


class InvariantLibrary:
    """Business invariants that must hold on any target.

    Violations become zero-day candidates via :func:`zero_day_candidates`.
    :meth:`record` feeds the runtime evidence store used by
    INV-ADMIN-NOT-PUBLIC (last body per URL) and INV-STATUS-CONSISTENCY
    (status history per URL).
    """

    def __init__(self) -> None:
        self._status_history: dict[str, list[int]] = {}
        self._last_body: dict[str, str] = {}
        self.invariants: list[dict] = [
            {
                "id": "INV-NO-WRITE-ANON",
                "claim": _CLAIM_NO_WRITE_ANON,
                "check": self._check_no_write_anon,
                "safe_validation": (
                    "Read-only: telusuri log permintaan yang menyebut "
                    "write/delete terkonfirmasi, ulangi observasi tanpa "
                    "kredensial dengan GET, dan pastikan resource tidak "
                    "benar-benar berubah."
                ),
            },
            {
                "id": "INV-ADMIN-NOT-PUBLIC",
                "claim": _CLAIM_ADMIN_NOT_PUBLIC,
                "check": self._check_admin_not_public,
                "safe_validation": (
                    "Read-only: buka ulang URL admin yang sama tanpa "
                    "kredensial, simpan body respons, dan cocokkan apakah "
                    "memuat data sensitif (user list/dashboard); jangan "
                    "mencoba login atau bypass."
                ),
            },
            {
                "id": "INV-STATUS-CONSISTENCY",
                "claim": _CLAIM_STATUS_CONSISTENCY,
                "check": self._check_status_consistency,
                "safe_validation": (
                    "Read-only: request ulang URL yang sama 3x dalam sesi "
                    "terpisah tanpa mengubah state, lalu bandingkan status; "
                    ">2 status unik menandakan routing/cache yang layak "
                    "diteliti."
                ),
            },
        ]

    # ------------------------------------------------------------------ #
    # Evidence store
    # ------------------------------------------------------------------ #
    def record(self, url: str, status: int, body: str = "") -> None:
        """Store one observed response: status history + last body per URL."""
        url = str(url)
        self._status_history.setdefault(url, []).append(int(status))
        if body:
            self._last_body[url] = body

    def _body_for(self, url: str) -> str:
        """Last recorded body for ``url``, matched by path as a fallback."""
        if url in self._last_body:
            return self._last_body[url]
        path = urlsplit(url).path
        for known, body in self._last_body.items():
            if urlsplit(known).path == path:
                return body
        return ""

    # ------------------------------------------------------------------ #
    # Invariant checks (each returns at most one violation dict)
    # ------------------------------------------------------------------ #
    def _check_no_write_anon(self, world: "WorldModel") -> dict | None:
        for note in getattr(world, "notes", None) or []:
            text = str(note).lower()
            if "confirmed" in text and ("write" in text or "delete" in text):
                return {
                    "id": "INV-NO-WRITE-ANON",
                    "claim": _CLAIM_NO_WRITE_ANON,
                    "evidence": f"note: {note}",
                }
        return None

    def _check_admin_not_public(self, world: "WorldModel") -> dict | None:
        for url, ep in _endpoints_of(world):
            path = urlsplit(str(url)).path.lower()
            if "admin" not in path:
                continue
            if getattr(ep, "status", None) != 200:
                continue
            body = self._body_for(str(url))
            if not body:
                continue  # no recorded body -> cannot verify, not applicable
            markers = [m for m in _ADMIN_BODY_MARKERS if m in body.lower()]
            if markers:
                return {
                    "id": "INV-ADMIN-NOT-PUBLIC",
                    "claim": _CLAIM_ADMIN_NOT_PUBLIC,
                    "evidence": (
                        f"{url} (status 200) menyajikan body dengan marker "
                        f"sensitif: {', '.join(markers)}"
                    ),
                }
        return None

    def _check_status_consistency(self, world: "WorldModel") -> dict | None:
        worst: tuple[str, set[int]] | None = None
        for url, history in self._status_history.items():
            unique = set(history)
            if len(unique) <= 2:
                continue
            if worst is None or len(unique) > len(worst[1]):
                worst = (url, unique)
        if worst is None:
            return None
        url, unique = worst
        return {
            "id": "INV-STATUS-CONSISTENCY",
            "claim": _CLAIM_STATUS_CONSISTENCY,
            "evidence": (
                f"{url} mengembalikan {len(unique)} status unik: "
                f"{sorted(unique)}"
            ),
        }

    # ------------------------------------------------------------------ #
    # Public API
    # ------------------------------------------------------------------ #
    def run_all(self, world: "WorldModel") -> list[dict]:
        """Run every invariant and return all violations."""
        violations: list[dict] = []
        for invariant in self.invariants:
            violation = invariant["check"](world)
            if violation:
                violations.append(violation)
        return violations


def zero_day_candidates(
    world: "WorldModel",
    baseline: ResponseBaseline | None = None,
    library: InvariantLibrary | None = None,
) -> list[dict]:
    """Collect deterministic zero-day candidates from a WorldModel.

    Two sources, merged into one list:

    - ``source="anomaly"``: learn a response baseline from every endpoint
      (path class + status), then flag endpoints whose response deviates
      from their class baseline.
    - ``source="invariant"``: violations of the business invariants in
      ``library`` (fresh by default; pass a long-lived library that has been
      fed with :meth:`InvariantLibrary.record` to enable body/history-based
      invariants).

    Each candidate dict contains at least ``source``, ``hypothesis`` and
    ``safe_validation`` (a read-only verification recipe).
    """
    baseline = baseline if baseline is not None else ResponseBaseline()
    library = library if library is not None else InvariantLibrary()

    observed: list[tuple[str, str, int]] = []
    for url, ep in _endpoints_of(world):
        status = getattr(ep, "status", None)
        if status is None:
            continue
        path = urlsplit(str(url)).path
        url_class = ResponseBaseline.classify_path(path)
        baseline.learn(url_class, int(status), "")
        observed.append((str(url), url_class, int(status)))

    candidates: list[dict] = []
    for url, url_class, status in observed:
        anomaly = baseline.check(url_class, status, "")
        if anomaly:
            candidates.append({
                "source": "anomaly",
                "hypothesis": ANOMALY_HYPOTHESIS,
                "safe_validation": ANOMALY_SAFE_VALIDATION,
                "url": url,
                "url_class": anomaly["url_class"],
                "expected_status": anomaly["expected_status"],
                "status": anomaly["status"],
                "len_delta_pct": anomaly["len_delta_pct"],
                "reason": anomaly["reason"],
            })

    safe_by_id = {inv["id"]: inv["safe_validation"] for inv in library.invariants}
    for violation in library.run_all(world):
        inv_id = violation.get("id", "")
        candidates.append({
            "source": "invariant",
            "hypothesis": violation.get("claim", inv_id),
            "safe_validation": safe_by_id.get(inv_id, ""),
            "invariant": inv_id,
            "evidence": violation.get("evidence"),
        })
    return candidates

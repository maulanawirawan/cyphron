"""Shared framework for the attack/exploit skill pack (25 skills).

Design contracts (same as the rest of skillpack):
- FAIL-CLOSED LAB GATE: no --lab flag, no run.
- findings.json one-pintu output via lib.findings (verdict ladder fields).
- DETERMINISTIC skills: fixed payload set + control pair + reproduce 2x
  before any L3 claim.
- NON-DETERMINISTIC skills: payload/order sampling with a seeded RNG whose
  seed is recorded in `meta.rng_seed` and in every finding's extra - a run
  can be replayed exactly.
- Stealth: realistic UA, default delay, bounded request counts.
"""

from __future__ import annotations

import random
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from lib.findings import make_finding, write_findings  # noqa: E402

from attack.blackbox_recon import STEALTH_UA, require_lab  # noqa: E402,F401


class AttackClient:
    def __init__(self, delay: float = 0.5, timeout: float = 10.0):
        self.delay = delay
        self.timeout = timeout
        self.request_log: list[dict] = []

    def _do(self, url: str, data: bytes | None, headers: dict) -> tuple[int, dict, bytes]:
        req = urllib.request.Request(url, data=data, headers={
            "User-Agent": STEALTH_UA, **headers})
        ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                status, hdrs, body = resp.status, dict(resp.headers), resp.read(300_000)
        except urllib.error.HTTPError as exc:
            status = exc.code
            hdrs = dict(exc.headers or {})
            body = exc.read(200_000) if exc.fp else b""
        except Exception as exc:
            self.request_log.append({"ts": ts, "url": url, "status": 0,
                                     "error": type(exc).__name__})
            time.sleep(self.delay)
            return 0, {}, b""
        self.request_log.append({"ts": ts, "url": url, "status": status})
        time.sleep(self.delay)
        return status, hdrs, body

    def get(self, url: str, headers: dict | None = None) -> tuple[int, dict, bytes]:
        return self._do(url, None, headers or {})

    def post(self, url: str, body: str | bytes, content_type: str,
             headers: dict | None = None) -> tuple[int, dict, bytes]:
        data = body.encode() if isinstance(body, str) else body
        return self._do(url, data, {"Content-Type": content_type, **(headers or {})})


def marker(prefix: str = "hop") -> str:
    """Unique, low-noise marker (timestamp-based, 8 chars)."""
    return f"{prefix}{int(time.time()) % 10_000_000:07d}"


def set_with_param(url: str, param: str, value: str) -> str:
    parts = urllib.parse.urlsplit(url)
    q = [(k, value if k == param else v)
         for k, v in urllib.parse.parse_qsl(parts.query, keep_blank_values=True)]
    # bug #15 (audit 2026-10-05): param yang BELUM ada di query dulunya
    # di-diam-diamkan - payload tak pernah terkirim (false-negative senyap
    # di semua skill yang terima --url tanpa query). Sekarang ditambahkan.
    if not any(k == param for k, _ in q):
        q.append((param, value))
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path,
                                    urllib.parse.urlencode(q), parts.fragment))


def rng_for(seed: int | None, name: str) -> random.Random:
    """Seeded RNG for non-deterministic skills; the seed is recorded so a
    run is exactly replayable."""
    return random.Random(seed if seed is not None else
                         int(time.time() * 1000) % 2**31)


def emit(out: str, findings: list, meta: dict, client: AttackClient,
         extra_meta: dict | None = None) -> None:
    meta = dict(meta or {})
    meta["request_log"] = client.request_log
    meta["request_count"] = len(client.request_log)
    if client.request_log:
        meta["started_at"] = client.request_log[0]["ts"]
        meta["ended_at"] = client.request_log[-1]["ts"]
    if extra_meta:
        meta.update(extra_meta)
    write_findings(out, findings, meta=meta)


def finding(**kwargs):
    return make_finding(tool=kwargs.pop("tool"), **kwargs)


def standard_args(argv: list[str], ap) -> argparse.Namespace:  # noqa: F821
    import argparse
    if not isinstance(ap, argparse.ArgumentParser):
        raise TypeError("pass an ArgumentParser")
    args, _unknown = ap.parse_known_args(argv)  # --lab is a gate flag
    return args

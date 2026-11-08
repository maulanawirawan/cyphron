"""Nol jaringan — test rust_binary_triage (#0942, identifikasi biner Rust
+ inventaris crate + kapabilitas).

Fixtures = blob sintetis dibangun runtime (string runtime Rust, jalur
registry, simbol legacy-mangled yang didekode manual).
"""
from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1] / "tools"
sys.path.insert(0, str(TOOLS))

import rust_binary_triage as rbt  # noqa: E402


def _scan_tmp(data: bytes):
    """Tulis blob ke berkas sementara, scan, kembalikan (result, path)."""
    with tempfile.NamedTemporaryFile(delete=False) as fh:
        fh.write(data)
        p = Path(fh.name)
    return rbt.scan(p), p


def _rust_blob() -> bytes:
    parts = [
        b"\x7fELF" + b"\x00" * 40,
        b"panicked at 'called `Option::unwrap()` on a `None` value', "
        b"src/main.rs:42:5",
        b"core::panicking::panic_bounds_check",
        b"std::rt::lang_start_internal",
        b"rustc 1.79.0 (129f3b994 2024-06-10)",
        b"/home/user/.cargo/registry/src/index.crates.io-"
        b"6f17d22bba15001f/tokio-1.38.0/src/net/tcp.rs",
        b"/home/user/.cargo/registry/src/index.crates.io-"
        b"6f17d22bba15001f/reqwest-0.12.5/src/async_impl/client.rs",
        b"/home/user/.cargo/registry/src/index.crates.io-"
        b"6f17d22bba15001f/aes-0.8.4/src/aes.rs",
        # simbol legacy (dipisah NUL — seperti tabel simbol biner nyata)
        b"_ZN5tokio3net5lookup17h0123456789abcdefE\x00",
        b"_ZN4core6result13unwrap_failed17hdeadbeefcafebabeE\x00",
        b"_ZN7stealer4keys4grab17h00ff00ff00ff00ffE\x00",
        b"https://c2.example.net/upload",
        b"mutex poisoning guard pipe",
        b"\x00" * 64,
    ]
    return b"".join(parts)


class TestVerdict(unittest.TestCase):
    def test_rust_likely_full_blob(self):
        r, p = _scan_tmp(_rust_blob())
        try:
            self.assertEqual(r["verdict"], "RUST-LIKELY")
            ids = {s["id"] for s in r["indicators"]}
            self.assertIn("panic-string", ids)
            self.assertIn("rustc-version", ids)
            self.assertIn("cargo-registry", ids)
            self.assertEqual(r["rustc_versions"], ["1.79.0"])
        finally:
            p.unlink()

    def test_one_indicator_only_possible(self):
        data = b"\x00" * 32 + b"panicked at src/lib.rs:1" + b"\x00" * 32
        r, p = _scan_tmp(data)
        try:
            self.assertEqual(r["verdict"], "RUST-POSSIBLE")
        finally:
            p.unlink()

    def test_registry_paths_threshold_becomes_indicator(self):
        # >= 3 crate registry = indikator kompilasi; dgn panic string
        # (total 2 indikator) -> RUST-LIKELY meski tanpa versi rustc
        data = (b"panicked at src/x.rs:1\x00"
                b"crates.io-6f17d22bba15001f/tokio-1.38.0/src/lib.rs\x00"
                b"crates.io-6f17d22bba15001f/hyper-1.0.0/src/x.rs\x00"
                b"crates.io-6f17d22bba15001f/aes-0.8.4/src/lib.rs\x00")
        r, p = _scan_tmp(data)
        try:
            self.assertEqual(r["verdict"], "RUST-LIKELY")
            self.assertIn("crates-io-paths",
                          {s["id"] for s in r["indicators"]})
        finally:
            p.unlink()

    def test_few_registry_paths_not_indicator(self):
        # < 3 crate: TIDAK jadi indikator (anti-FP dokumen teks)
        data = (b"panicked at src/x.rs:1\x00"
                b"crates.io-6f17d22bba15001f/tokio-1.38.0/src/lib.rs\x00")
        r, p = _scan_tmp(data)
        try:
            self.assertEqual(r["verdict"], "RUST-POSSIBLE")
            self.assertNotIn("crates-io-paths",
                             {s["id"] for s in r["indicators"]})
        finally:
            p.unlink()

    def test_no_evidence_not_claimed_not_rust(self):
        r, p = _scan_tmp(b"\x41" * 4096)
        try:
            self.assertEqual(r["verdict"], "NO-RUST-EVIDENCE")
            ids = {f["id"] for f in r["findings"]}
            self.assertIn("meta.no-rust-evidence", ids)
        finally:
            p.unlink()


class TestCrates(unittest.TestCase):
    def test_registry_and_symbols(self):
        r, p = _scan_tmp(_rust_blob())
        try:
            self.assertEqual(r["crates"]["tokio"], "1.38.0")
            self.assertEqual(r["crates"]["reqwest"], "0.12.5")
            self.assertEqual(r["crates"]["aes"], "0.8.4")
            # crate dari simbol: stealer (tokio/core sudah dari registry)
            self.assertIn("stealer", r["crates_from_symbols"])
            # core/std TIDAK masuk crate (runtime segment difilter)
            self.assertNotIn("core", r["crates_from_symbols"])
            self.assertNotIn("std", r["crates_from_symbols"])
        finally:
            p.unlink()

    def test_legacy_decode(self):
        segs = rbt._decode_legacy_mangle(b"7stealer4keys4grab")
        self.assertEqual(segs, ["stealer", "keys", "grab"])
        # malformed: length melebihi payload -> None
        self.assertIsNone(rbt._decode_legacy_mangle(b"99ab"))
        # length 0 -> None
        self.assertIsNone(rbt._decode_legacy_mangle(b"0x"))

    def test_crate_from_runtime_prefix(self):
        segs = ["core", "stealer"]
        self.assertEqual(rbt._crate_from_segments(segs), "stealer")
        self.assertIsNone(rbt._crate_from_segments(["core", "alloc"]))


class TestCapabilities(unittest.TestCase):
    def test_capability_leads(self):
        r, p = _scan_tmp(_rust_blob())
        try:
            classes = {c["class"] for c in r["capabilities"]}
            self.assertIn("network", classes)          # reqwest/tokio
            self.assertIn("crypto", classes)           # aes
            caps = {c["crate"]: c["class"] for c in r["capabilities"]}
            self.assertEqual(caps.get("aes"), "crypto")
            self.assertEqual(caps.get("reqwest"), "network")
            # semua lead low
            for f in r["findings"]:
                if f["id"].startswith("capability."):
                    self.assertEqual(f["severity"], "low")
        finally:
            p.unlink()


class TestStrings(unittest.TestCase):
    def test_keyword_strings_defanged(self):
        r, p = _scan_tmp(_rust_blob())
        try:
            texts = [s["text"] for s in r["strings"]]
            self.assertTrue(any("c2[.]example[.]net" in t for t in texts))
            # URL di-defang: tidak ada http:// aktif di output
            for t in texts:
                self.assertNotIn("http://", t)
                self.assertNotIn("https://", t)
        finally:
            p.unlink()


class TestCli(unittest.TestCase):
    def test_exit_2_missing_and_empty(self):
        self.assertEqual(rbt.main(["--file", "no-such-file.bin"]), 2)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            p = Path(fh.name)
        try:
            self.assertEqual(rbt.main(["--file", str(p)]), 2)
        finally:
            p.unlink()

    def test_exit_gate(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(_rust_blob())
            p = Path(fh.name)
        try:
            self.assertEqual(rbt.main(["--file", str(p)]), 1)
        finally:
            p.unlink()

    def test_out_writes_json(self):
        with tempfile.TemporaryDirectory() as td:
            src = Path(td) / "s.bin"
            src.write_bytes(_rust_blob())
            dst = Path(td) / "o.json"
            self.assertEqual(rbt.main(["--file", str(src), "--out",
                                       str(dst)]), 1)
            obj = json.loads(dst.read_text(encoding="utf-8"))
            self.assertEqual(obj["schema"], rbt.SCHEMA)
            self.assertTrue(obj["read_only"])
            self.assertEqual(obj["verdict"], "RUST-LIKELY")

    def test_subprocess_clean_blob_exit_0(self):
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(b"\x42" * 2048)
            p = Path(fh.name)
        try:
            proc = subprocess.run(
                [sys.executable, str(TOOLS / "rust_binary_triage.py"),
                 "--file", str(p)],
                capture_output=True, text=True, timeout=120)
            self.assertEqual(proc.returncode, 0)
            obj = json.loads(proc.stdout)
            self.assertEqual(obj["verdict"], "NO-RUST-EVIDENCE")
        finally:
            p.unlink()


if __name__ == "__main__":
    unittest.main()

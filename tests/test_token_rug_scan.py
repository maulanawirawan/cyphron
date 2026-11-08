"""Nol jaringan — test token_rug_scan (postur rug dari sumber kontrak;
lead maks L2 + note LP-lock jujur; fail-closed; tanpa klaim harga/likuiditas).

Fixture kontrak ditulis runtime ke tmp (inline di file ini) — tanpa
kompilasi Solidity, tanpa jaringan, deterministik.
"""
from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "core"))

import token_rug_scan as trs  # noqa: E402
from findings import verdict_tag  # noqa: E402

# ── Fixture: token bergaya rug menyentuh 8 vektor + note LP ─────────────────

RUG_TOKEN = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

contract RugToken {
    uint256 public _totalSupply = 1_000_000e18;
    mapping(address => uint256) public _balances;
    mapping(address => bool) public isBlacklisted;
    mapping(address => bool) public isExcludedFromFee;
    uint256 public _taxFee = 2;
    uint256 public maxTxAmount = 20_000e18;
    bool public tradingEnabled;
    address public uniswapV2Pair;
    address public _backupOwner;

    event Transfer(address indexed from, address indexed to, uint256 v);

    constructor() { _backupOwner = tx.origin; }

    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        _totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    function setBlacklist(address a, bool v) external { isBlacklisted[a] = v; }

    function setFees(uint256 f) external { _taxFee = f; }

    function removeLimits() external { maxTxAmount = _totalSupply; }

    function setTrading(bool v) external { tradingEnabled = v; }

    function setPair(address p) external { uniswapV2Pair = p; }

    function upgradeTo(address impl, bytes memory data) external {
        impl.delegatecall(data);
    }

    function renounceOwnership() public virtual override {}

    function transfer(address to, uint256 amount) public returns (bool) {
        require(!isBlacklisted[msg.sender]);
        if (to == uniswapV2Pair) { require(tradingEnabled); }
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    // LP akan dikunci 1 tahun di PinkLock setelah launch (janji tim).
}
"""

# ── Fixture: token bersih — harus nol temuan ────────────────────────────────

CLEAN_TOKEN = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

contract CleanToken {
    uint256 public _totalSupply;
    mapping(address => uint256) public _balances;
    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 v);

    constructor() {
        owner = msg.sender;
        _totalSupply = 1_000_000e18;
        _balances[msg.sender] = 1_000_000e18;
        emit Transfer(address(0), msg.sender, 1_000_000e18);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(_balances[msg.sender] >= amount);
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }
}
"""


def _run_main(tmp: Path, target: Path, *extra: str):
    out = tmp / "result.json"
    code = trs.main([str(target), "--out", str(out), *extra])
    return code, (json.loads(out.read_text(encoding="utf-8"))
                  if out.exists() else None)


class DeteksiVektorRug(unittest.TestCase):
    def test_delapan_vektor_terdeteksi(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "RugToken.sol").write_text(RUG_TOKEN, encoding="utf-8")
            code, res = _run_main(tmp, tmp / "RugToken.sol")
            self.assertEqual(code, 0)
            for vektor in ("MINT_UNBOUNDED", "BLACKLIST_CONTROL",
                           "PROXY_UPGRADEABILITY", "FEE_UNBOUNDED",
                           "WHALE_GUARD_BYPASSABLE",
                           "HONEYPOT_SELL_PATTERN",
                           "FAKE_RENOUNCE_SIGNALS", "LP_CONTROL"):
                self.assertTrue(res["vectors"][vektor],
                                f"vektor {vektor} tidak terdeteksi")

    def test_mint_tanpa_cap_tapi_cap_tertandai_rendah(self) -> None:
        # mint DENGAN cap -> hanya lead low "verifikasi kelengkapan"
        capped = RUG_TOKEN.replace(
            "function mint(address to, uint256 amount) external {",
            "function mint(address to, uint256 amount) external {\n"
            "        require(_totalSupply + amount <= 1_000_000e18);")
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "C.sol").write_text(capped, encoding="utf-8")
            _, res = _run_main(tmp, tmp / "C.sol")
            mint_fns = [f for f in res["findings"]
                        if f["class_id"] == "MINT_UNBOUNDED"
                        and "cap" in f["title"].lower()]
            self.assertTrue(mint_fns)
            self.assertTrue(all(f["severity"] == "low" for f in mint_fns))

    def test_note_lp_lock_jujur_l0(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "RugToken.sol").write_text(RUG_TOKEN, encoding="utf-8")
            _, res = _run_main(tmp, tmp / "RugToken.sol")
            notes = [f for f in res["findings"]
                     if f["class_id"] == "LP_LOCK_NOTE"]
            self.assertEqual(len(notes), 1)
            note = notes[0]
            self.assertEqual(note["verdict"], 0)
            # tag dari satu pintu core: L0 lead ber-sufiks - LEAD
            self.assertEqual(note["verdict_tag"], "L0 OBSERVED - LEAD")
            self.assertIn("TAK TERVERIFIKASI", note["title"])
            self.assertIn("bukti on-chain", note["rationale"] +
                          note["note"])

    def test_kontrak_bersih_nol_temuan(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "CleanToken.sol").write_text(CLEAN_TOKEN, encoding="utf-8")
            code, res = _run_main(tmp, tmp / "CleanToken.sol")
            self.assertEqual(code, 0)
            self.assertEqual(res["summary"]["total"], 0)
            self.assertFalse(any(res["vectors"].values()))

    def test_transfer_standar_tidak_dianggap_mint(self) -> None:
        # _balances[to] += di transfer standar BUKAN manipulasi langsung
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "CleanToken.sol").write_text(CLEAN_TOKEN, encoding="utf-8")
            _, res = _run_main(tmp, tmp / "CleanToken.sol")
            self.assertNotIn("MINT_UNBOUNDED",
                             {f["class_id"] for f in res["findings"]})


class KontrakVerdict(unittest.TestCase):
    def test_semua_temuan_lead_maks_l2_dan_ber_eviden(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "RugToken.sol").write_text(RUG_TOKEN, encoding="utf-8")
            _, res = _run_main(tmp, tmp / "RugToken.sol")
            self.assertTrue(res["findings"])
            for f in res["findings"]:
                self.assertIn(f["verdict"], (0, 1, 2))
                self.assertEqual(f["status"], "unconfirmed")
                self.assertFalse(f["reportable"])
                self.assertEqual(f["verdict_tag"], verdict_tag(f["verdict"]))
                self.assertTrue(0.0 <= f["confidence"] <= 1.0)
                self.assertGreaterEqual(f["line"], 1)
                # note L0 boleh snippet kosong; lead wajib bukti
                if f["verdict"] >= 1:
                    self.assertTrue(f["snippet"].strip())

    def test_id_deterministik_dan_unik(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "RugToken.sol").write_text(RUG_TOKEN, encoding="utf-8")
            _, a = _run_main(tmp, tmp / "RugToken.sol")
            _, b = _run_main(tmp, tmp / "RugToken.sol")
            ida = [f["id"] for f in a["findings"]]
            idb = [f["id"] for f in b["findings"]]
            self.assertEqual(ida, idb)
            self.assertEqual(len(ida), len(set(ida)))

    def test_batas_offline_ditulis_eksplisit(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "RugToken.sol").write_text(RUG_TOKEN, encoding="utf-8")
            _, res = _run_main(tmp, tmp / "RugToken.sol")
            joined = " ".join(res["offline_limits"]).lower()
            self.assertIn("harga", joined)
            self.assertIn("likuiditas", joined)
            self.assertIn("on-chain", joined)


class FailClosed(unittest.TestCase):
    def test_target_tidak_ada_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(trs.main([str(Path(td) / "absent.sol")]), 2)

    def test_dir_tanpa_sol_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "notes.txt").write_text("bukan kontrak")
            self.assertEqual(trs.main([str(tmp)]), 2)

    def test_fail_on_high_exit_1(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "RugToken.sol").write_text(RUG_TOKEN, encoding="utf-8")
            self.assertEqual(trs.main([str(tmp / "RugToken.sol"),
                                       "--fail-on", "high"]), 1)

    def test_fail_on_any_pada_bersih_exit_0(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "CleanToken.sol").write_text(CLEAN_TOKEN, encoding="utf-8")
            self.assertEqual(trs.main([str(tmp / "CleanToken.sol"),
                                       "--fail-on", "any"]), 0)

    def test_komentar_teknis_tidak_memicu_vektor(self) -> None:
        anti = """\
pragma solidity 0.8.24;
contract Anti {
    mapping(address => uint256) public _balances;
    // setFees(99) dan removeLimits() hanya komentar
    // upgradeTo + delegatecall juga hanya komentar
    function transfer(address to, uint256 a) public returns (bool) {
        _balances[msg.sender] -= a;
        _balances[to] += a;
        return true;
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "Anti.sol").write_text(anti, encoding="utf-8")
            _, res = _run_main(tmp, tmp / "Anti.sol")
            kelas = {f["class_id"] for f in res["findings"]}
            self.assertNotIn("FEE_UNBOUNDED", kelas)
            self.assertNotIn("WHALE_GUARD_BYPASSABLE", kelas)
            self.assertNotIn("PROXY_UPGRADEABILITY", kelas)


if __name__ == "__main__":
    unittest.main()

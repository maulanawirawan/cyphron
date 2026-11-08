"""Nol jaringan — test solidity_static_audit (10 kelas bug statis .sol;
lead ber-eviden maks L2; keccak/selector; fail-closed).

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

import solidity_static_audit as ssa  # noqa: E402
from findings import verdict_tag  # noqa: E402

# ── Fixture: satu kontrak rentan menyentuh 10 kelas ─────────────────────────

VULN_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity ^0.7.6;

interface IFeed {
    function latestRoundData() external view
        returns (uint80, int256, uint256, uint256, uint80);
}
interface IRouter {
    function swapExactTokensForETH(uint256 a, uint256 out, address[] calldata p,
        address t, uint256 d) external returns (uint256[] memory);
}

contract VulnVault {
    address public owner;
    mapping(address => uint256) public balances;
    IFeed public feed;

    constructor(IFeed f) { owner = tx.origin; feed = f; }

    function initialize(address o) external { owner = o; }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        (bool ok, ) = msg.sender.call{value: amount}("");
        ok;
        balances[msg.sender] -= amount;
    }

    function emergencyDrain() external {
        payable(msg.sender).send(address(this).balance);
        balances[msg.sender] = 0;
    }

    function adminExec(address t, bytes memory d) external {
        t.delegatecall(d);
    }

    function kill() external { selfdestruct(payable(owner)); }

    function setOwnerByTxOrigin(address n) external {
        require(tx.origin == owner, "no");
        owner = n;
    }

    function collateral() external view returns (uint256) {
        (, int256 p, , , ) = feed.latestRoundData();
        return uint256(p) * balances[msg.sender];
    }

    function swapOut(address r, address[] memory path) external {
        IRouter(r).swapExactTokensForETH(balances[msg.sender], 0, path,
            msg.sender, block.timestamp + 15);
    }
}
"""

# ── Fixture: versi diperbaiki — harus bersih ────────────────────────────────

FIXED_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

interface IFeed {
    function latestRoundData() external view
        returns (uint80, int256, uint256, uint256, uint80);
}

contract FixedVault {
    address public owner;
    IFeed public immutable feed;
    uint256 public constant MAX_AGE = 1 hours;
    mapping(address => uint256) private balances;

    modifier onlyOwner() { require(msg.sender == owner, "no"); _; }

    constructor(IFeed f) { owner = msg.sender; feed = f; }

    function initialize(address o) external onlyOwner { owner = o; }

    function deposit() external payable { balances[msg.sender] += msg.value; }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "fail");
    }

    function drain() external onlyOwner {
        uint256 amt = address(this).balance;
        (bool ok, ) = msg.sender.call{value: amt}("");
        require(ok, "fail");
    }

    function collateral() external view returns (uint256) {
        (, int256 p, , uint256 updatedAt, ) = feed.latestRoundData();
        require(p > 0);
        require(block.timestamp - updatedAt <= MAX_AGE);
        return uint256(p) * balances[msg.sender];
    }
}
"""

SEL_CONTRACT = """\
// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
contract Sel {
    function transfer(address to, uint256 amount) external {}
    function approve(address s, uint256 v) external {}
    function balanceOf(address w) external view returns (uint256) {}
    function totalSupply() external view returns (uint256) {}
    function pair(MyStruct a, uint256 b) external {}
}
"""


def _write(tmp: Path, name: str, content: str) -> Path:
    p = tmp / name
    p.write_text(content, encoding="utf-8")
    return p


def _run_main(tmp: Path, target: Path, *extra: str) -> dict:
    out = tmp / "result.json"
    code = ssa.main([str(target), "--out", str(out), *extra])
    return code, (json.loads(out.read_text(encoding="utf-8"))
                  if out.exists() else None)


class KeccakSelector(unittest.TestCase):
    def test_vektor_resmi_keccak(self) -> None:
        self.assertEqual(ssa.keccak256(b"").hex(), ssa.KECCAK_EMPTY)
        self.assertEqual(ssa.keccak256(b"abc").hex(), ssa.KECCAK_ABC)

    def test_selector_erc20_kanonik(self) -> None:
        # selector ERC20 adalah fakta ABI stabil — jangkar verifikasi
        kasus = {
            "transfer(address,uint256)": "a9059cbb",
            "approve(address,uint256)": "095ea7b3",
            "balanceOf(address)": "70a08231",
            "totalSupply()": "18160ddd",
        }
        for sig, want in kasus.items():
            name, args = sig.split("(", 1)
            got = ssa.canonical_signature(name, args[:-1])
            self.assertEqual(got, sig)
            self.assertEqual("0x" + ssa.keccak256(got.encode()).hex()[:8],
                             "0x" + want)

    def test_selector_tipe_kompleks_jujur_null(self) -> None:
        # struct/tuple/mapping tidak diekspansi ABI offline -> None
        # (tidak ditebak)
        self.assertIsNone(ssa.canonical_signature(
            "pair", "MyStruct a, uint256 b"))
        self.assertIsNone(ssa.canonical_signature(
            "map", "mapping(address => uint256) m"))
        # alias uint -> uint256 pada signature kanonik
        self.assertEqual(
            ssa.canonical_signature("zap", "uint a, uint[] b"),
            "zap(uint256,uint256[])")

    def test_selftest_startup_gagal_internal(self) -> None:
        # vektor resmi dipakai sebagai gerbang: kalau engine rusak -> error
        self.assertTrue(ssa.KECCAK_EMPTY.startswith("c5d24601"))


class Deteksi10Kelas(unittest.TestCase):
    def test_semua_10_kelas_terdeteksi(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "VulnVault.sol", VULN_CONTRACT)
            code, res = _run_main(tmp, tmp)
            self.assertEqual(code, 0)
            kelas = {f["class_id"] for f in res["findings"]}
            self.assertEqual(kelas, {
                "REENTRANCY", "TX_ORIGIN_AUTH", "UNCHECKED_CALL_RETURN",
                "DELEGATECALL_DYNAMIC", "SELFDESTRUCT_PRESENT",
                "PRAGMA_UNCHECKED_ARITHMETIC", "CRITICAL_UNGUARDED",
                "ORACLE_STALENESS", "ORDERING_MEV", "PRAGMA_FLOATING",
            })

    def test_semua_lead_ber_eviden_maks_l2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "VulnVault.sol", VULN_CONTRACT)
            _, res = _run_main(tmp, tmp)
            self.assertTrue(res["findings"])
            for f in res["findings"]:
                self.assertIn(f["verdict"], (1, 2))
                self.assertEqual(f["status"], "unconfirmed")
                self.assertFalse(f["reportable"])
                self.assertEqual(f["verdict_tag"], verdict_tag(f["verdict"]))
                self.assertGreaterEqual(f["line"], 1)
                self.assertTrue(f["snippet"].strip(),
                                "lead tanpa bukti snippet")
                self.assertIn(f["severity"],
                              ("critical", "high", "medium", "low", "info"))
                self.assertTrue(0.0 <= f["confidence"] <= 1.0)

    def test_versi_diperbaiki_bersih(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "FixedVault.sol", FIXED_CONTRACT)
            code, res = _run_main(tmp, tmp)
            self.assertEqual(code, 0)
            self.assertEqual(res["summary"]["total"], 0,
                             json.dumps(res["findings"], indent=1)[:600])

    def test_no_reentrancy_pada_pola_cei(self) -> None:
        # state write SEBELUM call = tidak boleh ada lead reentrancy
        cei = """\
pragma solidity 0.8.24;
contract Cei {
    mapping(address => uint256) balances;
    function withdraw(uint256 a) external {
        require(balances[msg.sender] >= a);
        balances[msg.sender] -= a;
        (bool ok, ) = msg.sender.call{value: a}("");
        require(ok);
    }
}
"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "Cei.sol", cei)
            _, res = _run_main(tmp, tmp)
            reentr = [f for f in res["findings"]
                      if f["class_id"] == "REENTRANCY"]
            self.assertEqual(reentr, [])

    def test_komentar_tidak_memicu_temuan(self) -> None:
        anti = """\
pragma solidity 0.8.24;
contract Anti {
    // selfdestruct(tx.origin) di komentar TIDAK boleh jadi lead
    // delegatecall ke parameter juga hanya komentar
    function ok() external {}
}
"""
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "Anti.sol", anti)
            _, res = _run_main(tmp, tmp)
            kelas = {f["class_id"] for f in res["findings"]}
            self.assertNotIn("SELFDESTRUCT_PRESENT", kelas)
            self.assertNotIn("DELEGATECALL_DYNAMIC", kelas)
            self.assertNotIn("TX_ORIGIN_AUTH", kelas)


class FailClosed(unittest.TestCase):
    def test_target_tidak_ada_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            self.assertEqual(ssa.main([str(Path(td) / "absent.sol")]), 2)

    def test_dir_tanpa_sol_exit_2(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "readme.txt").write_text("bukan kontrak")
            self.assertEqual(ssa.main([str(tmp)]), 2)

    def test_fail_on_medium_exit_1(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "VulnVault.sol", VULN_CONTRACT)
            self.assertEqual(
                ssa.main([str(tmp / "VulnVault.sol"), "--fail-on",
                          "medium"]), 1)

    def test_fail_on_high_pada_bersih_exit_0(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "FixedVault.sol", FIXED_CONTRACT)
            self.assertEqual(
                ssa.main([str(tmp / "FixedVault.sol"), "--fail-on",
                          "any"]), 0)


class DeterminismeOutput(unittest.TestCase):
    def test_dua_run_identik(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "VulnVault.sol", VULN_CONTRACT)
            _, a = _run_main(tmp, tmp)
            _, b = _run_main(tmp, tmp)
            self.assertEqual(json.dumps(a, sort_keys=True),
                             json.dumps(b, sort_keys=True))

    def test_id_deterministik(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "VulnVault.sol", VULN_CONTRACT)
            _, res = _run_main(tmp, tmp)
            ids = [f["id"] for f in res["findings"]]
            self.assertEqual(len(ids), len(set(ids)))
            _, res2 = _run_main(tmp, tmp)
            self.assertEqual(ids, [f["id"] for f in res2["findings"]])

    def test_selector_table_dalam_output(self) -> None:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            _write(tmp, "Sel.sol", SEL_CONTRACT)
            _, res = _run_main(tmp, tmp)
            fns = {f["name"]: f for f in res["functions_by_file"][
                str(tmp / "Sel.sol")]}
            self.assertEqual(fns["transfer"]["selector"], "0xa9059cbb")
            self.assertEqual(fns["approve"]["selector"], "0x095ea7b3")
            self.assertEqual(fns["balanceOf"]["selector"], "0x70a08231")
            self.assertEqual(fns["totalSupply"]["selector"], "0x18160ddd")
            # struct param -> selector null + alasan jujur
            self.assertIsNone(fns["pair"]["selector"])


if __name__ == "__main__":
    unittest.main()

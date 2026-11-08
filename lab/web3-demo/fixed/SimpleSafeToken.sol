// SPDX-License-Identifier: MIT
// KONTRAK DEMO LIVE-VERIFY (analisis statis; BUKAN untuk deploy).
// Versi diperbaiki dari SimpleRugToken.sol — pasokan tetap, tanpa
// blacklist/fee-dinamis/batas-bisa-dimatikan/proxy/pair-setter, dan
// TANPA klaim lock yang tidak bisa diverifikasi. Harus bersih (0 temuan)
// pada tools/token_rug_scan.py.
pragma solidity 0.8.24;

contract SimpleSafeToken {
    string public constant NAME = "Demo Safe";
    string public constant SYMBOL = "SAFE";
    uint8 public constant DECIMALS = 18;

    uint256 public _totalSupply;
    mapping(address => uint256) public _balances;
    address public owner;

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        owner = msg.sender;
        // pasokan tetap: cetak SEKALI di constructor, tanpa fungsi mint
        uint256 total = 1_000_000e18;
        _totalSupply = total;
        _balances[msg.sender] = total;
        emit Transfer(address(0), msg.sender, total);
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(_balances[msg.sender] >= amount, "insufficient");
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount)
        public returns (bool)
    {
        require(_balances[from] >= amount, "insufficient");
        _balances[from] -= amount;
        _balances[to] += amount;
        emit Transfer(from, to, amount);
        return true;
    }
}

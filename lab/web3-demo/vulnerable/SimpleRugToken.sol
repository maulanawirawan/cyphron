// SPDX-License-Identifier: MIT
// KONTRAK DEMO LIVE-VERIFY (analisis statis; BUKAN untuk deploy).
// Contoh realistis karya sendiri untuk secai W2 — token bergaya meme
// dengan vektor rug yang seharusnya tertangkap tools/token_rug_scan.py.
// Bukan untuk deploy; pipeline tool ini murni analisis teks/struktur.
pragma solidity ^0.8.13;

contract SimpleRugToken {
    string public name = "Demo Rug";
    string public symbol = "DRUG";
    uint8 public decimals = 18;

    uint256 public _totalSupply = 1_000_000e18;
    mapping(address => uint256) public _balances;
    mapping(address => bool) public isBlacklisted;
    mapping(address => bool) public isExcludedFromFee;

    uint256 public _taxFee = 2;
    uint256 public maxTxAmount = 20_000e18;
    bool public tradingEnabled;
    address public uniswapV2Pair;
    address public _backupOwner;                 // admin bayangan

    event Transfer(address indexed from, address indexed to, uint256 value);

    constructor() {
        _balances[msg.sender] = _totalSupply;
        _backupOwner = tx.origin;
    }

    // (1) mint tanpa cap supply
    function mint(address to, uint256 amount) external {
        _balances[to] += amount;
        _totalSupply += amount;
        emit Transfer(address(0), to, amount);
    }

    // (2) setter blacklist
    function setBlacklist(address account, bool value) external {
        isBlacklisted[account] = value;
    }

    // (4) setter fee TANPA batas atas
    function setFees(uint256 newFee) external {
        _taxFee = newFee;
    }

    // (5) batas anti-whale bisa dimatikan pemilik
    function removeLimits() external {
        maxTxAmount = _totalSupply;
    }

    // (6) saklar trading dua arah (bisa menutup jual lagi)
    function setTrading(bool value) external {
        tradingEnabled = value;
    }

    // (8) pair dapat diganti (kontrol likuiditas)
    function setPair(address pair) external {
        uniswapV2Pair = pair;
    }

    // (3) proxy marker: upgrade via delegatecall
    function upgradeTo(address newImplementation, bytes memory data)
        external
    {
        newImplementation.delegatecall(data);
    }

    // (7) fake renounce: override tanpa melepas ownership
    function renounceOwnership() public virtual override {
        // kosong: ownership TIDAK dilepas walau tombol renounce ditekan
    }

    function transfer(address to, uint256 amount) public returns (bool) {
        require(!isBlacklisted[msg.sender], "blacklisted");
        if (to == uniswapV2Pair) {
            require(tradingEnabled, "trading closed");
        }
        _balances[msg.sender] -= amount;
        _balances[to] += amount;
        emit Transfer(msg.sender, to, amount);
        return true;
    }

    // (9) note: klaim LP lock hanya tertulis di komentar — TIDAK bisa
    // diverifikasi offline oleh tool mana pun.
    // LP akan dikunci 1 tahun di PinkLock setelah launch (janji tim).
}

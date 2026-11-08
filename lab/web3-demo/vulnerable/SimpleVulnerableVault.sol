// SPDX-License-Identifier: MIT
// KONTRAK DEMO LIVE-VERIFY (analisis statis; BUKAN untuk deploy).
// Contoh realistis karya sendiri untuk secai W2 — memuat pola-pola
// buruk yang seharusnya tertangkap tools/solidity_static_audit.py
// (10 kelas lead). Sengaja TIDAK dideploy & tidak perlu dikompilasi:
// pipeline tool ini murni analisis teks/struktur.
pragma solidity ^0.7.6;

interface IPriceFeed {
    function latestRoundData()
        external view
        returns (uint80 roundId, int256 answer, uint256 startedAt,
                 uint256 updatedAt, uint80 answeredInRound);
}

interface IRouter {
    function swapExactTokensForETH(
        uint256 amountIn, uint256 amountOutMin, address[] calldata path,
        address to, uint256 deadline)
        external returns (uint256[] memory amounts);
}

contract SimpleVulnerableVault {
    address public owner;
    mapping(address => uint256) public balances;
    IPriceFeed public feed;

    constructor(IPriceFeed _feed) {
        owner = tx.origin;                       // (2) tx.origin sebagai identitas
        feed = _feed;
    }

    // (7) fungsi inisialisasi publik tanpa guard apa pun
    function initialize(address newOwner) external {
        owner = newOwner;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        // (1) external call SEBELUM update state -> jendela reentrancy
        (bool ok, ) = msg.sender.call{value: amount}("");
        ok;
        balances[msg.sender] -= amount;
    }

    // (7) tanpa guard + (3) return send diabaikan + menguras pool bersama
    function emergencyWithdrawAll() external {
        payable(msg.sender).send(address(this).balance);
        balances[msg.sender] = 0;
    }

    // (4) delegatecall dengan target dari parameter
    function adminExecute(address target, bytes memory data) external {
        target.delegatecall(data);
    }

    // (5) selfdestruct
    function kill() external {
        selfdestruct(payable(owner));
    }

    // (8) oracle tanpa cek staleness / harga positif
    function collateralValue() external view returns (uint256) {
        (, int256 price, , , ) = feed.latestRoundData();
        return uint256(price) * balances[msg.sender];
    }

    // (9) amountOutMin = 0 (posisi argumen kedua)
    function exitToEth(address router, address[] memory path) external {
        IRouter(router).swapExactTokensForETH(
            balances[msg.sender], 0, path, msg.sender, block.timestamp + 15);
    }

    // (2) tx.origin dipakai untuk otorisasi
    function changeOwner(address next) external {
        require(tx.origin == owner, "not authorized");
        owner = next;
    }
}

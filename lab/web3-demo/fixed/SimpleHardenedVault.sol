// SPDX-License-Identifier: MIT
// KONTRAK DEMO LIVE-VERIFY (analisis statis; BUKAN untuk deploy).
// Versi diperbaiki dari SimpleVulnerableVault.sol — pola yang sama
// ditulis dengan disiplin aman: pin pragma persis, CEI, return di-check,
// guard akses, staleness oracle, min-out swap. Harus bersih (0 lead
// medium+) pada tools/solidity_static_audit.py.
pragma solidity 0.8.24;

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

contract SimpleHardenedVault {
    address public owner;
    IPriceFeed public immutable feed;
    uint256 public constant MAX_PRICE_AGE = 1 hours;
    mapping(address => uint256) private balances;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    constructor(IPriceFeed _feed) {
        owner = msg.sender;
        feed = _feed;
    }

    // guarded: hanya pemilik yang boleh memindahkan kendali
    function initialize(address newOwner) external onlyOwner {
        owner = newOwner;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    // CEI: efek (update state) SEBELUM interaksi (external call);
    // return call di-check.
    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // guarded: drain seluruh saldo hanya untuk pemilik
    function emergencyWithdrawAll() external onlyOwner {
        uint256 amount = address(this).balance;
        balances[msg.sender] = 0;
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // oracle: harga positif + staleness check
    function collateralValue() external view returns (uint256) {
        (, int256 price, , uint256 updatedAt, ) = feed.latestRoundData();
        require(price > 0, "bad price");
        require(block.timestamp - updatedAt <= MAX_PRICE_AGE, "stale");
        return uint256(price) * balances[msg.sender];
    }

    // MEV: min-out dihitung, deadline eksplisit
    function exitToEth(address router, address[] calldata path) external {
        uint256 deadline = block.timestamp + 600;
        uint256 minOut = (collateralValue() * 95) / 100;
        IRouter(router).swapExactTokensForETH(
            balances[msg.sender], minOut, path, msg.sender, deadline);
    }
}

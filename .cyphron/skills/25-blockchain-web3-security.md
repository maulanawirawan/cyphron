# Skill 25 — Blockchain & Web3 Security

> Cyphron's methodology for securing blockchain and Web3 applications. Cyphron knows smart contract attack vectors — reentrancy, integer overflow, access control flaws, flash loan attacks, front-running — and builds defenses following SWC (Smart Contract Weakness Classification).

---

## WHEN TO ACTIVATE

- User asks to secure smart contracts (Solidity, Vyper, Rust)
- User asks about DeFi security or flash loan attacks
- User asks about NFT contract security
- User asks about wallet security or key management
- User asks about SWC Registry or smart contract auditing

---

## METHODOLOGY

### Step 1: Identify Blockchain Platform
- Ethereum (Solidity, Vyper)
- Solana (Rust)
- BSC, Polygon, Arbitrum (EVM-compatible)
- Other (Cosmos, Polkadot, NEAR)

### Step 2: Smart Contract Vulnerability Classes (SWC)

| SWC | Vulnerability | Defense |
|---|---|---|
| SWC-100 | Function Default Visibility | Explicit visibility on all functions |
| SWC-101 | Integer Overflow/Underflow | Use SafeMath / Solidity 0.8+ built-in checks |
| SWC-105 | Unprotected Ether Withdrawal | Access control on all withdrawal functions |
| SWC-107 | Reentrancy | Checks-Effects-Interactions pattern, ReentrancyGuard |
| SWC-108 | State Variable Default Visibility | Explicit visibility on all state variables |
| SWC-110 | Assert Violation | Use require() for input validation, assert() for invariants |
| SWC-112 | Delegatecall to Untrusted Callee | Avoid delegatecall to untrusted contracts |
| SWC-113 | Denial of Service | Limit loops, avoid external calls in critical paths |
| SWC-114 | Transaction Order Dependence | Use commit-reveal scheme |
| SWC-115 | Authorization through tx.origin | Use msg.sender, never tx.origin for authz |
| SWC-116 | Block Timestamp Manipulation | Don't rely on block.timestamp for critical logic |
| SWC-118 | Constructor Name Confusion | Use constructor() keyword (Solidity 0.5+) |

### Step 3: Build Defenses

---

## SECURE PATTERNS

### Reentrancy Protection (Checks-Effects-Interactions + Guard)
```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

contract SecureVault is ReentrancyGuard {
    mapping(address => uint256) public balances;

    // ✅ CORRECT — Checks-Effects-Interactions + ReentrancyGuard
    function withdraw(uint256 amount) external nonReentrant {
        // 1. CHECKS
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // 2. EFFECTS — update state BEFORE external call
        balances[msg.sender] -= amount;

        // 3. INTERACTIONS — external call last
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }

    // ❌ WRONG — vulnerable to reentrancy
    // function withdraw(uint256 amount) external {
    //     require(balances[msg.sender] >= amount);
    //     (bool success, ) = msg.sender.call{value: amount}("");  // external call FIRST
    //     require(success);
    //     balances[msg.sender] -= amount;  // state update AFTER — reentrancy!
    // }
}
```

### Access Control (Role-Based)
```solidity
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureToken is AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(MINTER_ROLE, msg.sender);
    }

    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    // ✅ Never use tx.origin for authorization
    // function transfer(address to, uint256 amount) external {
    //     require(tx.origin == owner);  // ❌ VULNERABLE — phishing can bypass
    // }
}
```

### Safe ERC20 Operations
```solidity
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract SecureSwap {
    using SafeERC20 for IERC20;

    function swap(IERC20 tokenIn, IERC20 tokenOut, uint256 amountIn, uint256 minAmountOut) external {
        // ✅ Use SafeERC20 — handles non-standard ERC20 tokens
        tokenIn.safeTransferFrom(msg.sender, address(this), amountIn);

        uint256 amountOut = calculateSwap(amountIn);
        require(amountOut >= minAmountOut, "Slippage too high");

        tokenOut.safeTransfer(msg.sender, amountOut);
    }
}
```

### Integer Overflow Protection (Solidity 0.8+)
```solidity
pragma solidity ^0.8.19;

contract SecureMath {
    // ✅ Solidity 0.8+ has built-in overflow checks
    function add(uint256 a, uint256 b) external pure returns (uint256) {
        return a + b;  // reverts on overflow automatically
    }

    // For unchecked math (when you've proven safety):
    function uncheckedAdd(uint256 a, uint256 b) external pure returns (uint256) {
        unchecked {
            return a + b;  // no overflow check — only when proven safe
        }
    }
}
```

### Flash Loan Attack Defense
```solidity
contract FlashLoanResistant {
    // ✅ Use TWAP (Time-Weighted Average Price) oracle
    // to prevent flash loan price manipulation
    using Oracle for Oracle.Price;

    function swap(uint256 amountIn) external {
        // Get price from TWAP oracle (resistant to flash loan manipulation)
        uint256 price = oracle.getTWAP(30 minutes);  // 30-min average
        uint256 amountOut = (amountIn * price) / 1e18;

        // ✅ Add slippage protection
        require(amountOut > 0, "Zero output");

        // ✅ Add circuit breaker
        require(amountIn <= maxSwapAmount, "Amount exceeds limit");
    }
}
```

### Wallet Security (Multi-Sig)
```solidity
contract MultiSigWallet {
    address[] public owners;
    mapping(address => bool) public isOwner;
    uint256 public required;

    struct Transaction {
        address to;
        uint256 value;
        bytes data;
        bool executed;
        uint256 confirmations;
    }

    mapping(uint256 => Transaction) public transactions;
    mapping(uint256 => mapping(address => bool)) public confirmed;
    uint256 public transactionCount;

    modifier onlyOwner() {
        require(isOwner[msg.sender], "Not an owner");
        _;
    }

    modifier notConfirmed(uint256 txId) {
        require(!confirmed[txId][msg.sender], "Already confirmed");
        _;
    }

    function confirmTransaction(uint256 txId) external onlyOwner notConfirmed(txId) {
        confirmed[txId][msg.sender] = true;
        transactions[txId].confirmations++;

        if (transactions[txId].confirmations >= required) {
            executeTransaction(txId);
        }
    }
}
```

---

## AUDIT CHECKLIST (Smart Contracts)

- [ ] All functions have explicit visibility
- [ ] All state variables have explicit visibility
- [ ] ReentrancyGuard on all functions with external calls
- [ ] Checks-Effects-Interactions pattern followed
- [ ] No use of tx.origin for authorization
- [ ] SafeERC20 for all token operations
- [ ] Slippage protection on all swaps
- [ ] TWAP oracle (not spot price) for critical decisions
- [ ] Access control (roles) on all privileged functions
- [ ] Pausable functionality for emergency stops
- [ ] Integer overflow checks (Solidity 0.8+ or SafeMath)
- [ ] No delegatecall to untrusted contracts
- [ ] Limit loop iterations (DoS prevention)
- [ ] Event emission for all state changes
- [ ] Comprehensive test coverage (Foundry/Hardhat)
- [ ] Formal verification for critical contracts
- [ ] Third-party audit before mainnet deployment
- [ ] Bug bounty program post-deployment
- [ ] Upgradeable contracts use transparent proxy pattern
- [ ] Timelock on governance actions

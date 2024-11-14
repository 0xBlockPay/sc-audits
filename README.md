# 0xBlockPay Smart Contract Audit Repository

![](logo.jpg)

## Table of Contents
1. Introduction
2. Resources
   - [Audits](#audits)
   - Articles
   - Cheat Sheets
   - Projects
   - Report Writing
3. Tools
4. Methodologies
5. Code Examples
   - Account Abstraction
6. License

## Introduction
Welcome to the Smart Contract Audit Repository! This repository contains resources, tools, and code examples to help you learn and practice smart contract auditing.

## Resources

### Audits
- [PasswordStore](./2024-09-25-password-store.pdf)
- [PuppyRaffle](./2024-09-26-puppy-raffle.pdf)
- [SantasList](./2024-09-27-santas-list.pdf)
- [Ethernaut](./2024-09-30-ethernaut.pdf)
- [FuzzTest](./2024-10-04-fuzz.pdf)
- [T-Swap](./2024-10-04-t-swap.pdf)
- [MysteryBox](./2024-09-30-mystery-box.pdf)
- [ThunderLoan](./2024-10-15-thunder-loan.pdf)

### Articles
- Basics of Smart Contract Auditing
- Advanced Techniques in Smart Contract Security

### Cheat Sheets
- Solidity Syntax
- Common Vulnerabilities

### Projects
- Malware Analysis
- Penetration Testing

### Report Writing
- Sample Audit Report
- Report Template

## Tools
- MythX
- Slither
- Remix IDE

## Methodologies
- OWASP Smart Contract Security
- Audit Methodology

## Code Examples
- Account Abstraction

Account abstraction in Ethereum is a proposed upgrade that aims to make interacting with the blockchain more flexible and user-friendly. Here are the key points:

### What is Account Abstraction?
Account abstraction allows for more flexible programming of security and user experiences within Ethereum accounts. Instead of relying solely on externally owned accounts (EOAs) controlled by private keys, account abstraction enables accounts to be controlled by smart contracts1.

### Benefits of Account Abstraction:
Flexible Security Rules: Users can define their own security rules within their accounts, adding layers of security beyond just private keys.

1) Enhanced Recovery: Users can set up backup mechanisms to regain access to their accounts if they lose their private keys.

2) Sharing Security: Users can share the security of their account with trusted devices or individuals.

3) Gas Flexibility: Users can pay gas fees using tokens other than ETH, simplifying the management of gas funds.

4) Batch Transactions: Complex actions, like approving and executing swaps in one go, become more straightforward.

5) Innovative dApps: Developers have greater freedom to innovate and create user-friendly decentralized applications (dApps).

### How It Works:
Account abstraction involves upgrading EOAs so they can be controlled by smart contracts, or upgrading smart contracts so they can initiate transactions. This allows for more complex and user-friendly interactions with the Ethereum network.

### Why It Matters:
Account abstraction aims to improve the overall user experience on Ethereum by making it easier to interact with the blockchain, reducing the need for users to manage private keys, and providing more options for security and transaction flexibility.

#### POC

`forge init`

`git add .`

`git commit -m "account abstraction init"`

`forge install OpenZeppelin/openzeppelin-contracts`

to `src/AccountAbstraction.sol`

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract AccountAbstraction is Ownable(msg.sender) {
    mapping(address => bool) private accountHolders;

    constructor() {
        accountHolders[msg.sender] = true;
    }

    function addAccountHolder(address _accountHolder) public onlyOwner {
        accountHolders[_accountHolder] = true;
    }

    function removeAccountHolder(address _accountHolder) public onlyOwner {
        accountHolders[_accountHolder] = false;
    }

    function isAccountHolder(address _accountHolder) public view returns (bool) {
        return accountHolders[_accountHolder];
    }

    function transferTokens(address token, address recipient, uint256 amount) public {
        require(isAccountHolder(msg.sender), "Not an account holder");
        IERC20(token).transferFrom(msg.sender, recipient, amount);
    }
}
```

to `test/AccountAbstraction.t.sol`

```javascript
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/AccountAbstraction.sol";
import "@openzeppelin/contracts/token/ERC20/ERC20.sol";

contract MockERC20 is ERC20 {
    constructor(uint256 initialSupply) ERC20("MockERC20", "MERC") {
        _mint(msg.sender, initialSupply);
    }
}

contract AccountAbstractionTest is Test {
    AccountAbstraction accountAbstraction;
    MockERC20 token;
    address owner = address(0x1);
    address accountHolder = address(0x2);
    address nonAccountHolder = address(0x3);


    function setUp() public {
        token = new MockERC20(1000 ether);
        vm.startPrank(owner);
        accountAbstraction = new AccountAbstraction();
        accountAbstraction.transferOwnership(owner);
        vm.stopPrank();
    }

    function testAddAccountHolder() public {
        vm.prank(owner);
        accountAbstraction.addAccountHolder(accountHolder);
        assertTrue(accountAbstraction.isAccountHolder(accountHolder));
    }

    function testRemoveAccountHolder() public {
        vm.prank(owner);
        accountAbstraction.addAccountHolder(accountHolder);
        vm.prank(owner);
        accountAbstraction.removeAccountHolder(accountHolder);
        assertFalse(accountAbstraction.isAccountHolder(accountHolder));
    }

    function testTransferTokens() public {
        vm.prank(owner);
        accountAbstraction.addAccountHolder(accountHolder);
        token.transfer(accountHolder, 100 ether);
        vm.prank(accountHolder);
        token.approve(address(accountAbstraction), 50 ether);
        vm.prank(accountHolder);
        accountAbstraction.transferTokens(address(token), nonAccountHolder, 50 ether);
        assertEq(token.balanceOf(nonAccountHolder), 50 ether);
    }

    function testFailTransferTokens_NotAccountHolder() public {
        vm.prank(nonAccountHolder);
        accountAbstraction.transferTokens(address(token), owner, 50 ether);
    }
}
```

to `remappings.txt`

```sh
@openzeppelin/contracts/=lib/openzeppelin-contracts/contracts/
```

and run
`forge test`


## License
This project is licensed under the MIT License - see the LICENSE file for details.

---

If you have any questions or suggestions, please feel free to open an issue or submit a pull request.

!Smart Contract Audit Image

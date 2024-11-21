# 0xBlockPay Smart Contract Audit Repository

![](logo.jpg)

## Table of Contents
1. Introduction
2. Resources
   - [Audits](#audits)
   - [Articles](#articles)
   - Cheat Sheets
   - Projects
   - Report Writing
3. Tools
4. Methodologies
5. Code Examples
   - [Account Abstraction](#account-abstraction)
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
- [StarkNet](./2024-10-10-starknet.pdf)
- [TrickOrTreat](./2024-10-24-trick.pdf)

### Articles
- Basics of Smart Contract Auditing
- Advanced Techniques in Smart Contract Security
- [Defi invariant](#defi-invariant)

### Wallet Security
- Overwiew 

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
### Account Abstraction

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

### Defi invariant

Protocols that are widely used and recognized in the cryptocurrency space:

- Uniswap: A decentralized exchange (DEX) that allows users to swap tokens directly from their wallets without the need for an intermediary.
- Aave: A lending and borrowing platform that offers features like flash loans, which allow users to borrow and repay funds within a single transaction.
- MakerDAO: A protocol that enables users to generate a stablecoin (DAI) by locking up collateral in a smart contract.
- Compound: A DeFi platform that allows users to lend and borrow cryptocurrencies, with interest rates that are algorithmically determined.
- Curve: A DEX that focuses on stablecoin trading, offering low slippage and efficient trades.
- SushiSwap: A fork of Uniswap, SushiSwap includes additional features like staking rewards for liquidity providers.
- dYdX: A decentralized exchange that offers advanced trading features, including perpetual contracts and spot trading.
- Balancer: A protocol that allows users to create and trade multi-asset portfolios with customizable weights.
- Lido: A liquid staking solution that allows users to stake their Ethereum and earn rewards while maintaining liquidity.
- De.Fi: A platform that provides analytics and portfolio management tools for DeFi users.

#### Uniswap (V2)
Uniswap uses the Constant Product Market Maker (CPMM) invariant. The invariant ensures that the product of the reserves of two tokens in a liquidity pool remains constant:

𝑥⋅𝑦=𝑘

Where:
𝑥 is the reserve of token A.
𝑦 is the reserve of token B.
𝑘 is a constant value representing the product of the initial reserves.

#### Aave
Aave's invariant ensures that the total value supplied to the protocol (deposits plus interest) should be greater than or equal to the total value borrowed (loans plus interest):

Total Deposits + Accrued Interest ≥ Total Borrows + Accrued Debt

#### MakerDAO

MakerDAO ensures that the value of the collateral locked in the system is greater than or equal to the value of the outstanding DAI loans:

Collateral Value ≥ DAI Debt ⋅ Liquidation Ratio

#### Compound

Compound's invariant ensures that the total supply of tokens is equal to the total borrow of tokens, adjusted for interest rates:

∑Supply = ∑Borrow ⋅(1+Interest Rate)

#### Curve

Curve uses the StableSwap invariant to maintain the balance of stablecoins in its pools:

$$ A \cdot n^n \cdot \sum x_i + D = D \cdot A \cdot n^n + \frac{D{n+1}}{nn \cdot \prod x_i} $$

Where:

𝑥𝑖 represents the balance of the 
𝑖 -th token in the pool.
𝐷 is the total amount of tokens in the pool when they have an equal price.
𝐴 is the amplification coefficient.
𝑛 is the number of tokens in the pool.

#### SushiSwap
SushiSwap also uses the Constant Product Market Maker (CPMM) invariant similar to Uniswap:

𝑥⋅𝑦=𝑘

Where:

𝑥 is the reserve of token A.
𝑦 is the reserve of token B.
𝑘 is a constant value representing the product of the initial reserves.

These invariants are fundamental in ensuring the stability, security, and efficiency of these DeFi protocols.

#### dYdX
dYdX uses cross-margining, which means that the margin and leverage are shared across all open positions. The invariant ensures that the total equity in the account is sufficient to cover the potential losses from all open positions:

Equity = Margin⋅(1+Leverage)

Where:

Equity is the total value of the user's account.
Margin is the amount of collateral (usually USDC) deposited by the user.
Leverage is the factor by which the user's position is amplified.
This invariant ensures that the user's account has enough margin to cover potential losses, even when using leverage.

#### Balancer
Balancer allows users to create and trade multi-asset portfolios with customizable weights. The balance invariant for Balancer pools ensures that the value function remains constant:

∑𝑖=1𝑛𝑤𝑖⋅𝑥𝑖=𝑘

Where:

𝑤𝑖 is the normalized weight of the 
𝑖 -th token in the pool.

𝑥𝑖 is the balance of the 
𝑖 -th token in the pool.

𝑘 is a constant value representing the total value of the pool.

#### Lido
Lido is a liquid staking solution that allows users to stake their Ethereum and earn rewards while maintaining liquidity. The balance invariant for Lido ensures that the stETH (staked ETH) tokens maintain a 1:1 ratio with the underlying staked ETH:

stETH=ETH

This invariant ensures that for every unit of ETH staked, one unit of stETH is issued, and vice versa when stETH is redeemed.

### Wallet Security

In this section, we will delve into topics such as algorithms that enhance the security of cryptocurrency wallets, including Multi-Party Computation (MPC), as well as the hardware analysis of security enclaves on both mobile and desktop devices. These discussions aim to provide a comprehensive understanding of the advanced techniques and technologies used to safeguard digital assets and ensure robust protection against various threats.

Securing your cryptocurrency wallet is crucial to protect your digital assets from theft and unauthorized access. Here are some key practices for enhancing wallet security:

Use Strong Passwords: Create complex passwords that combine letters, numbers, and special characters. Avoid using easily guessable information like birthdays or common words.

Enable Two-Factor Authentication (2FA): Adding an extra layer of security through 2FA can prevent unauthorized access even if your password is compromised.

Store Private Keys Safely: Never share your private keys or seed phrases. Store them offline in a secure location, such as a hardware wallet or a secure paper backup.

Regular Updates: Keep your wallet software and devices up to date to protect against the latest security vulnerabilities.

Be Cautious with Phishing Scams: Avoid clicking on suspicious links and always verify the authenticity of websites and apps before entering your credentials.

By following these best practices, you can significantly reduce the risk of losing your cryptocurrencies to cyber threats.



#### Intel SGX

Intel Software Guard Extensions (SGX) is a set of security-related instruction codes built into some Intel CPUs. SGX allows applications to create protected areas of memory called enclaves. These enclaves are designed to safeguard sensitive data and code from being accessed or tampered with by other processes, including those running at higher privilege levels like the operating system or hypervisors1.

Key Features of Intel SGX:
Trusted Execution Environment: SGX provides a trusted execution environment where sensitive code and data can be processed securely.

Memory Encryption: Data within an enclave is encrypted by the CPU, making it difficult for unauthorized parties to access.

Isolation: Enclaves are isolated from other parts of the system, protecting them from attacks and vulnerabilities.

Side-Channel Attack Mitigation: While SGX helps mitigate many types of attacks, it is not immune to side-channel attacks.

Applications:
SGX is useful for various applications, including secure remote computation, secure web browsing, and digital rights management (DRM). It can also be used to protect proprietary algorithms and encryption keys1.

Limitations:
SGX has been deprecated in Intel's 11th and 12th generation Core processors but continues to be supported in Intel Xeon processors for cloud and enterprise use. It is also vulnerable to certain types of attacks, such as side-channel attacks1.


1. Code can be download from repo:

`git clone https://github.com/intel/linux-sgx.git`

2. Installation

`sudo apt-get install build-essential python-is-python3`
`cd ./linux-sgx/`
`./install-sgx-sdk.bin.tmpl`
`./sgx_linux_x64_sdk_2.23.100.2.bin`

3. Set env variables
`source /home/xxx/sgx/linux-sgx/linux/installer/bin/sgxsdk/environment`

4. Test example (simulation mode without SGX hardware)

`cd SampleCode/Cxx17SGXDemo`
`make SGX_MODE=SIM`
`cd bin`
`./app`

5. Short description
The Sgx application has two main parts. 
First not secure:
`Cxx17SGXDemo/App/App.cpp`

Second secure:
`Cxx17SGXDemo/Enclave/Enclave.cpp`

and also connector between them:
`Cxx17SGXDemo/Enclave/Enclave.edl`

The most crucial is connector's part. There is an Enclave Definition Language (EDL) file used to define the interface between the enclave (trusted code) and the untrusted (regular) application code. Here's a brief overview of what's defined in this file:

Enclave Definition: The file starts by defining the enclave and specifying the trusted library files to import.

ECALLs and OCALLs: It specifies the entry points (ECALLs) for functions callable from the untrusted code and the exit points (OCALLs) for functions callable from the enclave.

Function Signatures: It defines the parameters and return types for these ECALLs and OCALLs.

Here's a simplified example of what the content might look like:

```edl
enclave {
    from "TrustedLibrary/Libcxx.edl" import *;
    from "sgx_tstdc.edl" import *;

    untrusted {
        void ocall_print_string([in, string] const char *str);
    };
}
```

In this example:

The enclave imports functions from the Libcxx.edl and sgx_tstdc.edl files.

It defines an OCALL ocall_print_string that takes a string input from the untrusted code.

#### Apache Teaclave SGX SDK

The Apache Teaclave SGX SDK is an open-source software development kit designed to help developers create secure applications using Intel SGX (Software Guard Extensions). Originally developed by Baidu and known as MesaTEE/Rust SGX SDK, it was open-sourced in July 2019 and entered the Apache Incubator in August 20192.

Key Features:
Rust Programming Language: The SDK is written in Rust, which helps prevent memory-safety issues.

Secure Computing: It provides a platform for secure computation on privacy-sensitive data.

Modular Design: Components are designed to be modular, making it easy to embed features like remote attestation in other projects.

Multi-Party Computation (MPC): Supports flexible multi-party secure computation.

Function-as-a-Service: Allows developers to write and execute functions in Python and other languages.

Use Cases:
Privacy-Preserving Machine Learning: Securely processing sensitive data for machine learning tasks.

Private Set Intersection: Performing set operations without revealing the actual data.

Crypto Computation: Handling cryptographic operations securely.

The project can be downloaded from
`git clone https://github.com/apache/incubator-teaclave-sgx-sdk.git`

For test I used docker 

1. Download sgx docker image
`docker pull baiduxlab/sgx-rust`

Important: docker image should have the same version like `dcap 1.12`

2. Run docker 
`docker run -v /path/to/rust-sgx:/root/sgx -ti baiduxlab/sgx-rust`

3. Run example

`cd sgx/samplecode/hello-rust`

`make SGX_MODE=SW`

`cd bin`

`./app`

Much easier than Intel SGX, but here, if you would like to use your own cryptographic algorithm, all libraries and dependencies must utilize a special standard library modified for SGX.


Application is splited on 2 parts:

The same structure like in Intel SGX 


Non enclave:

`app/src/main.rs`

Enclave:

`hello-rust/enclave`

#### EGO

Ego SGX is an architecture designed to utilize Intel Software Guard Extensions (SGX) for secure enclave computing. It focuses on enhancing security for sensitive data and computations by creating isolated execution environments. Here are some key aspects:

Core Features:
Isolation: Ego SGX creates secure enclaves, which are isolated from the main operating system and other processes. This ensures that sensitive data and code are protected from unauthorized access and tampering.

Encryption: All data within the enclave is encrypted, both in transit and at rest. This provides a robust layer of security against potential data breaches.

Attestation: Ego SGX supports remote attestation, allowing users to verify that the code running in the enclave is trusted and has not been altered.

Use Cases:
Secure Data Processing: Protecting sensitive computations in financial, healthcare, and government applications.

Confidential Machine Learning: Ensuring data privacy during machine learning tasks by processing data within secure enclaves.

Trusted Computing: Establishing a secure environment for running critical applications that require high levels of security assurance.

Benefits:
Enhanced Security: By leveraging the hardware-based security features of Intel SGX, Ego SGX provides a high level of protection against common security threats.

Performance: While maintaining security, Ego SGX is designed to minimize the performance overhead typically associated with secure computing.

Flexibility: Developers can utilize their own cryptographic algorithms and security protocols, as long as they are compatible with the SGX-modified standard libraries.

Ego SGX represents a significant step forward in secure computing, making it easier for developers to protect their applications and data in an increasingly complex threat landscape.

The esest way:

1. Instalation
`sudo snap install ego-dev --classic`

2. Library
`sudo apt install build-essential libssl-dev`

3. Build
```bash
mkdir build
cd build
cmake ..
make
make install
```

4. Example

```go
// https://tour.golang.org/concurrency/1

package main

import (
	"fmt"
	"time"
)

func say(s string) {
	for i := 0; i < 5; i++ {
		time.Sleep(100 * time.Millisecond)
		fmt.Println(s)
	}
}

func main() {
	go say("world")
	say("hello")
}
```

```bash
ego-go build #<-- build
ego sign helloworld #<-- sign
```
```bash
ego run #<-- run
```

If you would like to add addition file with certs is necessary to add `enclave.json` file.

```json
{
    "exe": "embedded_file",
    "key": "private.pem",
    "debug": true,
    "heapSize": 512,
    "productID": 1,
    "securityVersion": 1,
    "files": [
        {
            "source": "/etc/ssl/certs/ca-certificates.crt",
            "target": "/etc/ssl/certs/ca-certificates.crt"
        }
    ]
}
```



















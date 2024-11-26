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

### [Wallet Security](#wallet-security)
- Overwiew

#### Desktop
- [Intel SGX](#intel-sgx)
- [Apache Teaclave SGX SDK](#apache-teaclave-sgx-sdk)
- [EGO](#ego)

#### Mobile
- [Android Trusty TEE](#android-trusty-tee)
- [OP-TEE](#op-tee)

### [Memory Allocators](#memory-allocators-1)
- [jemallock](#jemalloc)
- [Scudo](#scudo)
- [dlmallock](#dlmalloc)

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

#### Mobile

#### Android Trusty TEE

Android Trusty is a secure operating system (OS) that provides a Trusted Execution Environment (TEE) for Android devices. Trusty runs on the same processor as the Android OS but is isolated from the rest of the system by both hardware and software1. This isolation ensures that sensitive data and operations are protected from malicious apps and potential vulnerabilities in the Android OS.

Key Features:
Isolation: Trusty is isolated from the main Android OS, providing a secure environment for sensitive operations.

Hardware and Software Protection: Trusty uses hardware features like ARM TrustZone (on ARM processors) and Intel VT (on Intel processors) to create a secure environment.

Open Source: Trusty is provided as an open-source alternative to proprietary TEE solutions, offering transparency and ease of debugging.

APIs for Development: Trusty provides APIs for developing trusted applications and services that run in the TEE, as well as for normal apps to interact with these trusted services.

Use Cases:
Secure Data Processing: Protecting sensitive data such as payment information, biometric data, and encryption keys.

Trusted Applications: Running applications that require a high level of security, such as mobile payment apps and DRM solutions.

Inter-Process Communication: Allowing secure communication between trusted and untrusted parts of the system.

End of the theory, let's dive into the details from a developer's point of view: It's challenging because it's an isolated mini operating system.

Even with something as substantial as 400 GB of memory, it might still not be sufficient.

!!! From a developer's perspective, a significant challenge in adding a custom algorithm to `Trusty` is the necessity to recompile the entire operating system. This process can be time-consuming and complex, as it requires in-depth knowledge of the system's architecture and dependencies. Additionally, ensuring compatibility and maintaining the integrity of the secure environment adds to the difficulty. This can be a considerable barrier for developers looking to integrate new algorithms into the Trusty environment.

I did some reserach, How to add ED25519 algorithm to trusty?

To that we can use `openssl-rust crate`.

First dependency should be put to: trusty api application's `rules.mk`
```bash
MODULE_LIBRARY_DEPS +=
trusty/user/base/lib/openssl-rust \
```

In `trusty/user/base/lib/openssl-rust` folder should be `rules.mk` file, with dependencies for openssl-rust
https://android.googlesource.com/trusty/lib/+/refs/heads/main/lib/openssl-rust/rules.mk

Folder with openssl-rust dep is https://android.googlesource.com/platform/external/rust/crates/openssl/+/refs/heads/main

Thanks this is possible use openssl-rust precompile dependencies in trusty application:

Example with openssl in trusty -rust:
https://android.googlesource.com/trusty/app/sample/+/refs/heads/main/hwcryptohal/server/platform_functions.rs

For sign tx can be use this template:
https://android.googlesource.com/trusty/app/sample/+/refs/heads/main/rust-hello-world/lib.rs

The following code illustrates a function to sign a SOLANA transaction within Trusty using openssl-rust. The use of openssl-rust here is crucial as it is an integral part of the Trusty library.

```rust
fn on_message(
&self,
_connection: &Self::Connection,
handle: &Handle,
msg: Self::Message,) -> tipc::Result<MessageResult> {}

//In function on_message as a msg's can be tx params for signing,
//and then code for signing with pure openssl-rust

use openssl::pkey::PKey;
use openssl::sign::Signer;

fn main() {
println!("Sign transaction in Android Trusty API");

// ED25519 private key generation. Private Key should be load from trust store.
       
let private_key = PKey::generate_ed25519().unwrap();
let public_key = private_key.raw_public_key().unwrap();
      
let mut signer = Signer::new_without_digest(&private_key).unwrap();

let tx = hex::decode("914bf4f22ccdedf00950d01020065b233ff0afa0753cd53baa5175827707aa75").unwrap();
let signature = signer.sign_oneshot_to_vec(&tx).unwrap();
assert_eq!(signature.len(), 64);

println!("Signature: {:?}", hex::encode(&signature));

let public_key_result =PKey::public_key_from_raw_bytes(&public_key, openssl::pkey::Id::ED25519);

let binding = public_key_result.unwrap();

let mut verifier = openssl::sign::Verifier::new_without_digest(&binding).unwrap();

let verify_result = verifier.verify_oneshot(&signature, &tx);

println!("Signature is: {:?}", verify_result.unwrap());

println!("Signature verification end");
}
``` 

That part was straightforward, but now comes the most challenging task: compiling the Android Kernel and Trusty.

1. Download Android Kernel

`repo init --partial-clone -b main -u https://android.googlesource.com/platform/manifest`

`repo sync -c -j8`

2. Download external library for specifiec device

`https://developers.google.com/android/blobs-preview?hl=pl`

3. Build Android library

```bash
source build/envsetup.sh
lunch qemu_trusty_arm64-userdebug
m
```

4. Download Trusty

```bash
mkdir trusty
cd trusty
repo init -u https://android.googlesource.com/trusty/manifest -b main
repo sync -j32`
```

5. Build Trusty image for quemu

`trusty/vendor/google/aosp/scripts/build.py qemu-generic-arm64-test-debug`

6.  Run

`build-root/build-qemu-generic-arm64-test-debug/run`


And after lots of scripts modification in folder `build-root/build-qemu-generic-arm64-test-debug`
should be `lk.bin` and `lk.elf` file.

However, to run my code on Android devices within the Trusted Execution Environment (TEE), it is crucial to note that I would need to be a mobile device vendor. This requirement adds an additional layer of complexity to the process. Moreover, it proved to be a task that, while only time-consuming, demanded significant effort and patience.

#### OP-TEE

Much more promissing solution than google's `Trusty`

**OP-TEE (Open Portable Trusted Execution Environment)** is an open-source project designed to provide a secure, isolated environment for executing sensitive tasks and handling sensitive data on modern ARM-based systems. Here's a detailed overview:

### Key Features of OP-TEE:
1. **Isolation**: OP-TEE runs alongside the main operating system (known as the "Rich Execution Environment" or REE) but is isolated from it, ensuring that sensitive operations remain secure.
2. **Open Source**: As an open-source project, OP-TEE provides transparency, allowing developers to review the code, contribute to the project, and customize the TEE to meet specific needs.
3. **Portability**: Designed to be portable across various hardware platforms, OP-TEE supports a wide range of ARM-based devices, including mobile phones, tablets, and IoT devices.
4. **Compliance with Standards**: OP-TEE adheres to industry standards such as GlobalPlatform TEE specifications, ensuring compatibility with a variety of trusted applications.

### Components of OP-TEE:
- **Trusted OS (Operating System)**: The core component that runs in the secure world, managing trusted applications and providing secure services.
- **Secure Monitor**: A small piece of code running at a higher privilege level, responsible for switching between the normal world and the secure world.
- **Trusted Applications (TAs)**: Applications running within the trusted OS, performing security-sensitive operations like encryption, decryption, and secure storage.

### Use Cases:
- **Digital Rights Management (DRM)**: Protecting media content by ensuring it can only be accessed by authorized users.
- **Secure Payment Systems**: Processing payment transactions securely, protecting user credentials and sensitive financial data.
- **Enterprise Security**: Ensuring secure access to corporate resources and protecting sensitive information within enterprise environments.

### Benefits:
- **Enhanced Security**: By isolating sensitive operations from the main OS, OP-TEE significantly reduces the attack surface and protects against various threats.
- **Flexibility and Customization**: As an open-source project, OP-TEE allows for extensive customization to meet specific security requirements and use cases.
- **Community and Support**: Being open-source, OP-TEE has a growing community of contributors and users, providing a wealth of knowledge, resources, and support.

OP-TEE is a powerful solution for implementing secure environments on ARM-based devices, enabling a wide range of secure applications and services.

1. Docker images
```bash
FROM ubuntu:22.04
ARG DEBIAN_FRONTEND=noninteractive
RUN apt update && apt upgrade -y
RUN apt install -y \
    adb \
    acpica-tools \
    autoconf \
    automake \
    bc \
    bison \
    build-essential \
    ccache \
    cpio \
    cscope \
    curl \
    device-tree-compiler \
    e2tools \
    expect \
    fastboot \
    flex \
    ftp-upload \
    gdisk \
    git \
    libattr1-dev \
    libcap-ng-dev \
    libfdt-dev \
    libftdi-dev \
    libglib2.0-dev \
    libgmp3-dev \
    libhidapi-dev \
    libmpc-dev \
    libncurses5-dev \
    libpixman-1-dev \
    libslirp-dev \
    libssl-dev \
    libtool \
    libusb-1.0-0-dev \
    make \
    mtools \
    netcat \
    ninja-build \
    python3-cryptography \
    python3-pip \
    python3-pyelftools \
    python3-serial \
    python-is-python3 \
    rsync \
    swig \
    unzip \
    uuid-dev \
    wget \
    xdg-utils \
    xterm \
    xz-utils \
    zlib1g-dev
RUN curl https://storage.googleapis.com/git-repo-downloads/repo > /bin/repo && chmod a+x /bin/repo
RUN mkdir /optee
WORKDIR /optee
RUN repo init -u https://github.com/OP-TEE/manifest.git -m qemu_v8.xml && repo sync -j10
WORKDIR /optee/build
RUN make -j2 toolchains
ENV FORCE_UNSAFE_CONFIGURE=1
RUN make -j$(nproc) check
```

2. Docker build
`docker build -t optee:latest .`

3. Docker run
`sudo docker run -it optee`

`sudo docker start busy_swirles`

`sudo docker exec -it busy_swirles bash`

4. Inside docker

```bash
git clone https://github.com/apache/incubator-teaclave-trustzone-sdk.git
cd incubator-teaclave-trustzone-sdk
./setup.sh
./build_optee_libraries.sh optee/
make -C examples/hello_world-rs/
cd ./tests/
./test_hello_world.sh
apt install screen
apt-get install -y libvdeplug-dev
apt install libsdl2-dev
./test_hello_world.sh

```
much faster and easy than `trusty`

You simply need to generate an Android app with native dependencies and incorporate your Trusty-generated code as a .so file. 

### Memory allocators

A crucial aspect of wallet security, perhaps even the most important, is memory allocation. 

It is the process of assigning memory space to various programs and data structures within a computer system. It is essential for running programs and managing data.

Memory allocators can introduce vulnerabilities that attackers might exploit. Here are some common types:

* Heap Overflow: Occurs when a program writes more data to a buffer located on the heap than it can hold, potentially overwriting adjacent memory.

* Use-After-Free (UAF): Happens when a program continues to use memory after it has been freed, leading to potential code execution or data corruption.

* Double Free: When a program frees the same block of memory twice, leading to unpredictable behavior and potential security breaches.

* Invalid Free: Freeing a memory block that was never allocated or already freed can cause crashes or allow attackers to manipulate memory.

These vulnerabilities can lead to arbitrary code execution, denial of service, or information leakage. Secure memory allocators and best practices in coding can help mitigate these risks.

Here, I would like to briefly describe the primary memory allocators we use.


* jemalloc

Android: Used in older Android versions (before Android 11) and still in use on some devices.
Mozilla Firefox: Used as the default memory allocator.

* Scudo
Android: Introduced in Android 11, used for all native code except on low-memory devices where jemalloc is still used.
LLVM Compiler: Part of the LLVM compiler-rt project, providing security features to mitigate heap-related vulnerabilities.

* dlmalloc (Doug Lea's malloc)
GNU C Library (glibc): Used in older versions of the GNU C Library.


#### dlmalloc

dlmalloc is a memory allocator designed for efficient and flexible memory management. Here's a graphical representation of its key components and processes:

1. **Free List Management**: dlmalloc maintains a list of free memory blocks (chunks). When memory is allocated or freed, it updates this list.
2. **Splitting and Coalescing**: When a request for memory is made, dlmalloc looks for a sufficiently large free block. If a block is larger than needed, it splits the block. If neighboring blocks are free when a block is freed, it coalesces them into a larger block.
3. **Bins**: dlmalloc uses bins to organize free chunks by size. This speeds up finding appropriate blocks for allocation.
4. **Top Chunk**: dlmalloc maintains a top chunk, which is the last contiguous block of memory in the heap. When the top chunk is too small to satisfy a request, dlmalloc expands the heap.

#### Example Implementation in C++

Here’s a simplified version of how you might use dlmalloc in C++. Please note that this is a conceptual example for illustrative purposes:

```cpp
#include <iostream>
#include <cstdlib>

// Simplified structure representing a memory chunk
struct Chunk {
    size_t size;  // Size of the chunk
    Chunk* next;  // Pointer to the next free chunk
};

// Pointer to the start of the free list
Chunk* freeList = nullptr;

// Function to allocate memory
void* dlmalloc(size_t size) {
    Chunk* prev = nullptr;
    Chunk* current = freeList;

    // Find a free chunk that is large enough
    while (current && current->size < size) {
        prev = current;
        current = current->next;
    }

    if (!current) {
        // No suitable chunk found; expand the heap
        current = reinterpret_cast<Chunk*>(std::malloc(size + sizeof(Chunk)));
        if (!current) {
            return nullptr; // Out of memory
        }
        current->size = size;
    } else {
        // Remove the chunk from the free list
        if (prev) {
            prev->next = current->next;
        } else {
            freeList = current->next;
        }
    }

    return (void*)(current + 1); // Return pointer to the allocated memory
}

// Function to free memory
void dlfree(void* ptr) {
    if (!ptr) return;

    Chunk* chunk = reinterpret_cast<Chunk*>(ptr) - 1; // Get the chunk header
    chunk->next = freeList;
    freeList = chunk;
}

int main() {
    // Allocate memory
    void* ptr1 = dlmalloc(100);
    void* ptr2 = dlmalloc(200);

    // Use the allocated memory (example)
    std::cout << "Memory allocated at: " << ptr1 << std::endl;
    std::cout << "Memory allocated at: " << ptr2 << std::endl;

    // Free memory
    dlfree(ptr1);
    dlfree(ptr2);

    return 0;
}
```

##### Explanation:

1. **dlmalloc**:
   - Searches for a free chunk large enough to fulfill the request.
   - If no suitable chunk is found, expands the heap using `std::malloc`.

2. **dlfree**:
   - Adds the freed chunk back to the free list.

##### Graphical Representation:

```
+---------------------+
|  Free List (Chunks) |
+----+---+----+---+---+
     |       |       |
     v       v       v
+----+   +----+   +----+
|    |   |    |   |    |
|    |-->|    |-->|    |
|    |   |    |   |    |
+----+   +----+   +----+
```

To integrate Doug Lea's Malloc (dlmalloc) into your project, you need to follow several steps to ensure proper usage and compatibility. Here’s a concise guide to help you get started:

##### dlmalloc in own Project:

1. **Download dlmalloc**:
   - You can find the source code for dlmalloc on Doug Lea's website or through various open-source repositories. Make sure to download a compatible version.

2. **Include the Source in Your Project**:
   - Place the downloaded `malloc.c` file into your project's source directory.
   - Ensure you also have the `malloc.h` header file.

3. **Modify Your Build System**:
   - Update your project's build configuration to include `malloc.c` in the compilation process. If you're using a Makefile, add the necessary instructions.

4. **Include the Header in Your Code**:
   - In your C++ source files where you plan to use dlmalloc, include the header file:
     ```cpp
     #include "malloc.h"
     ```

5. **Replace Standard Allocation Functions**:
   - Replace calls to standard memory allocation functions (`malloc`, `free`, etc.) with dlmalloc functions. dlmalloc functions include `dlmalloc`, `dlfree`, `dlrealloc`, and `dlcalloc`.
   - Example:
     ```cpp
     void* ptr = dlmalloc(100);  // Allocate 100 bytes
     dlfree(ptr);                // Free allocated memory
     ```

6. **Compile and Test**:
   - Compile your project to ensure there are no errors.
   - Run tests to make sure dlmalloc is functioning as expected and that memory is being managed correctly.

##### Example Integration in a Simple Project:

Here’s a basic example demonstrating how to integrate and use dlmalloc in a simple C++ project.

##### File Structure:
```
/my_project
  ├── malloc.c
  ├── malloc.h
  ├── main.cpp
  └── Makefile
```

##### main.cpp:
```cpp
#include <iostream>
#include "malloc.h"

int main() {
    // Allocate memory using dlmalloc
    void* ptr = dlmalloc(100);
    if (!ptr) {
        std::cerr << "Memory allocation failed" << std::endl;
        return 1;
    }

    // Use the allocated memory (example)
    std::cout << "Memory allocated at: " << ptr << std::endl;

    // Free the allocated memory
    dlfree(ptr);
    std::cout << "Memory freed" << std::endl;

    return 0;
}
```

##### Makefile:
```makefile
CC = g++
CFLAGS = -Wall -std=c++11

all: main

main: main.cpp malloc.c
	$(CC) $(CFLAGS) -o main main.cpp malloc.c

clean:
	rm -f main
```

##### Explanation:
- **main.cpp**: Demonstrates allocating and freeing memory using dlmalloc.
- **Makefile**: Compiles the project, including `malloc.c` and linking it with the main program.

#### jemalloc

Let's visually describe how `jemalloc` works. Here's a graphical representation and a brief explanation of its key components and processes:

##### Overview of jemalloc

##### Key Components:
1. **Bins**:
   - jemalloc organizes free memory into bins based on size classes. Each bin contains chunks of a specific size range.

2. **Chunks**:
   - Large memory blocks are divided into chunks, which are then subdivided into smaller blocks for allocation.

3. **Arenas**:
   - jemalloc uses multiple arenas to reduce contention in multi-threaded applications. Each arena has its own set of bins and free lists.

4. **Centralized Metadata**:
   - jemalloc maintains metadata to keep track of allocated and free memory chunks, ensuring efficient allocation and deallocation.

##### Graphical Representation

Here's a simplified diagram to illustrate the components:

```
+-------------------------------------------------+
|                    jemalloc                      |
+-------------------------------------------------+
|                      Arenas                      |
|   +-------------------------------------------+  |
|   |             Arena 1                       |  |
|   | +--------------+  +--------------+        |  |
|   | |    Bins      |  |    Chunks    |        |  |
|   | +--------------+  +--------------+        |  |
|   +-------------------------------------------+  |
|   +-------------------------------------------+  |
|   |             Arena 2                       |  |
|   | +--------------+  +--------------+        |  |
|   | |    Bins      |  |    Chunks    |        |  |
|   | +--------------+  +--------------+        |  |
|   +-------------------------------------------+  |
|   +-------------------------------------------+  |
|   |             Arena N                       |  |
|   | +--------------+  +--------------+        |  |
|   | |    Bins      |  |    Chunks    |        |  |
|   | +--------------+  +--------------+        |  |
|   +-------------------------------------------+  |
+-------------------------------------------------+
```

Sure, let's create a graphical step-by-step overview of how `jemalloc` works.

##### Step-by-Step Graphical Overview of jemalloc

##### 1. **Initialization**
- When the program starts, jemalloc initializes its data structures including arenas and bins.

```
[Initialization]
    |
    V
+---------------------------------------+
|     jemalloc Data Structures          |
|                                       |
|   +---------+   +---------+   +------+|
|   | Arena 1 |   | Arena 2 |...| Arena N|
|   +---------+   +---------+   +------+
|   | Bins    |   | Bins    |   | Bins  |
|   +---------+   +---------+   +------+
|                                       |
+---------------------------------------+
```

##### 2. **Memory Allocation Request**
- A memory allocation request is made. jemalloc selects an appropriate arena to handle the request.

```
[Memory Allocation Request]
    |
    V
+---------------------------------------+
|           Select an Arena             |
|        (based on thread/round-robin)  |
|                                       |
|   +---------+                         |
|   | Arena 1 |--[Request]--------------+
|   +---------+                         |
|   | Bins    |                         |
|   +---------+                         |
+---------------------------------------+
```

##### 3. **Select Bin and Chunk**
- Within the selected arena, jemalloc chooses the appropriate bin based on the size of the requested memory. It then finds a suitable chunk within that bin.

```
[Select Bin and Chunk]
    |
    V
+---------------------------------------+
|      Arena 1                          |
|   +-------------------------+         |
|   | Bin for size class X    |---------|---> [Find suitable chunk]
|   +-------------------------+         |
|                                       |
+---------------------------------------+
```

##### 4. **Allocate Memory**
- jemalloc allocates the memory by removing the chunk from the bin and returning a pointer to the caller. If a chunk is too large, it is split.

```
[Allocate Memory]
    |
    V
+---------------------------------------+
|      Arena 1                          |
|   +-------------------------+         |
|   | Bin for size class X    |         |
|   +---------+---------------+         |
|   | Chunk 1 |----> [Allocate]---------|---> [Return pointer to caller]
|   +---------+                         |
+---------------------------------------+
```

##### 5. **Memory Deallocation**
- When memory is freed, jemalloc places the chunk back into the appropriate bin and attempts to coalesce adjacent free chunks to reduce fragmentation.

```
[Memory Deallocation]
    |
    V
+---------------------------------------+
|      Arena 1                          |
|   +-------------------------+         |
|   | Bin for size class X    |<--------|--[Free chunk]
|   +---------+---------------+         |
|   | Chunk 1 |<---+                    |
|   +---------+    |                    |
|                  |                    |
|   +---------+    |                    |
|   | Chunk 2 |<---+                    |
|   +---------+                         |
+---------------------------------------+
```

This graphical representation outlines how `jemalloc` manages memory allocation and deallocation through the use of arenas, bins, and chunks, ensuring efficient memory management.

#### Example Usage in C++

Here’s how you might use `jemalloc` in your C++ project:

##### Code Example:
```cpp
#include <iostream>
#include <jemalloc/jemalloc.h>

int main() {
    // Allocate memory using jemalloc
    void* ptr = je_malloc(100);
    if (!ptr) {
        std::cerr << "Memory allocation failed" << std::endl;
        return 1;
    }

    // Use the allocated memory (example)
    std::cout << "Memory allocated at: " << ptr << std::endl;

    // Free the allocated memory
    je_free(ptr);
    std::cout << "Memory freed" << std::endl;

    return 0;
}
```

##### Explanation:
- **Bins**: Used to organize free chunks of memory by size.
- **Chunks**: Large blocks of memory that are subdivided.
- **Arenas**: Reduce contention by having multiple arenas handling different threads.

By organizing memory into bins and using multiple arenas, `jemalloc` optimizes memory allocation and deallocation for performance, especially in multi-threaded applications.

To integrate `jemalloc` into your project, follow these steps to ensure proper usage and compatibility. Here's a concise guide:

### jemalloc

1. **Download and Install jemalloc**:
   - You can find jemalloc's source code on its [GitHub repository](https://github.com/jemalloc/jemalloc). Clone the repository or download the tarball.
   - Build and install jemalloc:
     ```sh
     git clone https://github.com/jemalloc/jemalloc.git
     cd jemalloc
     ./autogen.sh
     make
     sudo make install
     ```

2. **Include jemalloc in Your Project**:
   - Link jemalloc to your project by specifying it in your build system. For example, if you're using a Makefile, add the necessary flags.

3. **Modify Your Build System**:
   - Update your project's build configuration to link against jemalloc. This usually involves adding `-ljemalloc` to your linker flags.

4. **Include jemalloc Header**:
   - In your C++ source files where you plan to use jemalloc, include the header file:
     ```cpp
     #include <jemalloc/jemalloc.h>
     ```

5. **Replace Standard Allocation Functions**:
   - Replace calls to standard memory allocation functions (`malloc`, `free`, etc.) with jemalloc functions. jemalloc provides equivalent functions like `je_malloc`, `je_free`, etc.
   - Example:
     ```cpp
     void* ptr = je_malloc(100);  // Allocate 100 bytes
     je_free(ptr);                // Free allocated memory
     ```

6. **Compile and Test**:
   - Compile your project to ensure there are no errors.
   - Run tests to make sure jemalloc is functioning as expected and that memory is being managed correctly.

##### Integration

Here’s a basic example demonstrating how to integrate and use jemalloc in a simple C++ project.

##### File Structure:
```
/my_project
  ├── main.cpp
  └── Makefile
```

##### main.cpp:
```cpp
#include <iostream>
#include <jemalloc/jemalloc.h>

int main() {
    // Allocate memory using jemalloc
    void* ptr = je_malloc(100);
    if (!ptr) {
        std::cerr << "Memory allocation failed" << std::endl;
        return 1;
    }

    // Use the allocated memory (example)
    std::cout << "Memory allocated at: " << ptr << std::endl;

    // Free the allocated memory
    je_free(ptr);
    std::cout << "Memory freed" << std::endl;

    return 0;
}
```

##### Makefile:
```makefile
CC = g++
CFLAGS = -Wall -std=c++11
LDFLAGS = -ljemalloc

all: main

main: main.cpp
	$(CC) $(CFLAGS) main.cpp -o main $(LDFLAGS)

clean:
	rm -f main
```

##### Explanation:
- **main.cpp**: Demonstrates allocating and freeing memory using jemalloc.
- **Makefile**: Compiles the project, linking it with jemalloc.

Certainly! Here's a graphical step-by-step overview of how `Scudo` works:

### Scudo

##### 1. **Initialization**
- When the program starts, `Scudo` initializes its data structures, including arenas and bins.

```
[Initialization]
    |
    V
+----------------------------------------------------+
|                  Scudo Data Structures             |
|                                                    |
|   +-----------+   +-----------+   +--------------+ |
|   |  Arena 1  |   |  Arena 2  |...|    Arena N   | |
|   +-----------+   +-----------+   +--------------+ |
|   |   Bins    |   |   Bins    |   |     Bins     | |
|   +-----------+   +-----------+   +--------------+ |
|                                                    |
+----------------------------------------------------+
```

##### 2. **Memory Allocation Request**
- A memory allocation request is made. `Scudo` selects an appropriate arena to handle the request, reducing contention in multi-threaded applications.

```
[Memory Allocation Request]
    |
    V
+----------------------------------------------------+
|                  Select an Arena                   |
|             (based on thread/round-robin)          |
|                                                    |
|   +-----------+                                    |
|   |  Arena 1  |--[Request]-------------------------|
|   +-----------+                                    |
|   |   Bins    |                                    |
|   +-----------+                                    |
+----------------------------------------------------+
```

##### 3. **Select Bin and Chunk**
- Within the selected arena, `Scudo` chooses the appropriate bin based on the size of the requested memory. It then finds a suitable chunk within that bin.

```
[Select Bin and Chunk]
    |
    V
+----------------------------------------------------+
|                  Arena 1                           |
|   +------------------------------+                 |
|   | Bin for size class X         |-----------------|---> [Find suitable chunk]
|   +------------------------------+                 |
|                                                    |
+----------------------------------------------------+
```

##### 4. **Allocate Memory**
- `Scudo` allocates the memory by removing the chunk from the bin and returning a pointer to the caller. If a chunk is too large, it is split.

```
[Allocate Memory]
    |
    V
+----------------------------------------------------+
|                  Arena 1                           |
|   +------------------------------+                 |
|   | Bin for size class X         |                 |
|   +---------+--------------------+                 |
|   | Chunk 1 |----> [Allocate]----------------------|---> [Return pointer to caller]
|   +---------+                                      |
+----------------------------------------------------+
```

##### 5. **Memory Deallocation**
- When memory is freed, `Scudo` places the chunk back into the appropriate bin and attempts to coalesce adjacent free chunks to reduce fragmentation.

```
[Memory Deallocation]
    |
    V
+----------------------------------------------------+
|                  Arena 1                           |
|   +------------------------------+                 |
|   | Bin for size class X         |<----------------|--[Free chunk]
|   +---------+--------------------+                 |
|   | Chunk 1 |<---+                                 |
|   +---------+    |                                 |
|                  |                                 |
|   +---------+    |                                 |
|   | Chunk 2 |<---+                                 |
|   +---------+                                      |
+----------------------------------------------------+
```

This graphical representation outlines how `Scudo` manages memory allocation and deallocation through the use of arenas, bins, and chunks, ensuring efficient memory management and reducing fragmentation.

To integrate **Scudo** into your project, you can follow these steps to ensure proper usage and compatibility. Scudo is designed to be a robust allocator that offers additional security features, making it suitable for security-sensitive applications. Here’s a detailed guide to help you get started:

##### Use Scudo in Your Project

#### 1. **Download and Install Scudo**
- **Clone the Repository**: Scudo is part of the LLVM project, so you’ll need to get LLVM with the Scudo allocator.
  ```sh
  git clone https://github.com/llvm/llvm-project.git
  cd llvm-project
  mkdir build && cd build
  cmake -G "Unix Makefiles" ../llvm
  make
  ```

#### 2. **Include Scudo in Your Project**
- **Link Scudo**: Ensure that your project's build system links against Scudo. This usually involves using the LLVM build and specifying Scudo as your allocator.

#### 3. **Modify Your Build System**
- **Update Build Configuration**: If using a Makefile or CMake, make sure to link against the LLVM libraries that include Scudo.

##### Using CMake:
```cmake
cmake_minimum_required(VERSION 3.13)
project(MyProject)

set(CMAKE_CXX_STANDARD 11)

# Specify the path to the LLVM build directory
set(LLVM_DIR "/path/to/llvm-project/build/lib/cmake/llvm")

find_package(LLVM REQUIRED CONFIG)
llvm_map_components_to_libnames(llvm_libs support scudo)

add_executable(MyProject main.cpp)
target_link_libraries(MyProject ${llvm_libs})
```

#### 4. **Use Scudo as the Allocator**
- **Configure the Environment**: Set environment variables to use Scudo as the memory allocator.
  ```sh
  export LD_PRELOAD=/path/to/libscudo.so
  ```

#### 5. **Run Your Project**
- **Compile and Run**: Ensure your project compiles correctly and run it to see Scudo in action.

##### Project Structure

#### File Structure:
```
/my_project
  ├── main.cpp
  └── CMakeLists.txt
```

#### main.cpp:
```cpp
#include <iostream>
#include <cstdlib>

int main() {
    // Allocate memory using Scudo
    void* ptr = malloc(100);  // Request 100 bytes of memory

    if (!ptr) {
        std::cerr << "Memory allocation failed" << std::endl;
        return 1;
    }

    // Use the allocated memory (example)
    std::cout << "Memory allocated at: " << ptr << std::endl;

    // Free the allocated memory
    free(ptr);
    std::cout << "Memory freed" << std::endl;

    return 0;
}
```

#### CMakeLists.txt:
```cmake
cmake_minimum_required(VERSION 3.13)
project(MyProject)

set(CMAKE_CXX_STANDARD 11)

# Specify the path to the LLVM build directory
set(LLVM_DIR "/path/to/llvm-project/build/lib/cmake/llvm")

find_package(LLVM REQUIRED CONFIG)
llvm_map_components_to_libnames(llvm_libs support scudo)

add_executable(MyProject main.cpp)
target_link_libraries(MyProject ${llvm_libs})
```


























# Starknet Account Abstraction Smart Contract

An Account Abstraction (AA) smart contract for the Starknet network, written in Cairo 2. It supports multi-signature logic, guardian management, and time-limited session keys.

## 🚀 Features

* **SNIP-6 Standard Compliance**: Implements core account interface logic including `__validate__`, `__execute__`, and `is_valid_signature`.
* **Multisig Support**: Multi-signature validation mechanism with a configurable `threshold`.
* **Guardian Management**: Functions to add and remove guardians for account recovery and security (`add_guardian`, `remove_guardian`).
* **Session Keys**: Issue temporary session keys with strictly enforced expiration timestamps and call limits (`add_session_key`, `revoke_session_key`).

## 🛠 Tech Stack

* **Language:** Cairo 2.x
* **Build Tool:** Scarb
* **Target:** Starknet / Cairo VM

## 💻 Getting Started

### Prerequisites

Make sure you have [Scarb](https://docs.swmansion.com/scarb/) installed on your machine.

### Build

Clone the repository and compile the contract:

```bash
git clone [https://github.com/zhr-stark/AA_expiriment_starknet.git](https://github.com/zhr-stark/AA_expiriment_starknet.git)
cd AA_expiriment_starknet
scarb build
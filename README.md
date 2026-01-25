
# Rhinestone Nexus

A modular smart account optimized for chain abstraction and multi-chain use with [Rhinestone Intents](https://docs.rhinestone.dev/home/introduction/rhinestone-intents).

> This is a fork of [Biconomy's Nexus](https://github.com/bcnmy/nexus), a modular smart account built off the foundational work of ERC-7579 and the [ERC-7579 referenvce implementation](https://github.com/erc7579/erc7579-implementation). We extend our thanks to the Biconomy team in partnering with us to build the foundations of ERC-7579.

## Overview

Rhinestone Nexus is an [ERC-7579](https://eips.ethereum.org/EIPS/eip-7579) compliant modular smart account designed for seamless cross-chain operations. Built on top of the battle-tested and heavily audited Biconomy Nexus, this fork adds features specifically designed to work with Rhinestone's intent-based infrastructure.

### Key Features

**Chain Abstraction Ready**
- Multi-chain aware initialization with chain ID verification
- EIP-712 TypedData signing for cross-chain initialize transactions
- Designed for use with Rhinestone Orchestrator for intent execution

**EIP-7702 Native Support**
- Full support for [EIP-7702](https://eips.ethereum.org/EIPS/eip-7702) accounts
- PREP (Provably Rootless EIP-7702 Proxy) implementation for relay-friendly account initialization
- Enables EOAs to delegate to smart account logic without deploying a proxy

**Composable Execution**
- `executeComposable()` for multi-transaction orchestration
- Supports complex execution flows for intent settlement
- Integrated with the modular validator, executor, and hook system

**Enhanced Module System**
- Pre-validation hooks for ERC-4337 and ERC-1271
- Emergency hook uninstall mechanism with timelock protection
- ERC-7484 module registry integration for attested module verification

## Getting Started

### Prerequisites

- Node.js (v18.x or later)
- Yarn (or npm)
- Foundry (Refer to [Foundry installation instructions](https://book.getfoundry.sh/getting-started/installation))

### Installation

1. **Clone the repository:**

```bash
git clone https://github.com/rhinestonewtf/nexus.git
cd nexus
```

2. **Install dependencies:**

```bash
yarn install
```

## Essential Scripts

Build and test using Foundry or Hardhat. Append `:forge` or `:hardhat` to target a specific environment.

### Build Contracts

```bash
yarn build
```

### Run Tests

```bash
yarn test
```

### Gas Report

```bash
yarn test:gas
```

### Coverage Report

```bash
yarn coverage
```

### Generate Documentation

```bash
yarn docs
```

### Lint Code

```bash
yarn lint
```

### Auto-fix Linting Issues

```bash
yarn lint:fix
```

### Generate Storage Layout

```bash
yarn check
```

## Security Audits

| Auditor          | Date       | Report |
| ---------------- | ---------- | ------ |
| CodeHawks-Cyfrin | 09-2024    | [View Report](./audits/CodeHawks-Cyfrin-17-09-2024.pdf) |
| Spearbit         | 10/11-2024 | [View Report](./audits/report-cantinacode-biconomy-0708-final.pdf) / [ERC-7739 Add-on](./audits/report-cantinacode-biconomy-erc7739-addon-final.pdf) |
| Zenith           | 03-2025    | [View Report](./audits/Biconomy-Nexus_Zenith-Audit-Report.pdf) |
| Pashov           | 03-2025    | [View Report](./audits/Nexus-Pashov-Review_2025-03.pdf) |
| ChainLight       | 01-2026    | [View Report](./audits/[ChainLight]%20Rhinestone%20Nexus%20Security%20Audit%20v1.0.pdf) |

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Connect with Rhinestone

[![Website](https://img.shields.io/badge/Website-7C3AED?style=for-the-badge&logoColor=white)](https://rhinestone.dev) [![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/rhinestonewtf) [![GitHub](https://img.shields.io/badge/GitHub-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/rhinestonewtf) [![Documentation](https://img.shields.io/badge/Docs-7C3AED?style=for-the-badge&logoColor=white)](https://docs.rhinestone.wtf)

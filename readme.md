<!--
Copyright 2026 MMXlabs & LQC LLC
SPDX-License-Identifier: Apache-2.0
-->

# LQC Mainnet Development

«Status: Early-stage development. LQC Mainnet is not an operational mainnet or a completed blockchain.»

## Project goal

LQC Mainnet is an independent blockchain development project intended to use Cosmos EVM-based technology. Its design, implementation, integrations, and release plans remain under development and review.

## Relationship with LQC Flow

The project aims to preserve compatibility with the existing BSC-based LQC Flow where technically feasible. Existing BSC code and tests must be preserved. BSC and LQC Mainnet configurations must remain distinct, including chain IDs, RPC endpoints, and contract addresses.

This compatibility goal does not mean that existing LQC Flow contracts or services have been integrated into LQC Mainnet.

## Implementation status

This repository currently contains early-stage development materials, example network configuration, and network quote adapter code and tests. It does not establish that a production blockchain or mainnet is implemented or operating.

Router, Vault, Lending, Futures, and other protocol components must not be considered complete, deployed, or validated unless their implementation and verification are separately documented.

## Tests

In previous local testing, 25 network Adapter unit tests were reported as passing. These results have not been independently revalidated for this publication review and do not establish mainnet readiness.

These results do not validate a blockchain implementation, validators, RPC services, IBC, protocol contracts, or production readiness.

## Unconfirmed development items

The following remain unconfirmed or planned and must not be treated as available production services:

- LQC Devnet and Mainnet chain IDs
- RPC endpoints
- Validator operation
- IBC configuration and operation
- Mainnet launch timing and readiness

## Licensing and project policies

Copyright ownership, contributor rights, and publication permissions for project materials remain subject to final verification. Third-party code retains its applicable license, copyright, and attribution requirements; this project does not claim ownership of third-party materials.

Use of GitHub must comply with its applicable Terms of Service and Acceptable Use Policies. Contributions and reuse are governed by the licenses and rights applicable to each component. Unverified ownership or publication permissions must not be represented as confirmed.
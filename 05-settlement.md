# 05 — Settlement

## Overview

ACE supports multiple settlement methods through a namespace-based system. The protocol defines the message format for invoices and receipts but does not enforce any specific payment mechanism.

## Settlement Method Namespaces

Settlement methods follow the format `namespace/method`:

### `crypto/*` — On-Chain Settlement

| Method | Description | Phase |
|--------|-------------|-------|
| `crypto/instant` | Direct on-chain token transfer | v1.0 |
| `crypto/escrow` | Conditional escrow smart contract | Future |
| `crypto/stream` | Streaming payment (per-second release) | Future |

### `fiat/*` — Off-Chain Settlement

The `fiat/*` namespace is reserved for traditional payment methods. ACE does not specify or endorse any particular fiat payment provider. The `settlementDetails` object is free-form JSON defined by the implementation.

## Settlement Details

### crypto/instant

Direct on-chain token transfer. The payer executes the transfer independently and provides the transaction hash as proof.

**Invoice settlementDetails:**

```json
{
  "chain": "eip155:8453",
  "token": "USDC",
  "tokenAddress": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "recipient": "0x7a3b...f91c"
}
```

**Receipt proof:**

```json
{
  "txHash": "0xabc123...",
  "chain": "eip155:8453"
}
```

The recipient SHOULD verify the transaction on-chain before considering the payment settled.

### fiat/*

The `fiat/*` namespace supports any off-chain payment method. The `settlementDetails` and `proof` objects are free-form JSON — ACE does not define their schema.

## Chain Identifier Format

ACE uses [CAIP-2](https://github.com/ChainAgnostic/CAIPs/blob/main/CAIPs/caip-2.md) chain identifiers:

| Chain | CAIP-2 Identifier |
|-------|-------------------|
| Ethereum Mainnet | `eip155:1` |
| Base | `eip155:8453` |
| Arbitrum | `eip155:42161` |
| Polygon | `eip155:137` |
| BNB Chain | `eip155:56` |
| Solana Mainnet | `solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp` |
| Base Sepolia (testnet) | `eip155:84532` |

## Settlement Negotiation

Agents negotiate settlement methods through the economic message flow:

1. **Registration file** declares supported methods via `settlement` array
2. **rfq** may indicate preferred currency
3. **offer** may include settlement preferences in `terms`
4. **invoice** specifies the exact `settlementMethod` and `settlementDetails`
5. If the payer cannot use the specified method, they may propose an alternative via a new message

The protocol does not enforce settlement method matching. Agents are free to negotiate through `text` messages if the standard flow is insufficient.

## Currency Codes

ACE uses standard identifiers for currencies:

- **Fiat:** ISO 4217 codes (`USD`, `EUR`, `CNY`, etc.)
- **Crypto tokens:** Token symbol (`USDC`, `ETH`, `SOL`, etc.)

When ambiguity exists (e.g., USDC on multiple chains), the `settlementDetails` MUST specify the chain and token contract address.

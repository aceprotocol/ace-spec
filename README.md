# ACE Protocol Specification

**Agent Commerce Engine** — An open protocol for secure, encrypted agent-to-agent communication and commerce.

## Version

1.0 (Draft)

## Overview

ACE Protocol enables AI agents to discover each other, communicate securely, negotiate economic terms, and settle payments — regardless of the underlying blockchain, framework, or infrastructure.

### Design Principles

1. **Define rules, don't restrict** — ACE specifies message formats and flows, not implementations
2. **Key-source agnostic** — Works with Secure Enclave, TPM, HSM, software keys, or any key source
3. **Chain agnostic** — EVM, Solana, or no chain at all
4. **Framework agnostic** — LangChain, CrewAI, OpenClaw, or custom agents
5. **Progressive trust** — Start with a key pair (Tier 0), add chain registration as needed

### Protocol Layers

```
Layer 1: Identity & Discovery     → Who are you? How do I find you?
Layer 2: Encrypted Communication  → Secure, authenticated messaging
Layer 3: Economic Negotiation     → RFQ → Offer → Accept → Invoice → Receipt (state machine enforced)
Layer 4: Settlement               → crypto/instant, fiat/*
Layer 5: Reputation               → Transaction-anchored feedback, scoring, portability
```

### Comparison

| Feature | ACE | Google A2A | Anthropic MCP |
|---------|-----|-----------|---------------|
| E2E Encryption | X-Wing (X25519 + ML-KEM-768) + AES-256-GCM | No | No |
| Identity Tiers | Key / Chain | Agent Card | Server manifest |
| Payment Native | Yes (crypto + fiat) | No | No |
| Hardware Security | Optional (SE/TPM/HSM) | No | N/A |
| Cross-Chain | Yes (signingScheme registry) | N/A | N/A |
| Post-Quantum Encryption | Yes (hybrid KEM) | No | No |

## Version Compatibility

ACE follows these versioning rules:

1. **Minor versions (1.x) are backward compatible.** A v1.1 agent MUST be able to communicate with a v1.0 agent.
2. **Unknown message types MUST be ignored.** If a v1.0 agent receives a message with an unknown `type`, it MUST silently discard it. It MUST NOT reject the connection or respond with an error.
3. **Unknown fields MUST be ignored.** If a message or registration file contains fields not defined in the agent's version of the spec, those fields MUST be ignored, not rejected.
4. **Major versions (2.x) MAY be breaking.** A v2.0 agent is NOT required to be compatible with v1.x agents.

These rules ensure the protocol can evolve without coordination — new message types and fields can be introduced in minor versions, and older agents will simply ignore what they don't understand.

## Specification Documents

| Document | Description |
|----------|-------------|
| [01-identity.md](./01-identity.md) | Identity tiers, registration file format |
| [02-discovery.md](./02-discovery.md) | Discovery mechanisms: direct, well-known, registry, ERC-8004 |
| [03-encryption.md](./03-encryption.md) | X-Wing hybrid post-quantum KEM + HKDF-SHA256 + AES-256-GCM encryption scheme |
| [04-messages.md](./04-messages.md) | Message envelope, types, and economic schemas |
| [05-settlement.md](./05-settlement.md) | Settlement methods: crypto/*, fiat/* |
| [06-security.md](./06-security.md) | Security model: replay protection, signature verification, fail-stop |
| [07-reputation.md](./07-reputation.md) | Reputation system: transaction-anchored feedback, scoring, anti-gaming |

## Signing Schemes

| Scheme | Algorithm | Chains | Spec |
|--------|-----------|--------|------|
| [ed25519](./signing-schemes/ed25519.md) | Ed25519 | Solana, general-purpose | Built-in |
| [secp256k1](./signing-schemes/secp256k1.md) | secp256k1 ECDSA | EVM (Ethereum, Base, etc.) | Built-in |
| [ml-dsa-65](./signing-schemes/ml-dsa-65.md) | ML-DSA-65 (FIPS 204) | — | Reserved |

New schemes are added via PR to this repository.

## License

Apache-2.0

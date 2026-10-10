# ACE Protocol Specification

ACE (Agent Commerce Engine) is an open protocol for agent identity, private communication and verifiable authorization: the trust layer that agents need before they can work, trade and pay together.

## Version

2.0 message packets; 1.0 identity/relay API (Draft). Pre-release: the protocol may change without notice until its first release.

**Architecture status:** [Architecture and implementation status](./00-architecture.md) defines the intended separation of private messaging, resource-scoped authority and application execution. Generic private content and optional commerce/account profiles are implemented across the SDKs. Exact-intent grants and audit proofs have shared SDK implementations. TypeScript and Swift authorities integrate with sponsored Solana/EVM execution and optional pinned-quorum storage. A common MLS engine and three SDK bindings are implemented as a separate component and every CLI, MCP and SoulPass network receive path uses it; independent cryptographic review remains open. Authority/audit deployment and reviewed lost-quorum recovery are also release work.

## Overview

ACE enables agents from different providers to authenticate one another and communicate privately. Financial operations, economic negotiation and reputation are application profiles. SoulPass is a financial agent using the protocol; it has no built-in authority over other agents.

### Design Principles

1. **Separate identity, communication and authority.** Authentication establishes who sent data; execution requires a resource-specific authorization decision.
2. **Use explicit trust roots.** Device labels, model providers, product names and advertised capabilities do not confer rights.
3. **Keep applications extensible.** Text and structured data share the same private channel; unknown semantics never authorize an effect.
4. **Make dependencies optional.** Agents need no blockchain, particular framework, wallet product or hardware vendor to communicate.
5. **State security limits precisely.** Encryption, delivery, execution, settlement and public audit provide distinct guarantees.

### Target Protocol Layers

```
Identity and discovery       → authenticated keys and service discovery
Private communication        → opaque authenticated packets and durable delivery
Resource authorization       → scoped grants, revocation and execution constraints
Optional application profiles→ payments, negotiation, coordination and other schemas
Optional audit               → privacy-preserving commitments and verifiable checkpoints
```

The SDKs support arbitrary namespaced schemas and private application headers. Commerce and account policies are explicitly installed. Static X-Wing encryption is the outer layer of the secure-delivery control frames only; application delivery always runs over a fresh MLS group ([13-session-core.md](./13-session-core.md)). See the architecture status for release gates.

## Current Draft Wire Rules

1. Namespaced custom types with a pinned schema digest are accepted as data. Unknown semantics never authorize execution.
2. Private content is closed to `{type,schemaDigest,threadId?,body}`. Public envelopes reject those four application fields. Other extension fields follow the document-specific parsing rules.

These parsing rules do not grant execution permission. An application receiving a payment or another constrained action must reject unsupported constraints rather than ignore them.

## Specification Documents

| Document | Description |
|----------|-------------|
| [00-architecture.md](./00-architecture.md) | Target architecture, implemented security foundation and remaining release work |
| [01-identity.md](./01-identity.md) | Identity tiers, registration file format, principal field |
| [02-discovery.md](./02-discovery.md) | Discovery mechanisms: direct, well-known, registry, ERC-8004 |
| [03-encryption.md](./03-encryption.md) | X-Wing hybrid post-quantum KEM + HKDF-SHA256 + AES-256-GCM encryption scheme |
| [04-messages.md](./04-messages.md) | Encoding rules, size limits, message envelope, types, economic schemas and state machine |
| [05-settlement.md](./05-settlement.md) | Settlement methods: crypto/*, fiat/* |
| [06-security.md](./06-security.md) | Security model: processing pipeline, replay protection, durable delivery, SDK error codes |
| [07-reputation.md](./07-reputation.md) | Reputation system: transaction-anchored feedback, scoring, anti-gaming |
| [08-relay.md](./08-relay.md) | Relay HTTP API: registration, discovery, send, inbox, listen, intents, webhooks, errors; direct delivery; client rules |
| [09-principal.md](./09-principal.md) | Principal binding (extension draft): principal record, `principal` signing context, same-account rules, `request` / `decision` / `report` |
| [10-resource-grants.md](./10-resource-grants.md) | Exact-intent capabilities, delegation and authoritative reservation |
| [11-audit.md](./11-audit.md) | Private salted commitments, Merkle proofs and signed checkpoints |
| [12-soulpass-payments.md](./12-soulpass-payments.md) | Exact human-approved payments, external pairing and execution receipts |
| [13-session-core.md](./13-session-core.md) | Authenticated fresh MLS delivery, explicit admission, durable receipts and security boundaries |
| [openapi.yaml](./openapi.yaml) | OpenAPI 3.1 rendering of the relay API (documentation; 08-relay.md is normative) |

## Signing Schemes

| Scheme | Algorithm | Chains | Spec |
|--------|-----------|--------|------|
| [ed25519](./signing-schemes/ed25519.md) | Ed25519 | Solana, general-purpose | Built-in |
| [secp256k1](./signing-schemes/secp256k1.md) | secp256k1 ECDSA | EVM (Ethereum, Base, etc.) | Built-in |
| [ml-dsa-65](./signing-schemes/ml-dsa-65.md) | ML-DSA-65 (FIPS 204) | — | Reserved |

New schemes are added via PR to this repository.

## License

Apache-2.0

## Execution and optional audit

[Resource grants](./10-resource-grants.md) bind one exact intent to a resource and executor, with bounded delegation, policy epochs and revocation. All three SDKs share verification vectors. The TypeScript and Swift authorities atomically reserve budget and permanent operation IDs; deployment must route all consumers of a resource to that same authoritative state. SoulPass adapters and its private ACE CLI service use this boundary with local or pinned etcd storage.

[Optional audit](./11-audit.md) provides private salted commitments, Merkle inclusion and consistency proofs, and signed checkpoints. It does not publish anything automatically or replace authorization.

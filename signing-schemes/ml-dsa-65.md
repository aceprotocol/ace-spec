# Signing Scheme: ml-dsa-65 (Reserved)

## Status

**Reserved identifier. Not implemented.** Implementations MUST NOT emit `"ml-dsa-65"` and MUST reject messages or registrations that use it until this document is promoted to Built-in.

## Overview

| Property | Value |
|----------|-------|
| Scheme ID | `ml-dsa-65` |
| Algorithm | ML-DSA-65 (FIPS 204, NIST security level 3) |
| Key size | 1952 bytes (public), 32-byte seed (private) |
| Signature size | 3309 bytes |
| Address format | To be defined |
| Typical chains | None yet (no production chain exposes an ML-DSA precompile) |

## Why reserved

ACE encryption is already hybrid post-quantum (see [03-encryption.md](../03-encryption.md)). Signatures do not face a retroactive threat: a recorded signature cannot be exploited later, and an agent can rotate to a post-quantum signing key at any time with no loss. ACE therefore keeps classical signatures, which are the same keys agents use on-chain, until one of these triggers occurs:

1. A supported chain adopts a post-quantum signature precompile, so an ACE identity can again equal a chain identity; or
2. NIST's 2030 deprecation of 112-bit classical signatures becomes binding for the deployment.

When promoted, ML-DSA-65 will be signed over the same 32-byte `signData` digest as the other schemes, and the `signature.scheme` field already present in every envelope carries the switch.

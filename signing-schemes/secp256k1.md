# Signing Scheme: secp256k1

## Overview

| Property | Value |
|----------|-------|
| Scheme ID | `secp256k1` |
| Algorithm | ECDSA over secp256k1 |
| Key size | 32 bytes (private), 33 bytes (compressed public) |
| Signature size | 65 bytes (r[32] + s[32] + v[1]) |
| Address format | `0x` + hex(keccak256(uncompressedPubKey[1:])[12:]) |
| Typical chains | Ethereum, Base, Polygon, Arbitrum, BNB Chain |

## Address Derivation

```
privateKey[32 bytes]
  → secp256k1.publicKey(compressed=false)[65 bytes]
  → drop first byte (0x04 prefix)
  → Keccak-256(uncompressedPubKey[64 bytes])
  → take last 20 bytes
  → "0x" + hex(20 bytes)
  → address
```

Example: `0x7a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b`

## Signing

```
signData = SHA-256(length-prefixed envelope fields)  // See 04-messages.md
(v, r, s) = secp256k1.sign_recoverable(privateKey, signData)
encoded = "0x" + hex(r[32] || s[32] || v[1])
```

The `v` value is the recovery ID (0 or 1), allowing public key recovery from the signature.

### Low-S Normalization

Implementations SHOULD normalize signatures to low-S form per [EIP-2](https://eips.ethereum.org/EIPS/eip-2). This is RECOMMENDED for consistency but not required — ACE messages do not go on-chain, so there is no consensus-layer enforcement of low-S:

```
if s > secp256k1_N / 2:
    s = secp256k1_N - s
    v = v ^ 1
```

## Verification

```
signData = SHA-256(reconstructed length-prefixed fields)
recoveredPubKey = secp256k1.recover(signData, r, s, v)
recoveredAddress = keccak256(recoveredPubKey[1:])[12:]
valid = constantTimeEqual(recoveredAddress, sender.address)
```

Note: secp256k1 verification uses public key recovery (ecrecover), not direct verification. This is consistent with Ethereum's signature model.

## Address Normalization

EVM addresses are normalized to lowercase hex with `0x` prefix:

```
"0x7A3B...F91C" → "0x7a3b...f91c"
```

Comparison MUST be case-insensitive or performed on normalized (lowercase) addresses.

## Libraries

| Language | Library |
|----------|---------|
| Swift | `GigaBitcoin/secp256k1.swift` (module: `P256K`) |
| TypeScript | `@noble/secp256k1` or `ethers` |
| Python | `eth-keys` or `coincurve` |
| Rust | `secp256k1` (rust-bitcoin) |
| Go | `ethereum/go-ethereum/crypto` |

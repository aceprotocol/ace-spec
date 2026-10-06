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
encoded = "0x" + lowercase_hex(r[32] || s[32] || v[1])
```

The wire encoding is exactly `^0x[0-9a-f]{130}$` ([04-messages.md](../04-messages.md) § Encoding Rules). The `v` value is the recovery ID (0 or 1), allowing public key recovery from the signature.

### Low-S Normalization

Signers MUST emit low-S signatures per [EIP-2](https://eips.ethereum.org/EIPS/eip-2); verifiers reject high-S:

```
if s > secp256k1_N / 2:
    s = secp256k1_N - s
    v = v ^ 1
```

## Verification

Let `n` be the secp256k1 group order. Reject unless all of these hold:

1. The value matches `^0x[0-9a-f]{130}$`; decode `r[32] || s[32] || v[1]`.
2. `r ∈ [1, n-1]`, `s ∈ [1, floor(n/2)]` and `v ∈ {0, 1}`.
3. Recovery succeeds and the recovered key, as a 33-byte compressed point, equals the sender's registered `signingPublicKey` in constant time.

```
signData = SHA-256(reconstructed length-prefixed fields)
recoveredPubKey = secp256k1.recover(signData, r, s, v)
valid = constantTimeEqual(compress(recoveredPubKey), sender.signingPublicKey[33])
```

The registered key is always the 33-byte compressed point (`02`/`03` prefix). Test vectors: `test-vectors.json` → `signatures.secp256k1`.

## Address Normalization

EVM addresses are normalized to lowercase hex with `0x` prefix:

```
"0x7A3B...F91C" → "0x7a3b...f91c"
```

Comparison MUST be case-insensitive or performed on normalized (lowercase) addresses. A registration file's `address` MUST equal the address derived from its `signingPublicKey` under this comparison.

## Libraries

| Language | Library |
|----------|---------|
| Swift | `GigaBitcoin/secp256k1.swift` (module: `P256K`) |
| TypeScript | `@noble/secp256k1` or `ethers` |
| Python | `eth-keys` or `coincurve` |
| Rust | `secp256k1` (rust-bitcoin) |
| Go | `ethereum/go-ethereum/crypto` |

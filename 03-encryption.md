# 03 — Encryption

## Overview

ACE uses X25519 ECDH key exchange with HKDF-SHA256 key derivation and AES-256-GCM authenticated encryption. Every message has forward secrecy through ephemeral key pairs.

## Encryption Flow

### Sending a Message

```
1. Generate ephemeral X25519 key pair (random, per-message)
2. Fetch recipient's X25519 public key (from registration file, cached)
3. ECDH(ephemeralPrivateKey, recipientPublicKey) → sharedSecret
4. HKDF-SHA256(
     ikm: sharedSecret,
     salt: ACE_DH_SALT,
     info: conversationId
   ) → 32-byte AES key
5. Generate random 12-byte nonce
6. AES-256-GCM(
     key: aesKey,
     nonce: nonce,
     plaintext: messageBody,
     aad: conversationId
   ) → ciphertext + tag
7. Output:
     payload: Base64(nonce[12] || ciphertext || tag[16])
     ephemeralPubKey: Base64(ephemeralPublicKey[32])
8. Destroy ephemeral private key immediately
```

### Receiving a Message

```
1. Extract ephemeralPubKey from message
2. Load own X25519 private key
3. ECDH(ownPrivateKey, ephemeralPubKey) → sharedSecret
4. HKDF-SHA256(sharedSecret, ACE_DH_SALT, conversationId) → aesKey
5. Parse payload: nonce[12] || ciphertext || tag[16]
6. AES-256-GCM open(aesKey, nonce, ciphertext, tag, aad=conversationId) → plaintext
```

## Conversation ID

A deterministic, symmetric identifier for any pair of agents:

```
conversationId = hex(SHA-256(sort_bytes(pubKeyA[32], pubKeyB[32])))
```

- `pubKeyA` and `pubKeyB` are the raw 32-byte X25519 public keys
- `sort_bytes` sorts the two keys lexicographically (lower bytes first)
- Output: 64 hex characters, no prefix

Properties:
- **Deterministic:** Same key pair always produces the same ID
- **Symmetric:** A↔B and B↔A produce the same ID
- **Chain-agnostic:** Based on encryption keys, not chain addresses

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `ACE_DH_SALT` | `SHA-256("ace.protocol.dh.v1")` | HKDF salt for AES key derivation |
| Nonce size | 12 bytes | AES-256-GCM standard |
| Tag size | 16 bytes | AES-256-GCM standard |
| X25519 key size | 32 bytes | Curve25519 standard |

### ACE_DH_SALT Computation

```
ACE_DH_SALT = SHA-256(UTF-8("ace.protocol.dh.v1"))
            = 0x562c4f092ff12b7f089228cdd48b6b40447010cd254e1c08d40bf505a8e5925a
```

Implementations MUST precompute this value. The salt input string MUST NOT change across protocol versions without a version negotiation mechanism.

## Forward Secrecy

Every message uses a fresh ephemeral X25519 key pair. Compromise of the identity encryption key does NOT compromise past messages, because:

1. The ephemeral private key is generated randomly per message
2. The ephemeral private key is destroyed immediately after encryption
3. The shared secret is derived from the ephemeral key, not the identity key

## Key Management

### Identity Encryption Key

Each agent has one long-lived X25519 key pair used for:
- Publishing the public key in the registration file
- Decrypting incoming messages (using the private key)

The private key SHOULD be stored in hardware (SE, TPM, HSM) when available. For software-only agents, the private key MUST be stored with appropriate file permissions (0600) and SHOULD be zeroed in memory after use.

### Ephemeral Keys

Generated per-message using a cryptographically secure random number generator. MUST be destroyed immediately after deriving the shared secret.

## Wire Format

The encrypted payload is transmitted as part of the message envelope:

```json
{
  "encryption": {
    "ephemeralPubKey": "Base64(ephemeralPublicKey[32])",
    "payload": "Base64(nonce[12] || ciphertext || tag[16])"
  }
}
```

## Implementation Notes

- Implementations MUST use constant-time comparison for MAC verification
- Implementations MUST NOT reuse nonces with the same key
- Implementations SHOULD use memory-safe handling for key material (mlock, secure zeroing)
- The `conversationId` used as AAD binds the ciphertext to the specific conversation, preventing message transplant attacks
- **Nonce safety:** Because each message generates a fresh ephemeral X25519 key pair, each message derives a cryptographically independent AES key via ECDH + HKDF. Therefore, random 12-byte nonces do not accumulate collision risk across messages — each nonce is used exactly once with its unique key. The birthday-bound concern (2^32 messages under the same key) does not apply.

# 03 — Encryption

## Overview

ACE encrypts every message with a hybrid post-quantum key encapsulation mechanism followed by a symmetric AEAD:

```
X-Wing (X25519 + ML-KEM-768)  →  HKDF-SHA256  →  AES-256-GCM
```

X-Wing is the hybrid KEM specified in `draft-connolly-cfrg-xwing-kem` (ML-KEM-768 per FIPS 203 combined with X25519 per RFC 7748). An attacker must break **both** X25519 and ML-KEM-768 to recover a message key. This protects recorded traffic against future quantum computers ("harvest now, decrypt later"), which is the one attack on an encryption scheme that cannot be fixed later by rotating keys.

ACE defines exactly one suite. Using a hybrid KEM does not make this protocol equivalent to an MLS or Signal session protocol. On the network, every secure-delivery frame is such a packet; the application envelope additionally travels inside a fresh classical MLS group ([13-session-core.md](./13-session-core.md)), which supplies forward secrecy for past deliveries but not post-quantum forward secrecy.

## Encryption Flow

### Sending a Message

```
1. Load recipient's X-Wing public key pk_R (1216 bytes, from the verified peer binding; see 02-discovery.md § Rollback Barrier)
2. (ss, ct) = XWing.Encapsulate(pk_R)
     ss: 32-byte shared secret
     ct: 1120-byte KEM ciphertext
3. HKDF-SHA256(
     ikm:  ss,
     salt: ACE_KEM_SALT,
     info: UTF-8(conversationId)
   ) → 32-byte AES key
4. Generate random 12-byte nonce
5. AES-256-GCM(
     key: aesKey,
     nonce: nonce,
     plaintext: messageBody,
     aad: UTF-8(conversationId)
   ) → ciphertext + tag
6. Output:
     kemCiphertext: Base64(ct[1120])
     payload:       Base64(nonce[12] || ciphertext || tag[16])
7. Destroy ss, aesKey and all encapsulation randomness immediately
```

### Receiving a Message

```
1. Decode kemCiphertext; reject unless exactly 1120 bytes
2. Load own X-Wing private key (32-byte seed)
3. ss = XWing.Decapsulate(ct, seed)
4. HKDF-SHA256(ss, ACE_KEM_SALT, UTF-8(conversationId)) → aesKey
5. Parse payload: nonce[12] || ciphertext || tag[16]
6. AES-256-GCM open(aesKey, nonce, ciphertext, tag, aad = UTF-8(conversationId)) → plaintext
```

ML-KEM uses implicit rejection and X-Wing hashes the X25519 component into the shared secret, so a tampered `kemCiphertext` normally surfaces as an AES-GCM tag failure in step 6. X25519 libraries additionally refuse an all-zero DH output, so a `ct_X` that is a low-order point makes decapsulation itself fail; either way the message is rejected. Decapsulation failure and AEAD failure are both reported as a permanent decryption failure. In practice neither is reached: `kemCiphertext` is part of the signed message payload (see [04-messages.md](./04-messages.md)), so tampering fails signature verification first.

## X-Wing Summary

Normative reference: `draft-connolly-cfrg-xwing-kem` (version 11 or later; the construction has been stable since version 06). This section restates the parts an implementer needs to check an implementation against.

| Item | Value |
|------|-------|
| Private key | 32-byte seed `sk` |
| Seed expansion | `expanded = SHAKE256(sk, 96)`; `(d, z) = expanded[0:64]` is the ML-KEM-768 key-generation seed; `sk_X = expanded[64:96]` |
| Public key | `pk = pk_M[1184] ‖ pk_X[32]` — 1216 bytes |
| Ciphertext | `ct = ct_M[1088] ‖ ct_X[32]` — 1120 bytes |
| Shared secret | `ss = SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ XWingLabel)` — 32 bytes |
| `XWingLabel` | 6 ASCII bytes `\.//^\` = `0x5c2e2f2f5e5c` |

Because `pk_X` and `ct_X` are hashed into the shared secret, no separate X25519 small-order or all-zero checks are needed. Implementations MUST NOT add them (they would only create cross-implementation divergence).

Conformance: an implementation MUST reproduce all three X-Wing draft test vectors (key generation from seed and decapsulation). `test-vectors.json` → `xwing` holds vectors 1–3.

## Conversation ID

A deterministic, symmetric identifier for any pair of agents:

```
conversationId = hex(SHA-256(sort_bytes(pkA[1216], pkB[1216])))
```

- `pkA` and `pkB` are the raw 1216-byte X-Wing public keys
- `sort_bytes` orders the two keys lexicographically (lower bytes first) before concatenation
- Output: 64 lowercase hex characters, no prefix

Properties:
- **Deterministic:** Same key pair always produces the same ID
- **Symmetric:** A↔B and B↔A produce the same ID
- **Chain-agnostic:** Based on encryption keys, not chain addresses

## Constants

| Constant | Value | Purpose |
|----------|-------|---------|
| `ACE_KEM_SALT` | `SHA-256(UTF-8("ace.protocol.kem.v1"))` | HKDF salt for AES key derivation |
| X-Wing public key | 1216 bytes | Recipient static encryption key |
| X-Wing ciphertext | 1120 bytes | Per-message `kemCiphertext` |
| X-Wing private key | 32 bytes (seed) | Stored or derived by the agent |
| Nonce size | 12 bytes | AES-256-GCM standard |
| Tag size | 16 bytes | AES-256-GCM standard |

Implementations MUST precompute `ACE_KEM_SALT`. The salt input string is part of the protocol definition and MUST NOT change without a new protocol major version.

## Security Properties

### What a compromised key reveals in a raw X-Wing packet

| Compromised | Messages exposed |
|-------------|------------------|
| Sender's erased encapsulation randomness | The KEM cannot reconstruct past sent message keys from erased randomness. Plaintext retained by the application, logs or backups remains exposed to endpoint compromise. |
| Recipient's X-Wing private key | **All** messages ever sent to that key, past and future, until the key is rotated. |

Raw X-Wing packets alone have neither forward secrecy against recipient-key compromise nor post-compromise security. The integrated [secure delivery profile](./13-session-core.md) uses them to carry authenticated control frames, with the original application envelope inside a fresh MLS group. Later static-key compromise exposes the outer frames but does not alone decrypt captured past application deliveries after ephemeral state erasure, under classical MLS assumptions. Original application envelopes retained in private Outbox storage, plaintext logs and backups are outside that guarantee. Store static seeds in hardware or derive them from a hardware root where available; rotate compromised bindings as specified in [04-messages.md](./04-messages.md).

### Post-quantum

Encryption is hybrid post-quantum. Message authentication (signatures) is classical; see [06-security.md](./06-security.md) § Post-Quantum Posture for the rationale.

## Key Management

### Identity Encryption Key

Each agent has one long-lived X-Wing key pair:
- The public key (1216 bytes) is published in the registration file as `signing.encryptionPublicKey`
- The private key is a 32-byte seed used to decapsulate incoming messages

The seed SHOULD be stored in, or deterministically derived from, hardware (Secure Enclave, TPM, HSM) when available. For software-only agents, the seed MUST be stored with appropriate file permissions (0600) and SHOULD be zeroed in memory after use. Implementations MAY cache the expanded ML-KEM and X25519 private keys in process memory for the lifetime of the identity object. They MUST NOT persist them.

### Encapsulation Randomness

Generated per message by a cryptographically secure random number generator inside the KEM library. Implementations MUST NOT provide deterministic encapsulation randomness outside of test vectors.

## Wire Format

The encrypted payload is transmitted as part of the message envelope:

```json
{
  "encryption": {
    "kemCiphertext": "Base64(ct[1120])",
    "payload": "Base64(nonce[12] || ciphertext || tag[16])"
  }
}
```

Both fields are canonical Base64. Receivers MUST reject the message unless `kemCiphertext` decodes to exactly 1120 bytes and `payload` decodes to between 28 and `MAX_PAYLOAD_BYTES` (65536) bytes inclusive. Senders MUST NOT encrypt a body larger than `MAX_PLAINTEXT_BYTES` (65508). See [04-messages.md](./04-messages.md) § Size Limits and § Envelope Decoding.

## Implementation Notes

- Implementations MUST use constant-time comparison for MAC verification
- Implementations MUST NOT reuse nonces with the same key
- Implementations SHOULD use memory-safe handling for key material (mlock, secure zeroing)
- The `conversationId` used as AAD binds the ciphertext to the specific conversation, preventing message transplant attacks
- **Nonce safety:** Every message encapsulates a fresh shared secret, so every message derives a cryptographically independent AES key. Random 12-byte nonces therefore do not accumulate collision risk across messages; the 2^32 birthday bound for a single key does not apply.
- **Libraries:** Swift — CryptoKit `XWingMLKEM768X25519` (macOS 26 / iOS 26) or swift-crypto; TypeScript — `@noble/post-quantum` `hybrid.ml_kem768_x25519`; Python — `cryptography` ≥ 48 (`MLKEM768PrivateKey.from_seed_bytes`, `X25519PrivateKey`) with the combiner above.

Public storage of ciphertext magnifies this limitation: a later recipient-key compromise exposes the archived history. Public transport metadata also reveals communicating identities, stable conversation links, timing and ciphertext size. Packet 2.0 encrypts application type and business thread IDs. Do not describe the current relay as a private public ledger or as a verifiable append-only log. This KEM construction provides no forward secrecy by itself; application delivery therefore runs over a fresh MLS (RFC 9420) group per attempt, specified in [13-session-core.md](./13-session-core.md).

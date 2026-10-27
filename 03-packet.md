# 03 — Packet

The packet is the only object agents exchange. It is encrypted to a prekey of the recipient — the published prekey of its descriptor ([04](04-descriptor.md#prekey)) or a peer prekey it offered the sender ([04](04-descriptor.md#peer-prekeys)) — and signed by the sender's delegated signing key.

```json
{
  "ace": "1",
  "messageId": "550e8400-e29b-41d4-a716-446655440000",
  "from": "ace:sha256:…",
  "to": "ace:sha256:…",
  "timestamp": 1760140800,
  "encryption": { "prekey": "<64 hex>", "kemCiphertext": "<Base64, 1120 bytes>", "payload": "<Base64>" },
  "signature": { "scheme": "ml-dsa-65", "seq": 1, "value": "<Base64, 3309 bytes>" }
}
```

## Decoding

A packet is accepted only if all of the following hold. `ace` is checked first; every other failure is `invalid_packet`.

| Field | Rule |
|---|---|
| (packet) | A JSON object whose canonical JSON is at most `MAX_PACKET_BYTES`. A transport rejects a larger serialized packet before parsing |
| `ace` | A string; any value other than `"1"` is `unsupported_version` |
| `messageId` | Message ID ([02](02-encoding.md#identifiers)); chosen by the sender, unique per sender, and kept across retries |
| `from`, `to` | ACE IDs; `from != to` |
| `timestamp` | Wire integer: the time of this signing attempt |
| `encryption.prekey` | Hex digest: the recipient's prekey ID |
| `encryption.kemCiphertext` | Canonical Base64 of exactly 1120 bytes |
| `encryption.payload` | Canonical Base64; decoded length is a plaintext bucket ([§ Encryption](#encryption)) plus 28 |
| `signature` | Delegated signature object ([02](02-encoding.md#delegated-signatures)) |

All three objects are closed: an unknown member at any level is `invalid_packet`.

There is no conversation identifier on the wire. An endpoint that needs a local pair key uses `lowercaseHex(SHA-256(min(a, b) ‖ 0x00 ‖ max(a, b)))`, where `a` and `b` are the UTF-8 bytes of the two ACE IDs, ordered bytewise.

## Encryption

```
content   = canonical JSON of the private content, at most MAX_PLAINTEXT_BYTES
plaintext = u32be(len(content)) ‖ content ‖ 0x00 × pad        // len(plaintext) = bucket(len(content) + 4)
header    = encodePayload("ace.v1.packet", from, to, messageId, decimal(timestamp), prekeyId, kemCiphertextBytes)
(ss, kemCiphertextBytes) = XWing.Encapsulate(prekey.publicKey)
key       = HKDF-SHA256(ikm = ss, salt = "" (empty), info = header, L = 32)
payload   = nonce[12] ‖ AES-256-GCM(key, nonce, plaintext, aad = header)      // ciphertext ‖ tag[16]
```

`bucket(n)` is the smallest power of two that is at least `n` and at least `MIN_PLAINTEXT_BUCKET`, except that when `n` exceeds 2^20 it is `MAX_PLAINTEXT_BYTES + 4`. The plaintext buckets are therefore 2^12 … 2^20 and `MAX_PLAINTEXT_BYTES + 4`. Padding hides the length of the content from the relay: a receipt without a permit renewal and a short message are the same size on the wire. The prekey ID remains visible ([06](06-delivery.md#security-considerations)).

The nonce is 12 random bytes. Every packet encapsulates a fresh secret, so every key is independent. `ss`, `key` and the encapsulation randomness are erased after use; deterministic encapsulation randomness is allowed only in test vectors.

The receiver looks up the prekey seed by `encryption.prekey` among its published prekeys and the peer prekeys it offered to `from` ([04](04-descriptor.md#peer-prekeys); `unknown_prekey` if it holds none), decapsulates, derives `key` from the received header fields and opens the AEAD. Decapsulation and AEAD failures are both `decryption_failed`. It then reads the length prefix `n`: `n <= MAX_PLAINTEXT_BYTES`, `4 + n <= len(plaintext)`, `len(plaintext) = bucket(n + 4)` and every padding byte is zero, else `invalid_body`; the content is `plaintext[4 : 4 + n]`.

`header` binds `from`, `to`, `messageId`, `timestamp` and the prekey. An attacker who strips the signature and re-signs under its own identity changes `from`, so decryption fails.

### X-Wing

Normative reference: `draft-connolly-cfrg-xwing-kem-11` (this exact revision).

| Item | Value |
|---|---|
| Private key | 32-byte seed; `expanded = SHAKE256(seed, 96)`, `expanded[0:64]` is the ML-KEM-768 key-generation seed `(d, z)`, `expanded[64:96]` the X25519 secret |
| Public key | `pk_M[1184] ‖ pk_X[32]`, 1216 bytes; `pk_M` passes the FIPS 203 modulus check (a key that does not is not an X-Wing public key); any 32 bytes are a valid `pk_X` |
| Ciphertext | `ct_M[1088] ‖ ct_X[32]`, 1120 bytes |
| Shared secret | `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ 0x5c2e2f2f5e5c)`, 32 bytes |

Implementations MUST NOT add separate X25519 small-order or all-zero checks beyond what the draft specifies. An implementation MUST reproduce the draft's test vectors.

## Signature

Action `packet`, delegated signature ([02](02-encoding.md#delegated-signatures)) with `aceId = from`, `timestamp` and payload

```
encodePayload(to, messageId, prekeyId, kemCiphertextBytes, payloadBytes)
```

`prekeyId` is the 64-character hex string; the other byte fields are decoded bytes. The signature commits to the ciphertext, so the receiver verifies it before decrypting ([06](06-delivery.md#receive-pipeline)). Swapping `kemCiphertext` or the prekey breaks the signature.

## Private content

The content is the canonical JSON ([02](02-encoding.md#canonical-json)) of exactly:

```json
{ "type": "ace:text:1", "schemaDigest": "<64 hex>", "threadId": "optional", "body": { "message": "hello" }, "admission": "optional", "prekey": "<Base64, 1216 bytes>" }
```

- `type` is a namespaced identifier; `schemaDigest` is the **message digest** of that type in an installed manifest ([08](08-profiles.md#digests)); `body` is a JSON object; `threadId`, when present, is a thread ID. A JSON `null` `threadId` is rejected; absence is the only way to omit it. `admission`, when present, is the closed object `{proof, permit, source}` of three JSON objects, the delivery permits and PublishedAgent of an Outbox retry ([05](05-admission.md#admission-recovery)); on a receipt or contact packet (`ace:receipt:1`, `ace:contact:1`) it is `invalid_body`, and the receiver never hands it to the application. `prekey` is required: the canonical Base64 of the 1216-byte X-Wing public key the sender offers `to` for its next application message back ([04](04-descriptor.md#peer-prekeys)); a value that does not decode as an X-Wing public key ([§ X-Wing](#x-wing)) is `invalid_body`; the receiver never hands it to the application. No other members are allowed.
- The content follows the JSON value rules ([02](02-encoding.md#json-values)) and is at most `MAX_PLAINTEXT_BYTES`. A sender rejects larger content before encrypting.
- Any parse or shape failure of the decrypted content is `invalid_body`.

Type, digest, thread and body are confidential and covered by the signature through the ciphertext. Relays route by `to` only.

# 04 — Messages

## Message Envelope

Every ACE message uses this envelope format:

```json
{
  "ace": "1.0",
  "messageId": "550e8400-e29b-41d4-a716-446655440000",
  "from": "ace:sha256:sender_fingerprint",
  "to": "ace:sha256:recipient_fingerprint",
  "conversationId": "hex(SHA-256(sort(pubA, pubB)))",
  "type": "rfq",
  "threadId": "deal-2026-03-13-gpu-rental",
  "timestamp": 1741000000,
  "body": {},

  "encryption": {
    "kemCiphertext": "Base64(X-Wing ciphertext[1120])",
    "payload": "Base64(nonce || ciphertext || tag)"
  },
  "signature": {
    "scheme": "ed25519",
    "value": "Base64(signature)"
  }
}
```

### Envelope Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `ace` | Yes | string | Protocol version. MUST be `"1.0"` |
| `messageId` | Yes | string | UUID v4, unique per message |
| `from` | Yes | string | Sender's ACE ID |
| `to` | Yes | string | Recipient's ACE ID |
| `conversationId` | Yes | string | Deterministic conversation identifier: 64 lowercase hex characters (see [03-encryption.md](./03-encryption.md)) |
| `type` | Yes | string | Message type (see below). A type not defined in § Message Types MUST be rejected. |
| `threadId` | Conditional | string | Business session identifier. **REQUIRED for all economic messages**, optional for system/social messages. Allows multiple concurrent deals between the same agent pair within one `conversationId`. Free-form string chosen by the initiator (e.g., UUID, deal reference). All messages in a business flow MUST share the same `threadId`. Constraints: max 256 characters, no control characters (U+0000–U+001F, U+007F). |

Wherever this specification limits a string to N "characters", it counts Unicode code points.
| `timestamp` | Yes | number | Unix timestamp in seconds |
| `body` | — | object | Message payload (schema depends on `type`). **Conceptual only**: in transit, the body is encrypted inside `encryption.payload`. Not present as a cleartext field on the wire. |
| `encryption` | Yes | object | Encryption envelope (see [03-encryption.md](./03-encryption.md)) |
| `signature` | Yes | object | Message signature |
| `signature.scheme` | Yes | string | Signing scheme used |
| `signature.value` | Yes | string | Signature value (encoding depends on scheme) |

### Note on Encryption

The `body` field in the envelope above shows the **decrypted** content for readability. In transit, the body is encrypted inside `encryption.payload`. The `type` field remains in cleartext to allow routing without decryption.

The decrypted body MUST be a JSON object (RFC 8259; the non-standard literals `NaN` and `Infinity` are invalid) nested at most 32 levels deep, the top-level object being level 0. An optional field whose value is `null` is treated as absent.

## Signature Construction

The signature covers the full message content to prevent tampering. ACE uses a **unified signing format** across all contexts (messages, registration, relay auth).

```
signData = SHA-256(
  UTF-8("ace.v1") ||
  len(action)[4 bytes, big-endian] || UTF-8(action) ||
  len(aceId)[4 bytes, big-endian] || UTF-8(aceId) ||
  timestamp[8 bytes, big-endian] ||
  len(payload)[4 bytes, big-endian] || payload
)
```

- `"ace.v1"` is a fixed domain separation prefix (raw UTF-8 bytes, not length-prefixed)
- `action` identifies the signing context (e.g., `"message"`, `"register"`, `"listen"`, `"inbox"`, `"unregister"`)
- `aceId` is the signer's ACE ID
- `payload` is context-specific data (e.g., encrypted message bytes, registration fields)
- Length-prefixed fields prevent boundary shifting attacks
- SHA-256 produces a 32-byte digest that is then signed with the sender's signing key

### Signing Contexts

| Action | Context | Payload |
|--------|---------|---------|
| `message` | Agent-to-agent messages | `encodePayload(type, to, conversationId, messageId, threadIdOrEmpty, kemCiphertextBytes, payloadBytes)` |
| `register` | Relay agent registration | Registration payload bytes |
| `listen` | Relay listen connection | `encodePayload(sinceCursorOrDash)` |
| `inbox` | Relay inbox polling | `encodePayload(sinceCursorOrDash, limit)` |
| `unregister` | Relay unregistration | Empty payload |

`threadId` is part of the signed message payload. Economic thread identity is security-relevant: changing `threadId` changes the signed meaning of the message and MUST invalidate the signature.

`kemCiphertext` (the raw 1120 bytes) is also part of the signed payload. It is the sender's commitment to the key the recipient will derive; a relay that swaps it MUST break the signature, not merely garble decryption.

### Signature Encoding by Scheme

| Scheme | Encoding | Size |
|--------|----------|------|
| `ed25519` | Base64 | 64 bytes |
| `secp256k1` | `0x` + hex(r[32] \|\| s[32] \|\| v[1]) | 65 bytes |

## Message Types

### System Messages

| Type | Description | Body Schema |
|------|-------------|-------------|
| `info` | Informational message | `{ "message": "string" }` |

**Key rotation:** To rotate the X-Wing encryption key or the signing key, update the registration file (or on-chain registry). Peers will pick up the new keys on their next fetch (cache TTL: 24h recommended). There is no in-band key-update message — this avoids the vulnerability where a compromised key could be used to send a fraudulent key-update.

**Liveness checks:** Use HTTP-level mechanisms (HEAD request to the endpoint, or a `/health` path) rather than protocol-level ping/pong. Encrypting and signing a liveness check message is unnecessary overhead.

### Economic Messages

Economic messages carry contractual weight. Schema validation is MANDATORY on both send and receive sides.

| Type | Description | Required Fields | Optional Fields |
|------|-------------|-----------------|-----------------|
| `rfq` | Request for Quote | `need` | `maxPrice`, `currency`, `ttl` |
| `offer` | Binding price quote | `price`, `currency` | `terms`, `ttl` |
| `accept` | Accept an offer | `offerId` | |
| `reject` | Decline an offer | | `reason` |
| `invoice` | Request payment | `offerId`, `amount`, `currency`, `settlementMethod` | `settlementDetails` |
| `receipt` | Confirm payment | `referenceId`, `amount`, `currency`, `settlementMethod`, `proof` | |
| `deliver` | Deliver work product | `type` | `content`, `contentType`, `uri`, `metadata` |
| `confirm` | Confirm delivery accepted | `deliverId` | `message` |

### Social Messages

| Type | Description | Body Schema |
|------|-------------|-------------|
| `text` | Free-form text | `{ "message": "string" }` |

## Economic Message Schemas

### rfq (Request for Quote)

```json
{
  "need": "Translate 1000 words English to Chinese",
  "maxPrice": "5.00",
  "currency": "USD"
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `need` | Yes | string | Description of what is needed |
| `maxPrice` | No | string | Maximum acceptable price |
| `currency` | No | string | Currency for maxPrice |
| `ttl` | No | number | Seconds until this RFQ expires. After expiry, the sender may re-send or abandon. |

### offer

```json
{
  "price": "3.50",
  "currency": "USD",
  "terms": "Delivery within 30 minutes, BLEU-4 score > 90",
  "ttl": 300
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `price` | Yes | string | Offered price (string to avoid float precision) |
| `currency` | Yes | string | Currency code. MUST be specified in binding offers. |
| `terms` | No | string | Human/agent-readable terms |
| `ttl` | No | number | Seconds until this offer expires. After expiry (`timestamp + ttl < now`), the offer SHOULD be treated as withdrawn. The offerer MAY send a new offer. |

### accept

```json
{
  "offerId": "550e8400-e29b-41d4-a716-446655440000"
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `offerId` | Yes | string | messageId of the accepted offer |

Receivers MUST verify that the referenced `offerId` exists in the same `(conversationId, threadId)` history before accepting this message.

### reject

```json
{
  "reason": "Price exceeds budget"
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `reason` | No | string | Rejection reason |

### invoice

```json
{
  "offerId": "550e8400-e29b-41d4-a716-446655440000",
  "amount": "3.50",
  "currency": "USD",
  "settlementMethod": "crypto/instant",
  "settlementDetails": {
    "chain": "eip155:8453",
    "token": "USDC",
    "tokenAddress": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
    "recipient": "0x7a3b...f91c"
  }
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `offerId` | Yes | string | messageId of the accepted offer. Binds this invoice to specific agreed terms. |
| `amount` | Yes | string | Amount due. Receivers SHOULD verify this matches the accepted offer's `price`. |
| `currency` | Yes | string | Currency code. SHOULD match the accepted offer's `currency`. |
| `settlementMethod` | Yes | string | Settlement method (see [05-settlement.md](./05-settlement.md)) |
| `settlementDetails` | No | object | Method-specific details (free-form JSON) |

Receivers MUST verify that the referenced `offerId` exists in the same `(conversationId, threadId)` history before accepting this message.

### receipt

```json
{
  "referenceId": "550e8400-e29b-41d4-a716-446655440000",
  "amount": "3.50",
  "currency": "USD",
  "settlementMethod": "crypto/instant",
  "proof": {
    "txHash": "0xabc123...",
    "chain": "eip155:8453"
  }
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `referenceId` | Yes | string | messageId of the message this payment settles: the `invoice`, or on the pre-paid path (no invoice) the `accept` |
| `amount` | Yes | string | Amount paid |
| `currency` | Yes | string | Currency code |
| `settlementMethod` | Yes | string | Settlement method used |
| `proof` | Yes | object | Payment proof (free-form, method-specific) |

Receivers MUST verify that `referenceId` exists in the same `(conversationId, threadId)` history before accepting this message: an `invoice` when the thread is `invoiced`, the `accept` when it is `accepted` (pre-paid).

### deliver

```json
{
  "type": "reference",
  "uri": "https://storage.example.com/result/abc123",
  "contentType": "application/pdf",
  "metadata": {
    "size": 1048576,
    "checksum": "sha256:9f86d08..."
  }
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `type` | Yes | string | `"inline"` or `"reference"` |
| `content` | No | string | Inline content (when type is `"inline"`) |
| `contentType` | No | string | MIME type of the deliverable |
| `uri` | No | string | URI to the deliverable (when type is `"reference"`) |
| `metadata` | No | object | Free-form metadata (size, checksum, expiry, credentials, etc.) |

**Conditional requirements:**
- When `type` is `"inline"`: `content` is REQUIRED
- When `type` is `"reference"`: `uri` is REQUIRED

For `reference` type, it is RECOMMENDED (but not required) to include `checksum` and `expiresAt` in `metadata` to prevent content tampering and stale links:

```json
{
  "type": "reference",
  "uri": "https://storage.example.com/result/abc123",
  "metadata": {
    "checksum": "sha256:9f86d08...",
    "size": 1048576,
    "expiresAt": 1741003600
  }
}
```

The `deliver` message intentionally does not prescribe how the deliverable is hosted or protected. The `uri` can point to any resource: HTTPS URL, IPFS CID, S3 presigned URL, or any other scheme. The `metadata` object is open for implementation-specific fields.

### confirm

```json
{
  "deliverId": "550e8400-e29b-41d4-a716-446655440000",
  "message": "Translation quality verified, BLEU-4 score 94.2"
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `deliverId` | Yes | string | messageId of the `deliver` message being confirmed |
| `message` | No | string | Optional acceptance note or evaluation result |

Receivers MUST verify that the referenced `deliverId` exists in the same `(conversationId, threadId)` history before accepting this message.

The `confirm` message signals that the buyer has accepted the delivered work. This is the normal success path and is essential for:
- Future escrow release (Phase 2)
- Reputation accumulation
- Closing the business session

## Economic Message Flow

### State Machine

Economic messages follow a mandatory state machine per `(conversationId, threadId)` pair. The flow is a single-round linear sequence from negotiation through execution to completion.

```
    idle ──→ rfq ──→ offered ──→ rejected ■
                       │
                       ↓
                   accepted ──→ invoiced ──→ paid ──→ delivered ──→ confirmed ■

    ■  = terminal (no economic messages allowed)
```

#### Thread States

| State | Description |
|-------|-------------|
| `idle` | No messages yet |
| `rfq` | RFQ sent/received, awaiting offer |
| `offered` | Offer on the table, awaiting accept/reject/counter-offer |
| `accepted` | Deal established, awaiting invoice |
| `rejected` | **Terminal.** Offer rejected. No further economic messages. |
| `invoiced` | Invoice issued, awaiting payment |
| `paid` | Payment confirmed, awaiting delivery |
| `delivered` | Work delivered, awaiting confirmation |
| `confirmed` | **Terminal.** Delivery confirmed. No further economic messages. |

#### Transition Table

| From State | Message Type | To State | Use Case |
|------------|-------------|----------|----------|
| `idle` | `rfq` | `rfq` | Start negotiation |
| `rfq` | `offer` | `offered` | Respond to RFQ |
| `offered` | `accept` | `accepted` | Accept the offer |
| `offered` | `reject` | `rejected` | Decline the offer |
| `offered` | `offer` | `offered` | Counter-offer |
| `accepted` | `invoice` | `invoiced` | Request payment |
| `accepted` | `receipt` | `paid` | Pre-paid (no invoice) |
| `accepted` | `deliver` | `delivered` | Deliver-first (trust-based) |
| `invoiced` | `receipt` | `paid` | Confirm payment |
| `paid` | `deliver` | `delivered` | Standard delivery after payment |
| `delivered` | `confirm` | `confirmed` | Accept delivery |

Non-economic messages (`text`, `info`) are always allowed regardless of state and do not change state. This allows agents to communicate freely during any phase of a deal.

Any transition not listed above MUST be rejected.

#### Implementation Requirements

- Implementations MUST enforce the state machine for all economic messages.
- State MUST be tracked per `(conversationId, threadId)` pair, ensuring thread isolation across conversations.
- `threadId` MUST be validated: non-empty, max 256 characters, no control characters (U+0000–U+001F, U+007F).
- Referenced message IDs (`offerId`, `referenceId`, `deliverId`) MUST resolve inside the same `(conversationId, threadId)` history before the transition is accepted.
- State SHOULD be persisted for crash recovery.
- Implementations MAY bound the number of threads and the history length per thread. When a bound is reached they MUST reject the message; they MUST NOT discard existing thread state to make room, since a forgotten terminal thread could be reopened.
- **Sender side:** Implementations MUST pre-check the transition validity before performing cryptographic operations (encrypt + sign). The state transition MUST only be committed after all cryptographic operations succeed. This prevents state corruption if encryption or signing fails.
- **Receiver side:** The state machine validation occurs after decryption and body schema validation (pipeline step 7). This ensures only fully verified messages advance the state.
- `rejected` and `confirmed` are terminal states — no economic messages are allowed after entering these states.

### Standard Flow

```
Buyer                          Seller
  |                              |
  |--- rfq ---------------------->|
  |                              |
  |<---------------------- offer ---|
  |                              |
  |--- accept ------------------>|
  |                              |
  |<-------------------- invoice ---|
  |                              |
  |--- receipt ----------------->|  (after payment)
  |                              |
  |<-------------------- deliver ---|
  |                              |
  |--- confirm ----------------->|  (delivery accepted)
  |                              |
```

### Variations

- **Counter-offer:** Seller sends a new `offer` instead of waiting for `accept`
- **Reject:** Buyer sends `reject` after receiving `offer`
- **Pre-paid:** Buyer sends `receipt` immediately after `accept` (no invoice needed). In this case, `referenceId` MUST be set to the `messageId` of the `accept` message.
- **Deliver-first:** Seller sends `deliver` before `invoice` (trust-based)

# 04 — Messages

## Encoding Rules

These rules apply wherever this specification refers to them: envelopes, bodies, registration files, registration requests, peer records, relay requests and relay responses.

Wherever this specification limits a string to N "characters", it counts Unicode code points.

### Wire Integers

Timestamps, `registeredAt`, `ttl`, `limit`, and the principal record's `issuedAt` and `expiresAt` are wire integers. A JSON number is a valid wire integer only if its mathematical value is an integer in `[0, 2^53-1]`. The lexical form does not matter: `1000`, `1000.0` and `1e3` are all accepted. Booleans, strings, `null` and non-finite values are rejected.

`decimal(n)` denotes the base-10 representation of a wire integer with no sign and no leading zeros (`"0"` for zero).

### Base64

Only padded standard Base64 (RFC 4648 §4) is accepted: no whitespace, no line breaks, no URL-safe alphabet, no missing padding. Decoders MUST reject non-canonical input: re-encoding the decoded bytes MUST reproduce the input exactly (so `"QR=="` is rejected; `"QQ=="` is the canonical form).

### Hex Signatures

A `secp256k1` signature is encoded as exactly `^0x[0-9a-f]{130}$` (65 bytes). Encoders emit lowercase. Decoders MUST reject a missing `0x`, `0X`, uppercase digits and any other length.

### HTTPS URLs

The registration `endpoint`, profile `endpoint` and profile `image` MUST match the ACE HTTPS URL grammar:

```
^https://[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(?::[0-9]{1,5})?(?:[/?#][A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?$
```

and additionally:

- Total length is at most 2048 characters.
- The host (between `://` and the first `:`, `/`, `?`, `#` or end) is at most 253 characters.
- A port, if present, is in 1..65535.

The scheme is lowercase `https` only. Userinfo, IPv6 literals and trailing dots are not accepted. Implementations MUST accept exactly this grammar and MUST NOT substitute a platform URL parser for acceptance.

### Thread IDs

A thread ID is a string of 1..`MAX_THREAD_ID_LENGTH` (256) code points containing no U+0000–U+001F or U+007F. The empty string is invalid. For the private-content `threadId`, a JSON `null` is always rejected; an absent `threadId` is the only way to omit it. Inside message bodies (for example `ref.threadId`, [09-principal.md](./09-principal.md)), a `null` optional field is treated as absent under § Body Rules.

## Size Limits

Normative constants. Every implementation and every relay uses these values.

| Name | Value | Meaning |
|------|-------|---------|
| `MAX_PLAINTEXT_BYTES` | 65508 | UTF-8 private-content JSON before encryption |
| `MAX_PAYLOAD_BYTES` | 65536 | `nonce ‖ ciphertext ‖ tag` (decoded `encryption.payload`) |
| `MAX_ENVELOPE_BYTES` | 131072 | Serialized envelope; SSE data limit |
| `MAX_JSON_DEPTH` | 32 | Private-content nesting depth; its top-level object is depth 0 |
| `MAX_THREAD_ID_LENGTH` | 256 | Code points |
| `MAX_OPEN_THREADS_PER_PEER` | 1000 | non-terminal threads held per peer |
| `TIMESTAMP_WINDOW_SECONDS` | 300 | Future bound for messages; freshness window for relay requests |
| `OFFLINE_WINDOW_SECONDS` | 604800 | Floor offset for a receiver collecting queued messages (`now - 7 days`); relay message TTL MUST NOT exceed this |
| `MAX_REGISTRATION_FILE_BYTES` | 1048576 | Registration file |
| `MAX_INBOX_PAGE` | 100 | Maximum `limit` of `GET /v1/inbox` |
| `MAX_DIRECT_BODY_BYTES` | 132096 | `MAX_ENVELOPE_BYTES + 1024`; direct-delivery and relay request body ([08-relay.md](./08-relay.md) § Direct Delivery, § Limits) |

`MAX_PLAINTEXT_BYTES + 28 = MAX_PAYLOAD_BYTES`. A sender MUST reject a body whose complete private-content serialization exceeds `MAX_PLAINTEXT_BYTES` before encrypting. A transport MUST reject a serialized envelope larger than `MAX_ENVELOPE_BYTES` before parsing it.

## Message Envelope

Every ACE message uses this envelope format:

```json
{
  "ace": "2.0",
  "messageId": "550e8400-e29b-41d4-a716-446655440000",
  "from": "ace:sha256:sender_fingerprint",
  "to": "ace:sha256:recipient_fingerprint",
  "conversationId": "hex(SHA-256(sort(pubA, pubB)))",
  "timestamp": 1741000000,

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
| `ace` | Yes | string | Packet version. MUST be `"2.0"` |
| `messageId` | Yes | string | Lowercase UUID v4, unique per sender |
| `from` | Yes | string | Sender's ACE ID |
| `to` | Yes | string | Recipient's ACE ID |
| `conversationId` | Yes | string | Deterministic conversation identifier: 64 lowercase hex characters (see [03-encryption.md](./03-encryption.md)) |
| `timestamp` | Yes | integer | Unix timestamp in seconds (wire integer) |
| `encryption` | Yes | object | Encryption envelope (see [03-encryption.md](./03-encryption.md)) |
| `signature` | Yes | object | Message signature |
| `signature.scheme` | Yes | string | Signing scheme used. MUST equal the sender's registered scheme. |
| `signature.value` | Yes | string | Signature value (§ Signature Encoding by Scheme) |

### Private content

The encrypted plaintext is exactly this JSON object:

```json
{
  "type": "urn:example:task:1",
  "schemaDigest": "abababababababababababababababababababababababababababababababab",
  "threadId": "private-workflow",
  "body": { "text": "Please summarize this document" }
}
```

`type`, `schemaDigest` and `body` are required; `threadId` is optional. No other private-content keys are accepted. `body` is a JSON object. Plain text uses the bundled `text` profile with `{"message":"…"}`. The depth and plaintext byte limits apply to the entire private-content object, including its wrapper.

A type is either a bundled profile name below, or an ASCII namespaced identifier of at most 256 bytes matching:

```
^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$
```

Identifiers are opaque; parsing MUST NOT fetch a URI or execute code. `schemaDigest` is 64 lowercase hex characters. Senders MUST supply it for custom types. A receiver retains unknown types and digests as authenticated data. A host MAY install a deterministic validator per `schemaDigest` (SDK `Inbox.open` / `Outbox.open` `schemas`); a message whose installed validator fails is rejected at pipeline step 6 of [06-security.md](./06-security.md). Execution still requires a separately installed authorization policy. Text, a type name and a digest confer no authority.

Bundled profiles use SHA-256 of compact, sorted-key UTF-8 JSON of `{type, fields, outcomes, version:1}`. `fields` is the ordered list of `[fieldName, kind]` from the profile tables (`str`, `optStr`, `obj`, `optObj`, `optTtl`); `outcomes` is the ordered allowed-outcome array, or `[]`. Version 1 identifies all bundled validation rules in this document, including references and delivery variants. A change to those rules requires a new profile version and digest. The `text` digest is `c82da8dde17338c28c42d2a6fad644961c3e7a8d1d008f9d2b18e8d624cf4a52`. All SDKs reject a different digest for a bundled profile.

Relays route by recipient. They cannot inspect the type, schema, business thread or body. Endpoints, sender/recipient IDs, conversation ID, timing and ciphertext size remain observable; this envelope does not provide metadata anonymity.

### Envelope Decoding

A received envelope is accepted only if all of the following hold. `ace` is checked first; every other failure is `invalid_envelope`.

| Field | Rule |
|-------|------|
| (envelope) | A JSON object |
| `ace` | A string. Any value other than `"2.0"` fails with `unsupported_version`; a missing or non-string `ace` fails with `invalid_envelope` |
| `messageId` | `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` (lowercase only) |
| `from`, `to` | `^ace:sha256:[0-9a-f]{64}$` |
| `conversationId` | `^[0-9a-f]{64}$` |
| `timestamp` | Wire integer |
| `encryption.kemCiphertext` | Canonical Base64 of exactly 1120 bytes |
| `encryption.payload` | Canonical Base64; decoded length in `[28, MAX_PAYLOAD_BYTES]` |
| `signature.scheme` | `ed25519` or `secp256k1` |
| `signature.value` | `ed25519`: canonical Base64 of exactly 64 bytes. `secp256k1`: `^0x[0-9a-f]{130}$` |

The cleartext envelope MUST reject `type`, `threadId`, `schemaDigest` and `body`, even if null. Other unknown fields in the envelope, `encryption` and `signature` are ignored. The behavior on duplicate JSON keys is unspecified.

### Envelope Fingerprint

The fingerprint of an envelope is the lowercase hex `SHA-256` of the RFC 8785 (JCS) serialization of its known fields only: `ace`, `messageId`, `from`, `to`, `conversationId`, `timestamp`, `encryption` (`kemCiphertext`, `payload`) and `signature` (`scheme`, `value`). Unknown fields at every level are dropped first, so two envelopes that differ only in unknown fields have the same fingerprint. Concretely: keys sorted; strings escape only `"`, `\` and control characters (`\b \f \n \r \t`, others as lowercase `\u00xx`); non-ASCII is emitted as raw UTF-8; `/` is not escaped; `timestamp` is `decimal(timestamp)`.

### Body Rules

The decrypted body is accepted only if:

- It is valid UTF-8 (invalid sequences are rejected, not replaced) and parses as a JSON object (RFC 8259).
- It contains no non-finite numbers. This includes the non-standard literals `NaN` and `Infinity` and literals that overflow to infinity, such as `1e400`.
- It is nested at most `MAX_JSON_DEPTH` (32) levels deep, the top-level object being depth 0.
- It satisfies the schema for its `type` (§ Message Types, § Economic Message Schemas):
  - Required string fields are present, non-null strings. The empty string is allowed.
  - An optional field whose value is `null` is treated as absent.
  - `ttl` (`rfq`, `offer`, `request`) is a wire integer.
  - Object-typed fields (`settlementDetails`, `proof`, `metadata`, `ref`, `details`, `result`) are JSON objects.
  - `decision.outcome`, `report.outcome` and `ref` satisfy [09-principal.md](./09-principal.md) § Principal Messages.

Unknown body fields are ignored and preserved. A failure is `invalid_body`.

Senders apply the same JSON-value rules before serialization: they reject NaN, ±Infinity, undefined values, functions and non-plain objects, and depth greater than 32.

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
- `action` identifies the signing context (§ Signing Contexts)
- `aceId` is the signer's ACE ID
- `timestamp` is a wire integer
- `payload` is context-specific data
- Length-prefixed fields prevent boundary shifting attacks
- SHA-256 produces a 32-byte digest that is then signed with the signer's signing key

`encodePayload(f1, …, fn)` is `len(f1)[4 bytes, big-endian] || f1 || … || len(fn)[4] || fn`. String fields are encoded as UTF-8; byte fields are used as is. `encodePayload()` with no fields is the empty byte string.

### Signing Contexts

The complete list. A signature produced under one action MUST NOT verify under any other.

| Action | Context | Payload |
|--------|---------|---------|
| `packet` | Agent-to-agent packets | `encodePayload(to, conversationId, messageId, kemCiphertextBytes, payloadBytes)` |
| `register` | Public encryption-key binding ([02-discovery.md](./02-discovery.md)) | `encodePayload(encryptionPublicKeyB64, signingPublicKeyB64)` |
| `register-request` | Relay registration write authorization | `registrationPayload` ([02-discovery.md](./02-discovery.md) § Registration authorization) |
| `listen` | `GET /v1/listen` | `encodePayload(sinceOrDash)` |
| `inbox` | `GET /v1/inbox` | `encodePayload(sinceOrDash, decimal(limit))` |
| `unregister` | `POST /v1/unregister` | Empty (0 bytes) |
| `intent` | `POST /v1/intents` | `encodePayload(need, join(tags, ","), extCanonicalOrEmpty, decimal(ttl))` |
| `webhook` | `PUT` / `GET` / `DELETE /v1/webhook` ([08-relay.md](./08-relay.md) § Webhooks) | `encodePayload(method, urlOrEmpty, secretOrEmpty)` |
| `grant` | Exact-intent resource capability ([10-resource-grants.md](./10-resource-grants.md)) | `encodePayload(claimsDigest)` |
| `audit` | Signed log checkpoint ([11-audit.md](./11-audit.md)) | `encodePayload(logId, decimal(size), rootBytes)` |
| `principal` | Principal attestation ([09-principal.md](./09-principal.md)) | `encodePayload(account, join(roles, ","), signer.scheme, signer.publicKey, subjectSigningPublicKeyB64, scopeOrEmpty, decimal(expiresAt))` |

- For `packet`, `aceId` is `from` and `timestamp` is the envelope `timestamp`. `kemCiphertextBytes` and `payloadBytes` are the decoded bytes.
- For `register` and `register-request`, `aceId` and `timestamp` are the request's. `encryptionPublicKeyB64` and `signingPublicKeyB64` are the Base64 strings as sent.
- For `listen`, `inbox`, `unregister`, `intent` and `webhook`, `aceId` and `timestamp` are the `X-ACE-Id` and `X-ACE-Timestamp` headers ([08-relay.md](./08-relay.md) § Authentication). `sinceOrDash` is the `since` value, or `-` when absent. `limit` is the effective limit. `tags` absent is the empty list. For `webhook`, `method` is the uppercase HTTP method as sent (`PUT`, `GET` or `DELETE`). For `GET` and `DELETE`, `urlOrEmpty` and `secretOrEmpty` are empty strings. For `PUT` they are the request body's `url` and `secret`.
- For `principal`, `aceId` is the **subject's** ACE ID and `timestamp` is `issuedAt`; the signature is made by the record's `signer`, not by the holder of `aceId`. `subjectSigningPublicKeyB64` is computed by the verifier from the subject key it verified; `scopeOrEmpty` is empty when `scope` is absent.

`threadId` is inside the ciphertext covered by the packet signature. Economic thread identity is security-relevant: changing `threadId` changes the signed meaning of the message and MUST invalidate the signature.

`kemCiphertext` (the raw 1120 bytes) is also part of the signed payload. It is the sender's commitment to the key the recipient will derive; a relay that swaps it MUST break the signature, not merely garble decryption.

### Signature Encoding by Scheme

| Scheme | Encoding | Size |
|--------|----------|------|
| `ed25519` | Canonical Base64 (§ Encoding Rules) | 64 bytes |
| `secp256k1` | `0x` + lowercase hex(r[32] \|\| s[32] \|\| v[1]), exactly `^0x[0-9a-f]{130}$` | 65 bytes |

Decoders MUST reject any other encoding. Verification rules are in [signing-schemes/ed25519.md](./signing-schemes/ed25519.md) and [signing-schemes/secp256k1.md](./signing-schemes/secp256k1.md).

## Bundled application profiles

These names are conveniences, not a closed protocol type registry. Commerce state transitions are opt-in (`commerce: true` / `commerce=True` in durable SDKs, or an explicit low-level thread machine). The account coordination policy from 09 is also opt-in. Neither is implicit in ordinary transport reception.

### Message Types

The bundled application profiles define 13 reserved names: `info`, `text`, the 8 economic types `rfq`, `offer`, `accept`, `reject`, `invoice`, `receipt`, `deliver`, `confirm`, and the 3 principal types `request`, `decision`, `report`.

### System Messages

| Type | Description | Body Schema |
|------|-------------|-------------|
| `info` | Informational message | `{ "message": "string" }` |

**Key rotation:** To rotate the X-Wing encryption key, publish a new binding (relay registration with a newer timestamp, or an updated registration file or on-chain record). Peers adopt it under the rollback barrier ([02-discovery.md](./02-discovery.md) § Rollback Barrier) on their next refresh (cache TTL: 24h recommended). The signing key determines the ACE ID; a new signing key is a new identity. There is no in-band key-update message — this avoids the vulnerability where a compromised key could be used to send a fraudulent key-update.

**Liveness checks:** Use HTTP-level mechanisms (HEAD request to the endpoint, or a `/health` path) rather than protocol-level ping/pong. Encrypting and signing a liveness check message is unnecessary overhead.

### Economic Messages

Economic messages are proposals or evidence interpreted by the optional commerce application profile. A received message is never payment authorization. Schema validation is MANDATORY on both send and receive sides.

| Type | Description | Required Fields | Optional Fields |
|------|-------------|-----------------|-----------------|
| `rfq` | Request for Quote | `need` | `maxPrice`, `currency`, `ttl` |
| `offer` | Binding price quote | `price`, `currency` | `terms`, `ttl` |
| `accept` | Accept an offer | `offerId` | |
| `reject` | Decline an RFQ or an offer | | `reason` |
| `invoice` | Request payment | `offerId`, `amount`, `currency`, `settlementMethod` | `settlementDetails` |
| `receipt` | Confirm payment | `referenceId`, `amount`, `currency`, `settlementMethod`, `proof` | |
| `deliver` | Deliver work product | `type` | `content`, `contentType`, `uri`, `metadata` |
| `confirm` | Confirm delivery accepted | `deliverId` | `message` |

### Commerce extension (`urn:ace:commerce:1`)

The commerce profile's discovery data lives under the namespaced key `urn:ace:commerce:1` of a profile's, registration file's or intent's `ext` object ([02-discovery.md](./02-discovery.md) § Profile Fields), never in the generic identity or discovery fields:

| Carrier | Member | Rule |
|---------|--------|------|
| profile, registration file | `chains` | string[]: CAIP-2 identifiers `^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}$`, at most 10 |
| profile, registration file | `pricing` | `{ "currency": string, "maxAmount"?: string }`; `currency` 1–16 characters without control characters, `maxAmount` 1–32 characters matching `^[0-9]+(\.[0-9]+)?$` |
| profile, registration file | `settlement` | string[]: settlement methods ([05-settlement.md](./05-settlement.md)), at most 10 |
| profile, registration file | `accounts` | `[{ "network": CAIP-2, "address": string }]`: payment addresses, at most 10 |
| intent | `maxPrice`, `currency` | strings (1–64 and 1–16 characters); both present or both absent |

SDKs validate this object whenever the namespace is present (`invalid_profile` for profiles and registration files, `invalid_argument` for intents) and expose it as typed data; a relay treats it like any other extension (stored and served in canonical form, not indexed). No member of it confers authority or changes message processing.

### Social Messages

| Type | Description | Body Schema |
|------|-------------|-------------|
| `text` | Free-form text | `{ "message": "string" }` |

### Principal Messages

| Type | Description | Required Fields | Optional Fields |
|------|-------------|-----------------|-----------------|
| `request` | Ask a controller of the same account to approve an action | `action`, `summary` | `ref`, `amount`, `currency`, `details`, `ttl` |
| `decision` | A controller's answer to a `request` | `requestId`, `outcome` | `reason`, `result` |
| `report` | Tell another identity of the same account what was done | `action`, `summary`, `outcome` | `ref`, `requestId`, `proof` |

Schemas, enums and the same-account acceptance rules are in [09-principal.md](./09-principal.md). Principal messages never change economic thread state.

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
| `ttl` | No | integer | Seconds until this RFQ expires (wire integer). After expiry, the sender may re-send or abandon. |

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
| `ttl` | No | integer | Seconds until this offer expires (wire integer). After expiry (`timestamp + ttl < now`), the offer SHOULD be treated as withdrawn. The offerer MAY send a new offer. |

### accept

```json
{
  "offerId": "550e8400-e29b-41d4-a716-446655440000"
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `offerId` | Yes | string | messageId of the accepted offer: the thread's head entry (§ References) |

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
| `offerId` | Yes | string | messageId of the accepted offer: the entry immediately before the `accept` (§ References). Binds this invoice to specific agreed terms. |
| `amount` | Yes | string | Amount due. Receivers SHOULD verify this matches the accepted offer's `price`. |
| `currency` | Yes | string | Currency code. SHOULD match the accepted offer's `currency`. |
| `settlementMethod` | Yes | string | Settlement method (see [05-settlement.md](./05-settlement.md)) |
| `settlementDetails` | No | object | Method-specific details (free-form JSON) |

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
| `referenceId` | Yes | string | messageId of the thread's head entry: the `invoice` when the thread is `invoiced`, or the buyer's own `accept` on the pre-paid path (§ References) |
| `amount` | Yes | string | Amount paid |
| `currency` | Yes | string | Currency code |
| `settlementMethod` | Yes | string | Settlement method used |
| `proof` | Yes | object | Payment proof (free-form, method-specific) |

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
| `content` | No | string | Inline content (when type is `"inline"`) |
| `contentType` | No | string | MIME type of the deliverable |
| `uri` | No | string | URI to the deliverable (when type is `"reference"`) |
| `metadata` | No | object | Free-form metadata (size, checksum, expiry, credentials, etc.) |

**Conditional requirements:**
- When `type` is `"inline"`: `content` is REQUIRED
- When `type` is `"reference"`: `uri` is REQUIRED
- Any other `type` value is invalid

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
| `deliverId` | Yes | string | messageId of the `deliver` being confirmed: the thread's head entry (§ References) |
| `message` | No | string | Optional acceptance note or evaluation result |

The `confirm` message signals that the buyer has accepted the delivered work. This is the normal success path and is essential for:
- Reputation accumulation
- Closing the business session

## Economic Message Flow

### State Machine

Applications that explicitly install the commerce profile apply its state machine per `(conversationId, threadId)` pair. The flow is a single-round linear sequence from negotiation through execution to completion.

```
    idle ──→ rfq ──→ offered ──→ rejected ■
              │        │
              │        ↓
              │    accepted ──→ invoiced ──→ paid ──→ delivered ──→ confirmed ■
              │
              └──→ rejected ■

    ■  = terminal (no economic messages allowed)
```

#### Thread States

| State | Description |
|-------|-------------|
| `idle` | No messages yet |
| `rfq` | RFQ sent/received, awaiting offer |
| `offered` | Offer on the table, awaiting accept/reject/counter-offer |
| `accepted` | Deal established, awaiting invoice, payment or delivery |
| `rejected` | **Terminal.** RFQ or offer rejected. No further economic messages. |
| `invoiced` | Invoice issued, awaiting payment |
| `paid` | Payment confirmed, awaiting delivery |
| `delivered` | Work delivered, awaiting confirmation |
| `confirmed` | **Terminal.** Delivery confirmed. No further economic messages. |

#### Parties and Roles

A thread has exactly two parties, fixed by its first message (`from`, `to`), which MUST differ. Every later message in the thread MUST be between the same two parties, in either direction.

The sender of the `rfq` is the **buyer**. The other party is the **seller**. Each transition requires a sender role.

#### Transition Table

| From State | Message Type | Sender | To State | Use Case |
|------------|-------------|--------|----------|----------|
| `idle` | `rfq` | buyer (defines the buyer) | `rfq` | Start negotiation |
| `rfq` | `offer` | seller | `offered` | Respond to RFQ |
| `rfq` | `reject` | seller | `rejected` | Seller declines the RFQ |
| `offered` | `offer` | seller | `offered` | Counter-offer (supersedes the previous offer) |
| `offered` | `accept` | buyer | `accepted` | Accept the offer |
| `offered` | `reject` | buyer | `rejected` | Decline the offer |
| `accepted` | `invoice` | seller | `invoiced` | Request payment |
| `accepted` | `receipt` | buyer | `paid` | Pre-paid (no invoice) |
| `accepted` | `deliver` | seller | `delivered` | Deliver-first (trust-based) |
| `invoiced` | `receipt` | buyer | `paid` | Confirm payment |
| `paid` | `deliver` | seller | `delivered` | Standard delivery after payment |
| `delivered` | `confirm` | buyer | `confirmed` | Accept delivery |

Non-economic messages (`text`, `info`, `request`, `decision`, `report`) are always allowed regardless of state and do not change state. This allows agents to communicate freely during any phase of a deal.

Any transition not listed above MUST be rejected.

#### History

Each accepted economic message appends an entry `{type, messageId, timestamp, from}` to the thread history. The **head** entry is the last one. The buyer is `history[0].from`.

#### References

References resolve to fixed positions in the history, never to an arbitrary earlier entry:

| Field | MUST equal the messageId of |
|-------|------------------------------|
| `accept.offerId` | The head entry (the latest offer; superseded offers are not acceptable) |
| `invoice.offerId` | The entry immediately before the `accept` entry (the accepted offer) |
| `receipt.referenceId` | The head entry (the `invoice` when `invoiced`; the buyer's own `accept` when `accepted`) |
| `confirm.deliverId` | The head entry (the `deliver`) |

The referenced entry's `from` is therefore always the counterparty, except for the pre-paid `receipt`, which references the buyer's own `accept`.

#### Check Order

A receiver (and a sender, before it encrypts) checks an economic message in this order; the first failure determines the error:

1. `threadId` absent or invalid → `invalid_envelope`.
2. The local agent is not one of `from`, `to`, or `from == to` → `wrong_party`.
3. The thread has history and its parties are not `{from, to}` → `wrong_party`.
4. The state is terminal, or `(state, type)` is not in the transition table → `transition_not_allowed`.
5. The sender's role is not the role the transition requires → `wrong_role`.
6. A reference does not match § References → `bad_reference` (a missing reference field is `invalid_body`, caught by § Body Rules).
7. A thread-count or history-length bound is reached → `limit_exceeded`.

A failed check does not change state.

#### Implementation Requirements

- Implementations MUST enforce the state machine for all economic messages.
- State MUST be tracked per `(conversationId, threadId)` pair, ensuring thread isolation across conversations.
- `threadId` MUST be a valid thread ID (§ Encoding Rules).
- State SHOULD be persisted for crash recovery.
- Implementations MAY bound the number of threads and the history length per thread. When a bound is reached they MUST reject the message; they MUST NOT discard existing thread state to make room, since a forgotten terminal thread could be reopened.
- **Retention:** an implementation MAY delete a terminal thread (`rejected` or `confirmed`) once its head entry's timestamp is older than `now - 30 days` (2592000 seconds, greater than `OFFLINE_WINDOW_SECONDS`). It MAY also delete a non-terminal thread in which the local party has sent no message, once its head entry is older than `now - 30 days` (no local obligation exists). Any other non-terminal thread MUST NOT be discarded.
- **Open-thread bound:** a receiver bounds the non-terminal threads it holds per peer (`MAX_OPEN_THREADS_PER_PEER` = 1000). A message that would open another thread beyond the bound is rejected with `limit_exceeded`; existing threads are unaffected.
- **Sender side:** Implementations MUST pre-check the transition (§ Check Order) before performing cryptographic operations (encrypt + sign). The state transition MUST only be committed after all cryptographic operations succeed. This prevents state corruption if encryption or signing fails.
- **Receiver side:** The state machine validation occurs after decryption and body schema validation (pipeline step 7 in [06-security.md](./06-security.md)). This ensures only fully verified messages advance the state.
- `rejected` and `confirmed` are terminal states — no economic messages are allowed after entering these states.

**Known race:** a party may act on a state that a message still in flight has superseded (for example, the buyer accepts an offer while a counter-offer is pending delivery). The receiver rejects such a message (`bad_reference` or `transition_not_allowed`). Resolving the race is out of scope; the parties continue from the receiver's state.

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

- **Counter-offer:** Seller sends a new `offer` instead of waiting for `accept`. Only the latest offer can be accepted.
- **Decline RFQ:** Seller sends `reject` in state `rfq`.
- **Reject:** Buyer sends `reject` after receiving `offer`.
- **Pre-paid:** Buyer sends `receipt` immediately after `accept` (no invoice needed). In this case, `referenceId` MUST be set to the `messageId` of the `accept` message.
- **Deliver-first:** Seller sends `deliver` before `invoice` (trust-based)

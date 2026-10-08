# 06 — Security

## Security Model

ACE follows two core security principles:

- **Zero Trust:** Never trust data from the network without independent verification
- **Fail-Stop:** When verification fails, reject the message. Never degrade to an insecure mode.

## Message Processing Pipeline

Receivers MUST process ALL messages (economic, system, social and principal) through this pipeline in order. A failure at any step causes the message to be rejected; the first failure determines the error code. The sender identity (ACE ID, scheme, signing key, encryption key) comes from a verified peer binding ([02-discovery.md](./02-discovery.md) § Rollback Barrier), never from the envelope itself.

```
1. Envelope Validation
   → Apply 04-messages.md § Envelope Decoding        (invalid_envelope | unsupported_version)
   → `to` MUST equal the recipient's ACE ID           (wrong_recipient)
   → `from` MUST equal the ACE ID of the sender
     identity being verified against                   (invalid_envelope)
   → `signature.scheme` MUST equal the sender's
     registered scheme                                 (scheme_mismatch)
   → `conversationId` MUST equal
     computeConversationId(senderEncKey, recipientEncKey)
     over the verified keys                            (invalid_envelope)

2. Timestamp Freshness (BEFORE expensive operations)
   → Reject unless floor <= timestamp <= now + TIMESTAMP_WINDOW_SECONDS
     (floor: see § Floor)                              (stale_timestamp)
   → Reject if timestamp <= H or timestamp <= H[from]
     (the seen store's horizons)                       (replay)

3. Replay Check
   → Reject if (from, messageId) is in the seen store  (replay)

4. Signature Verification (BEFORE decryption)
   → Reconstruct signData (04-messages.md § Signing Contexts, action `message`)
   → Verify with the sender's registered key under the
     strict rules of signing-schemes/*.md              (invalid_signature)
   → Then atomically commit to the seen store (§ Seen Message Store, Commit). Nothing enters
     the store before its signature verifies, and an entry is never removed
     on a later failure (decryption, body schema, state machine): an
     authentic message is processed at most once regardless of outcome

5. Decryption
   → Only after signature is verified
   → X-Wing decapsulation + HKDF-SHA256 + AES-256-GCM  (decryption_failed)

6. Body Validation
   → Apply 04-messages.md § Body Rules                 (invalid_body)
   → Reject malformed bodies (defense in depth)

7. State and Principal Validation
   → Economic types: apply 04-messages.md § Check Order: party check, transition,
     role check, reference positions (§ References), bounds
                     (wrong_party | transition_not_allowed | wrong_role |
                      bad_reference | limit_exceeded)
   → Apply state transition atomically
   → rejected and confirmed are terminal — reject all economic messages
   → Principal types: apply 09-principal.md § Same-Account Rules
                     (wrong_principal | bad_reference)
   → An accepted decision marks its request decided after the
     delivery record and before the replay state (§ Durable Delivery)

Note: On the **sender side**, the state machine uses a two-phase pattern:
  (a) Pre-check: verify the transition would be valid (fail fast)
  (b) Perform cryptographic operations (encrypt + sign)
  (c) Commit: apply the state transition only after crypto succeeds
This prevents state corruption if encryption or signing fails.
```

## Replay Protection

Invariant: a (from, messageId) pair MUST be rejected for as long as its message could still
pass step 2.

### Seen Message Store

The seen store holds entries `E` of `(timestamp, from, messageId)`, where `from` and
`timestamp` are the message's signed sender and envelope timestamp, a horizon
`H`, and per-sender horizons `H[from]`. Step 2 rejects every message with
`timestamp <= H` or `timestamp <= H[from]`, so removing an entry is safe once a
horizon covers it.

Entries are ordered by `(timestamp, from, messageId)` ascending; strings compare by
their UTF-8 bytes. `capacity` is an integer >= 1 and the sender quota is
`Q = max(1, floor(capacity / 16))`.

**Accepts.** `(messageId, from, timestamp)` is accepted iff `timestamp > H`,
`timestamp > H[from]` (if `H[from]` exists) and `(from, messageId)` is not in `E`.

**Commit** `(messageId, s, ts, floor)`: if the message is not accepted, the commit fails.
Otherwise insert `(ts, s, messageId)`, then:

1. **Floor.** While the smallest entry has `timestamp < floor`: remove it and raise `H` to
   its timestamp.
2. **Sender quota.** While sender `s` holds more than `Q` entries: remove `s`'s smallest
   entry, raise `H[s]` to its timestamp, and remove every entry of `s` with
   `timestamp <= H[s]`.
3. **Capacity.** While `|E| > capacity`: remove the smallest entry `e`, raise `H[e.from]`
   to its timestamp, and remove every entry of `e.from` with `timestamp <= H[e.from]`.
4. **Sender horizons.** Delete every `H[x] <= H`. If more than `capacity` sender horizons
   remain, sort them by `(H[x], x)` ascending and fold the first
   `count - floor(capacity / 2)` into `H` (raise `H` to each, delete it); then remove
   every entry with `timestamp <= H` and delete every `H[x] <= H` again.

"Raise X to t" means `X = max(X, t)`. After raising any horizon, the entries it covers
are removed in the same step. The quota bounds what one sender can occupy; it does not stop
Sybil senders. Capacity eviction can still raise an honest sender's `H[from]`, which only
rejects that sender's *older* out-of-order messages.

- **New store:** `H = now - TIMESTAMP_WINDOW_SECONDS` for an online receiver, or
  `H = floor - 1` for a receiver using an offline floor, on first use only. No sender
  horizons. Missing or corrupt state beside existing message history MUST NOT be
  treated as first use.
- **Capacity:** Minimum 100,000 entries (the SDK default).
- **Persistence:** Entries, `H` and the sender horizons are persisted together. The export
  is canonical: entries sorted by `(timestamp, from, messageId)` ascending, sender horizons
  sorted by sender. Every exported entry is above both horizons and unique. Restoring an
  export validates these properties and then normalizes it (step 2 for each sender in
  ascending order, then steps 3 and 4), so restoring preserves replay decisions. File
  format: § Appendix A.
- **Storage:** File or database, permissions 0600 (owner read/write only).

### Floor

The floor is a value in `[0, now]`. An online receiver uses
`now - TIMESTAMP_WINDOW_SECONDS`. A receiver that collects messages queued at a relay uses
`now - OFFLINE_WINDOW_SECONDS` (the SDK receive pipeline default). Relays MUST NOT retain a
message longer than `OFFLINE_WINDOW_SECONDS`, so every queued message stays above that floor.

A receiver MUST use the same floor for every message, live ones included: a live message
processed with a narrower floor would remove entries below it and raise `H` past queued
messages not yet processed.

### Timestamp Freshness

Timestamps prevent delayed replay of old messages:

| Bound | Value |
|-------|-------|
| Future | `now + TIMESTAMP_WINDOW_SECONDS` (5 minutes) |
| Past | The floor |
| Direct (non-relay) delivery | `|now - timestamp| <= TIMESTAMP_WINDOW_SECONDS` in addition |

Together with the store's horizons, the window is an **anti-replay** mechanism, not a business validity constraint. Business-level validity is handled by per-message fields:
- `offer.ttl` — how long an offer remains valid
- `rfq.ttl` — how long a request remains open
- `deliver.metadata.expiresAt` — when a delivery link expires

Implementations SHOULD use NTP-synchronized clocks.

## Durable Delivery

### Receiver

A receiver commits an accepted message in this order. Each step is durable before the next
begins:

1. Write the delivery record (the parsed message and the resulting thread snapshot). This is
   the commit point: a failure here leaves no trace and the message is retried.
1a. If the message is a `decision`, update the referenced `requests/` record (`decision` filled); if it is a `request`, nothing (requests are written by the sender).
2. Write the thread state.
3. Write the replay state (the tentative seen store that includes this message).
4. Hand the message to the application.
5. Mark the delivery as handed over.
6. Advance the cursor.

Replay state is updated on a copy and swapped in only after step 3 succeeds. On restart,
recovery repairs thread and replay state from delivery records and hands over every record
not yet marked. The application MUST persist its effect idempotently, keyed by
`(from, messageId)`, before returning.

Rejections:

- A relay-sourced message that fails permanently (any pipeline error) is quarantined under
  its envelope fingerprint ([04-messages.md](./04-messages.md) § Envelope Fingerprint), so a
  forged sender or message ID cannot poison an authentic delivery. If the failure came
  after step 4 of the pipeline, the seen-store commit is persisted too.
- A replay is a duplicate: nothing is written.
- A direct-sourced message is unauthenticated until verified; its rejections are not
  persisted. Direct delivery additionally requires `|now - timestamp| <= TIMESTAMP_WINDOW_SECONDS`.
- A transient failure (relay unreachable, timeout) or local failure (storage, unavailable key hardware) is retryable: the tentative replay
  state is discarded, including horizons.

The relay cursor advances past delivered, duplicate and quarantined entries, and stops
before the first retryable one.

### Sender

Persist a pending signed envelope together with its resulting thread state before
sending it. Uncertain network outcomes retry the same envelope and message ID;
a retry MUST NOT advance the thread twice. Clear the pending envelope only after
acknowledgement, or when a later inbound message on the thread proves delivery. A pending
envelope that the relay rejects as expired (`envelope_expired`) MAY be re-signed with the
same `messageId` and a fresh timestamp; the thread entry it produced is rebuilt with the new
timestamp.

A `request` whose transport succeeded is recorded in `requests/` ([09-principal.md](./09-principal.md) § Persistence) before the pending envelope is cleared; a crash in between leaves the send pending, and the retry writes the record.

## Signature Verification

### Verification Before Decryption

Signatures are verified BEFORE decryption. This means:
- Invalid messages are rejected without spending resources on decryption
- Signature verification uses only cleartext envelope fields + encrypted payload bytes
- The signature commits to the ciphertext, not the plaintext

### Cross-Scheme Verification

Receivers MUST support all signing schemes declared in the protocol's signing scheme registry. When verifying:

1. Require `signature.scheme` to equal the sender's registered scheme
2. Load the sender's signing public key from the verified peer binding
3. Dispatch to the scheme's strict verification ([ed25519](./signing-schemes/ed25519.md), [secp256k1](./signing-schemes/secp256k1.md))
4. Use constant-time comparison for all cryptographic operations

### Address Normalization

| Scheme | Normalization |
|--------|--------------|
| `secp256k1` | Lowercase hex with `0x` prefix; compared case-insensitively |
| `ed25519` | Base58 as-is (case-sensitive) |

## Memory Safety

Implementations SHOULD:

- Store private keys in locked memory (mlock) when available
- Zero key material immediately after use (secure zeroing, not just deallocation)
- Destroy KEM shared secrets and derived AES keys in a `defer`/`finally` block
- Never log or serialize private key material

## Peer Key Caching

Peer bindings are cached and pinned under [02-discovery.md](./02-discovery.md) § Rollback Barrier. The 24-hour TTL triggers a refresh only; it never removes a pin.

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping, including recorded traffic against future quantum computers | E2E encryption (X-Wing hybrid KEM + AES-256-GCM) |
| Message tampering | Signature verification |
| Replay attacks | messageId dedup + timestamp freshness + seen-store horizons |
| Seen-store flooding by one sender | Per-sender quota and per-sender horizons |
| Message transplant | conversationId as AAD in encryption, recomputed from verified keys |
| Impersonation | Signature tied to registered signing key; `from` and scheme bound to the verified peer |
| Delegate impersonating its principal | Principal attestation signed by the account key over the subject key + same-account rule (09-principal.md) |
| Encryption-key rollback | Rollback barrier on signed `registeredAt` |
| Sender state compromise | Nothing recoverable: encapsulation randomness and shared secrets are destroyed after use |
| State-skipping (e.g., invoice without accept) | Mandatory state machine per (conversationId, threadId) |
| Role confusion (e.g., seller sends `accept`) | Sender roles in the transition table |
| Third-party injection into a thread | Parties fixed by the first message |
| Double-spend (duplicate receipt) | State machine rejects repeated transitions |
| Cross-conversation thread hijack | Signed `threadId` + reference positions scoped to `(conversationId, threadId)` |
| Resource exhaustion by oversized input | 04-messages.md § Size Limits |

### Out of Scope

| Threat | Notes |
|--------|-------|
| Endpoint availability (DDoS) | Transport-level concern, not protocol-level |
| Malicious agent behavior | Handled by reputation (ERC-8004) and settlement mechanisms |
| Recipient encryption key compromise | Exposes all messages to that key, past and future, until rotated via a new binding. No ratchet in ACE 1.0. |
| Quantum forgery of classical signatures | Not retroactive; see § Post-Quantum Posture |
| Side-channel attacks on encryption | Implementation concern, not protocol-level |

## Post-Quantum Posture

| Layer | ACE 1.0 | Rationale |
|-------|---------|-----------|
| Message encryption | **Hybrid post-quantum** — X-Wing (X25519 + ML-KEM-768), see [03-encryption.md](./03-encryption.md) | Recorded ciphertext can be decrypted later by a quantum computer; this cannot be fixed by rotating keys after the fact |
| Message authentication | Classical — `ed25519`, `secp256k1` | A signature is only ever checked at receipt time; there is no retroactive attack. Keeping classical keys keeps the ACE identity equal to the agent's chain key |
| Reserved | `ml-dsa-65` (FIPS 204), see [signing-schemes/ml-dsa-65.md](./signing-schemes/ml-dsa-65.md) | Promoted when a supported chain exposes a post-quantum signature precompile or when classical signatures are deprecated for the deployment |

Pure (non-hybrid) ML-KEM is deliberately not used: every production deployment of post-quantum key exchange (Apple, Signal, Chrome, Cloudflare, IETF TLS/MLS suites) is hybrid, so a lattice break does not leave the protocol weaker than classical X25519.

## SDK Error Codes

An SDK reports every failure as one error type carrying a `code`. The `category` is a fixed function of the code. `transient` and `local` failures are retryable; `permanent` ones are not.

| Category | Codes |
|----------|-------|
| `permanent` | `invalid_argument`, `invalid_envelope`, `unsupported_version`, `wrong_recipient`, `invalid_signature`, `invalid_authorization`, `scheme_mismatch`, `stale_timestamp`, `replay`, `decryption_failed`, `invalid_body`, `transition_not_allowed`, `wrong_role`, `wrong_party`, `bad_reference`, `limit_exceeded`, `invalid_key`, `invalid_registration`, `invalid_profile`, `invalid_peer`, `invalid_principal`, `wrong_principal`, `stale_peer_binding`, `unknown_peer`, `not_registered`, `relay_rejected`, `envelope_expired`, `pending_send_conflict`, `blocked_address`, `direct_rejected` |
| `transient` | `relay_unavailable`, `relay_protocol_error`, `fetch_failed`, `direct_unavailable` |
| `local` | `storage_failed`, `identity_unavailable`, `handler_failed`, `receiver_busy`, `lock_busy` |

- `lock_busy`: a store lock is held by another holder and was not acquired within the lock timeout (default 10 s). `storage_failed` is reserved for I/O failures.
- `direct_rejected`: the receiver's direct endpoint answered 400 or 413 ([08-relay.md](./08-relay.md) § Direct Delivery). The error carries the receiver's `error` string as its remote code only when that string matches `^[a-z0-9_]{1,64}$`; any other value is peer-controlled text and is dropped.
- `direct_unavailable`: the direct endpoint could not be reached or answered anything other than 2xx `{"ok":true}`, 400 or 413 (network failure, timeout, 429, 503, other statuses).
- Relay HTTP responses map onto these codes as specified in [08-relay.md](./08-relay.md) § Client Rules.

## Implementation Checklist

- [ ] Strict envelope decoding, body rules and size limits (04-messages.md)
- [ ] Seen store with horizons, sender quota and canonical persistence
- [ ] Signature verification before decryption, with strict scheme rules
- [ ] Timestamp freshness enforcement
- [ ] Schema validation on both send and receive
- [ ] State machine with parties, roles and reference positions (send and receive sides); principal same-account rules (09)
- [ ] Durable delivery in the normative commit order
- [ ] X-Wing conformance against the draft test vectors (`test-vectors.json` → `xwing`)
- [ ] Constant-time cryptographic comparisons
- [ ] Secure key material handling (mlock, zeroing)
- [ ] Peer binding cache with rollback barrier
- [ ] File permissions (0600) for all sensitive data

## Appendix A: SDK Persistence Formats (non-normative)

The ACE SDKs persist pipeline state in a key-value store with these keys, so that other implementations can read and write the same files. Writers emit compact UTF-8 JSON with keys sorted ascending, non-ASCII unescaped and `/` unescaped. Readers accept any valid JSON. An unknown `version` is a storage error. `replay.json` contains only integers and ASCII strings, so its canonical form is byte-identical across implementations (`test-vectors.json` → `replay`).

`sha256(a ‖ 0x00 ‖ b)` below is lowercase hex SHA-256 over the UTF-8 strings joined by one zero byte.

| Key | Content |
|-----|---------|
| `replay.json` | `{"entries":[[messageId,from,timestamp],…],"horizon":H,"senderHorizons":{from:H[from]},"version":1}`; entries in seen-store order |
| `cursors.json` | `{"cursors":{"<normalized relay URL, 08-relay.md § Client Rules>":"<ms>-<seq>"},"version":1}` |
| `threads/<sha256(conversationId ‖ 0x00 ‖ threadId)>.json` | `{"conversationId","history":[{"from","messageId","timestamp","type"}],"localAceId","peerAceId","pending":null\|PendingSend,"state","threadId","version":1}` |
| `outbox/<sha256(requestId)>.json` | `{"message":Envelope,"requestId","requestTtl"?:int,"stagedAt","status":"pending"\|"expired","version":1}` (non-economic pending sends; `requestTtl` is optional and omitted when absent, see `PendingSend` below) |
| `deliveries/<sha256(from ‖ 0x00 ‖ messageId)>.json` | `{"fingerprint","message":{"body","conversationId","from","messageId","threadId":string\|null,"timestamp","to","type"},"receivedAt","source":"relay"\|"direct","status":"pending"\|"acked","thread":ThreadSnapshot\|null,"version":1}` |
| `quarantine/<fingerprint>.json` | `{"code","envelope":{known fields},"fingerprint","quarantinedAt","reason","source":"relay","version":1}`; `reason` at most 1000 characters. At most 1000 records: when exceeded, the oldest by `(quarantinedAt, fingerprint)` are deleted down to 900 |
| `requests/<sha256(conversationId ‖ 0x00 ‖ messageId)>.json` | `{"conversationId","decision":null\|{"messageId","outcome","timestamp"},"expiresAt":null\|int,"messageId","sentAt","to","version":1}`; written by the Outbox after a `request` is delivered (before the pending send is cleared); `decision` filled when the Inbox accepts a `decision` for it ([09-principal.md](./09-principal.md) § Persistence). Deletable 30 days after `sentAt` |
| `peers/<sha256(aceId)>.json` | `{"aceId","encryptionPublicKey","fetchedAt","profile":object\|null,"registeredAt","registrationSignature":string\|null,"scheme","signingPublicKey","source":"relay"\|"registration","version":1}`; keys Base64. Re-verified on load; the cached principal is stored as `profile.principal` whatever the source (relay profile or registration-file top-level `principal`), pinned with the profile and re-verified on load with `fetchedAt` as the time |
| `locks/<name>.lock` | File-store internal: `{"createdAt","host","pid"}`; `name` matches `^[a-z0-9][a-z0-9_-]{0,63}$` |

- `PendingSend` is `{"message":Envelope,"requestId","requestTtl"?,"stagedAt","status"}`. `requestTtl` is an optional wire integer, present only for a pending `request` whose body carried `ttl`; a retry uses it to compute the `requests/` record's `expiresAt`, because the body is encrypted to the recipient and the sender cannot re-read it. The member is omitted when absent, so canonical JSON stays valid. Inside a thread record it has no `version`. A thread has at most one pending send.
- `ThreadSnapshot` is the thread record without `pending` and `version`.
- Envelopes use the wire shape. Timestamps are Unix seconds.
- A delivery record whose status is `acked` is deleted once its timestamp is covered by `H` or `H[from]`. Terminal threads with no pending send are deleted after the 30-day retention ([04-messages.md](./04-messages.md) § Implementation Requirements).

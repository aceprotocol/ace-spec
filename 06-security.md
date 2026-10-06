# 06 — Security

## Security Model

ACE follows two core security principles:

- **Zero Trust:** Never trust data from the network without independent verification
- **Fail-Stop:** When verification fails, reject the message. Never degrade to an insecure mode.

## Message Processing Pipeline

Receivers MUST process ALL messages (economic, system, and social) through this pipeline in order. A failure at any step causes the message to be rejected.

```
1. Envelope Validation
   → Verify ace version, required fields present
   → Verify `to` field matches recipient's ACE ID

2. Timestamp Freshness (BEFORE expensive operations)
   → Reject unless floor <= timestamp <= now + 5 minutes
     (floor: see § Replay Protection)
   → Reject if timestamp <= H or timestamp <= H[from] (the seen store's horizons)

3. Replay Check
   → Reject if messageId is in the seen store

4. Signature Verification (BEFORE decryption)
   → Verify signature.scheme is supported
   → Verify signature against sender's public key
   → Reconstruct signData and compare
   → Then atomically: if messageId is in the seen store → reject; else insert
     (messageId, from, timestamp). Nothing enters the store before its signature
     verifies, and an entry is never removed on a later failure (decryption,
     body schema, state machine): an authentic message is processed at most
     once regardless of outcome

5. Decryption
   → Only after signature is verified
   → X-Wing decapsulation + HKDF-SHA256 + AES-256-GCM

6. Body Schema Validation
   → Economic messages: validate required fields per type
   → Reject malformed bodies (defense in depth)

7. State Machine Validation (economic messages only)
   → Verify threadId is present for economic messages
   → Validate threadId format (non-empty, max 256 chars, no control chars)
   → Verify any referenced message IDs (`offerId`, `invoiceId`, `deliverId`) belong to the same (conversationId, threadId)
   → Verify transition is valid for current (conversationId, threadId) state
   → Apply state transition atomically
   → rejected and confirmed are terminal — reject all economic messages
   → See 04-messages.md § State Machine for the full transition table

Note: On the **sender side**, the state machine uses a two-phase pattern:
  (a) Pre-check: verify the transition would be valid (fail fast)
  (b) Perform cryptographic operations (encrypt + sign)
  (c) Commit: apply the state transition only after crypto succeeds
This prevents state corruption if encryption or signing fails.
```

## Replay Protection

Invariant: a messageId MUST be rejected for as long as its message could still
pass step 2.

### Seen Message Store

The seen store holds entries `(messageId, from, timestamp)`, where `from` and
`timestamp` are the message's signed sender and envelope timestamp, a horizon
`H`, and per-sender horizons `H[from]`. Step 2 rejects every message with
`timestamp <= H` or `timestamp <= H[from]`, so removing an entry is safe once a
horizon covers it:

- **Removal:** only the entry with the smallest `timestamp` may be removed.
  When its `timestamp` is below the floor, raise `H` to it. When the store is
  over capacity, raise only `H[from]` of that entry's sender to it: a sender
  flooding the store then delays only its own messages, never anyone else's.
- **Sender horizons:** at most `capacity` are kept. Drop any `H[from] <= H`;
  if still over, fold the lowest into `H` (raise `H` to them and drop them).
- **New store:** `H = now - 5 minutes`, no sender horizons.
- **Capacity:** Minimum 100,000 entries
- **Persistence:** Entries, `H` and the sender horizons are persisted together. Economic messages
  MUST be persisted before they are acted on; system/social messages MAY be
  batch-persisted.
- **Storage:** File-based (e.g., `~/.ace/seen_messages.json`) or database,
  permissions 0600 (owner read/write only)

### Floor

The floor is `now - 5 minutes`. A receiver collecting messages queued while it
was offline MAY set a fixed earlier floor. Nothing else changes: entries removed
while the backlog is processed raise `H`, so a redelivered message is rejected
at step 2. Use that floor for every message, live ones included, until the
backlog is done: a live message processed with the default floor removes the
backlog entries below it and raises `H` past any backlog message not yet
processed.

### Timestamp Freshness

Timestamps prevent delayed replay of old messages:

| Message Category | Max Drift |
|-----------------|-----------|
| All messages | 5 minutes |

The future bound is fixed at 5 minutes; the past bound is the floor. Together
with the store's horizon, the window is an **anti-replay** mechanism, not a business validity constraint. Business-level validity is handled by per-message fields:
- `offer.ttl` — how long an offer remains valid
- `rfq.ttl` — how long a request remains open
- `deliver.metadata.expiresAt` — when a delivery link expires

Implementations SHOULD use NTP-synchronized clocks.

## Signature Verification

### Verification Before Decryption

Signatures are verified BEFORE decryption. This means:
- Invalid messages are rejected without spending resources on decryption
- Signature verification uses only cleartext envelope fields + encrypted payload bytes
- The signature commits to the ciphertext, not the plaintext

### Cross-Scheme Verification

Receivers MUST support all signing schemes declared in the protocol's signing scheme registry. When verifying:

1. Read `signature.scheme` from the envelope
2. Load the sender's signing public key (from cached registration file)
3. Dispatch to the appropriate verification algorithm
4. Use constant-time comparison for all cryptographic operations

### Address Normalization

| Scheme | Normalization |
|--------|--------------|
| `secp256k1` | Lowercase hex with `0x` prefix |
| `ed25519` | Base58 as-is (case-sensitive) |

## Memory Safety

Implementations SHOULD:

- Store private keys in locked memory (mlock) when available
- Zero key material immediately after use (secure zeroing, not just deallocation)
- Destroy KEM shared secrets and derived AES keys in a `defer`/`finally` block
- Never log or serialize private key material

## Peer Key Caching

Agent registration files (containing X-Wing public keys) MAY be cached:

- **TTL:** 24 hours recommended
- **Storage:** Per-peer cache file with appropriate permissions
- **Invalidation:** When a peer's registration file changes (detected on next fetch), invalidate cache immediately

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping, including recorded traffic against future quantum computers | E2E encryption (X-Wing hybrid KEM + AES-256-GCM) |
| Message tampering | Signature verification |
| Replay attacks | messageId dedup + timestamp freshness |
| Message transplant | conversationId as AAD in encryption |
| Impersonation | Signature tied to registered signing key |
| Sender state compromise | Nothing recoverable: encapsulation randomness and shared secrets are destroyed after use |
| State-skipping (e.g., invoice without accept) | Mandatory state machine per (conversationId, threadId) |
| Double-spend (duplicate receipt) | State machine rejects repeated transitions |
| Cross-conversation thread hijack | Signed `threadId` + reference checks scoped to `(conversationId, threadId)` |

### Out of Scope

| Threat | Notes |
|--------|-------|
| Endpoint availability (DDoS) | Transport-level concern, not protocol-level |
| Malicious agent behavior | Handled by reputation (ERC-8004) and settlement mechanisms |
| Recipient encryption key compromise | Exposes all messages to that key, past and future, until rotated via registration file update (or on-chain). No ratchet in ACE 1.0. |
| Quantum forgery of classical signatures | Not retroactive; see § Post-Quantum Posture |
| Side-channel attacks on encryption | Implementation concern, not protocol-level |

## Post-Quantum Posture

| Layer | ACE 1.0 | Rationale |
|-------|---------|-----------|
| Message encryption | **Hybrid post-quantum** — X-Wing (X25519 + ML-KEM-768), see [03-encryption.md](./03-encryption.md) | Recorded ciphertext can be decrypted later by a quantum computer; this cannot be fixed by rotating keys after the fact |
| Message authentication | Classical — `ed25519`, `secp256k1` | A signature is only ever checked at receipt time; there is no retroactive attack. Keeping classical keys keeps the ACE identity equal to the agent's chain key |
| Reserved | `ml-dsa-65` (FIPS 204), see [signing-schemes/ml-dsa-65.md](./signing-schemes/ml-dsa-65.md) | Promoted when a supported chain exposes a post-quantum signature precompile or when classical signatures are deprecated for the deployment |

Pure (non-hybrid) ML-KEM is deliberately not used: every production deployment of post-quantum key exchange (Apple, Signal, Chrome, Cloudflare, IETF TLS/MLS suites) is hybrid, so a lattice break does not leave the protocol weaker than classical X25519.

## Implementation Checklist

- [ ] Seen store with horizon `H`, persisted
- [ ] Signature verification before decryption
- [ ] Timestamp freshness enforcement
- [ ] Schema validation on both send and receive
- [ ] State machine enforcement for economic messages (send and receive sides)
- [ ] State machine persistence for crash recovery
- [ ] X-Wing conformance against the draft test vectors (`test-vectors.json` → `xwing`)
- [ ] Constant-time cryptographic comparisons
- [ ] Secure key material handling (mlock, zeroing)
- [ ] Peer key cache with TTL and invalidation
- [ ] File permissions (0600) for all sensitive data

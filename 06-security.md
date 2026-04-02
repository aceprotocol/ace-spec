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
   → All messages: reject if |now - timestamp| > 5 minutes

3. Replay Detection (atomic check-and-reserve)
   → Atomically: if messageId seen → reject; else reserve messageId
   → Reservation prevents concurrent duplicates before full processing

4. Signature Verification (BEFORE decryption)
   → Verify signature.scheme is supported
   → Verify signature against sender's public key
   → Reconstruct signData and compare

5. Decryption
   → Only after signature is verified
   → X25519 ECDH + HKDF + AES-256-GCM

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

8. Mark as Seen (atomic)
   → Add messageId to seen set
   → Economic messages: persist immediately (crash-resilient)
   → System/social messages: batch-persist acceptable
   → MUST be atomic to prevent concurrent duplicates
```

## Replay Protection

### Seen Message Store

Implementations MUST maintain a persistent set of seen messageIds to prevent replay attacks.

- **Storage:** File-based (e.g., `~/.ace/seen_messages.json`) or database
- **Capacity:** Minimum 100,000 entries with LRU eviction
- **Persistence:** Economic message IDs MUST be persisted immediately. System/social message IDs MAY be batch-persisted.
- **File permissions:** 0600 (owner read/write only)

### Timestamp Freshness

Timestamps prevent delayed replay of old messages:

| Message Category | Max Drift |
|-----------------|-----------|
| All messages | 5 minutes |

The 5-minute window is an **anti-replay** mechanism, not a business validity constraint. Business-level validity is handled by per-message fields:
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
- Destroy ephemeral keys in a `defer`/`finally` block
- Never log or serialize private key material

## Peer Key Caching

Agent registration files (containing X25519 public keys) MAY be cached:

- **TTL:** 24 hours recommended
- **Storage:** Per-peer cache file with appropriate permissions
- **Invalidation:** When a peer's registration file changes (detected on next fetch), invalidate cache immediately

## Threat Model

### In Scope

| Threat | Mitigation |
|--------|-----------|
| Eavesdropping | E2E encryption (X25519 + AES-256-GCM) |
| Message tampering | Signature verification |
| Replay attacks | messageId dedup + timestamp freshness |
| Message transplant | conversationId as AAD in encryption |
| Impersonation | Signature tied to registered signing key |
| Key compromise (past messages) | Forward secrecy via ephemeral keys |
| State-skipping (e.g., invoice without accept) | Mandatory state machine per (conversationId, threadId) |
| Double-spend (duplicate receipt) | State machine rejects repeated transitions |
| Cross-conversation thread hijack | Signed `threadId` + reference checks scoped to `(conversationId, threadId)` |

### Out of Scope

| Threat | Notes |
|--------|-------|
| Endpoint availability (DDoS) | Transport-level concern, not protocol-level |
| Malicious agent behavior | Handled by reputation (ERC-8004) and settlement mechanisms |
| Key compromise (future messages) | Requires key rotation via registration file update (or on-chain) |
| Side-channel attacks on encryption | Implementation concern, not protocol-level |

## Implementation Checklist

- [ ] Replay detection with persistent storage
- [ ] Signature verification before decryption
- [ ] Timestamp freshness enforcement
- [ ] Schema validation on both send and receive
- [ ] State machine enforcement for economic messages (send and receive sides)
- [ ] State machine persistence for crash recovery
- [ ] Constant-time cryptographic comparisons
- [ ] Secure key material handling (mlock, zeroing)
- [ ] Peer key cache with TTL and invalidation
- [ ] File permissions (0600) for all sensitive data

# 07 — Reputation

## Overview

**Status:** extension draft. `feedback` is not one of the message types defined in [04-messages.md](./04-messages.md), so ACE 1.0 receivers reject it (§ Envelope Decoding) until this chapter is promoted. The Reputation API below is not part of the relay API in [08-relay.md](./08-relay.md).

ACE Reputation is an open, off-chain reputation system built on top of the ACE economic message flow. Feedback is anchored to real completed transactions (`confirm` messages), stored and aggregated by Relays, and optionally synced to on-chain registries (ERC-8004) for high-value agents.

### Design Principles

1. **Transaction-anchored** — No real transaction, no feedback. Eliminates fake reviews at the protocol level.
2. **Multi-dimensional** — Single scores get gamed. ACE tracks multiple independent dimensions.
3. **Reviewer-weighted** — Not all feedback is equal. High-reputation, high-volume reviewers carry more weight.
4. **Time-decaying** — Recent performance matters more than ancient history.
5. **Off-chain first** — Relay stores and serves reputation data. On-chain (ERC-8004) is optional for agents that want immutable, portable records.
6. **Bilateral** — Both buyer and seller can rate each other after a completed transaction.
7. **Open and portable** — Reputation data format is standardized. Any Relay or client can aggregate and verify.

## Feedback Message

After a transaction reaches the `confirmed` terminal state, either party MAY send a `feedback` message within the feedback window.

### Message Type

| Type | Description | Required Fields | Optional Fields |
|------|-------------|-----------------|-----------------|
| `feedback` | Rate the counterparty | `threadId`, `ratings` | `comment`, `evidence` |

### Schema

```json
{
  "threadId": "deal-2026-03-13-gpu-rental",
  "ratings": {
    "overall": 4,
    "quality": 5,
    "speed": 4,
    "value": 3
  },
  "comment": "Excellent translation quality, slightly slow delivery",
  "evidence": {
    "type": "reference",
    "uri": "https://storage.example.com/feedback/abc123.json",
    "hash": "sha256:9f86d08..."
  }
}
```

### Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `threadId` | Yes | string | The `threadId` of the completed transaction. MUST reference a thread in `confirmed` state. |
| `ratings` | Yes | object | Multi-dimensional ratings (see Rating Dimensions below) |
| `ratings.overall` | Yes | integer | Overall satisfaction score, 1–5 |
| `ratings.quality` | No | integer | Delivery quality / accuracy, 1–5 |
| `ratings.speed` | No | integer | Response and delivery timeliness, 1–5 |
| `ratings.value` | No | integer | Price-to-quality ratio, 1–5 |
| `comment` | No | string | Free-text feedback. Max 1000 characters. |
| `evidence` | No | object | Link to detailed evidence (screenshots, logs, diffs) |
| `evidence.type` | Yes | string | `"reference"` |
| `evidence.uri` | Yes | string | URI to evidence file |
| `evidence.hash` | No | string | Content hash for integrity verification |

### Rating Dimensions

| Dimension | Description | Applies To |
|-----------|-------------|------------|
| `overall` | Overall transaction satisfaction | Both parties |
| `quality` | Quality of delivered work product | Seller (rated by buyer) |
| `speed` | Responsiveness and delivery timeliness | Both parties |
| `value` | Fairness of price relative to quality | Seller (rated by buyer) |
| `reliability` | Payment promptness and commitment | Buyer (rated by seller) |

Implementations MUST accept and store any dimension key, even if not listed above. This allows the ecosystem to evolve new dimensions organically. The `overall` dimension is the only REQUIRED rating.

### Feedback Rules

1. **Transaction anchor:** Feedback MUST reference a `threadId` that has reached the `confirmed` state in the same `conversationId`. Implementations MUST verify this before accepting the feedback message.

2. **One feedback per party per thread:** Each party MAY send exactly one `feedback` message per `(conversationId, threadId)`. Duplicate feedback for the same thread MUST be rejected.

3. **Feedback window:** Feedback MUST be submitted within 7 days (604,800 seconds) of the `confirm` message timestamp. After this window, the feedback right expires.

4. **Bilateral:** Both buyer and seller MAY submit feedback independently. Neither party can see the other's feedback until both have submitted, or the feedback window expires — whichever comes first. This prevents retaliation bias.

5. **Immutable:** Once submitted, feedback cannot be modified or deleted. This is a deliberate design decision — mutability enables "good-review-for-refund" gaming patterns.

6. **No self-review:** The `from` field MUST NOT equal the ACE ID of the agent being rated. Implementations MUST reject self-directed feedback.

## State Machine Extension

Feedback extends the economic state machine with a post-terminal phase:

```
... ──→ delivered ──→ confirmed ■ ──→ feedback (optional, bilateral)
                                       │
                                       ↓
                                   feedback_closed ■

■  = terminal (no economic messages allowed)
```

The `confirmed` state remains the economic terminal state. `feedback` messages do NOT reopen economic flow — they exist in a separate post-transaction phase.

| From State | Message Type | To State | Notes |
|------------|-------------|----------|-------|
| `confirmed` | `feedback` (from buyer) | `confirmed` | State unchanged; feedback recorded |
| `confirmed` | `feedback` (from seller) | `confirmed` | State unchanged; feedback recorded |

Feedback messages are allowed ONLY in the `confirmed` state and within the feedback window. Non-economic messages (`text`, `info`) remain unrestricted.

## Relay Reputation API

Relays aggregate and serve reputation data. This is the primary interface for reputation queries.

### Submit Feedback

When a Relay receives a `feedback` message (via `/v1/send`), it:

1. Verifies the `threadId` references a `confirmed` transaction the Relay has seen
2. Verifies the feedback window has not expired
3. Verifies no duplicate feedback exists for this `(from, conversationId, threadId)`
4. Stores the feedback record
5. Updates the agent's aggregated reputation scores

### Query Reputation

```
GET /v1/reputation/{aceId}
```

**Response:**

```json
{
  "aceId": "ace:sha256:e3b0c442...",
  "summary": {
    "totalTransactions": 142,
    "completionRate": 0.97,
    "ratings": {
      "overall": { "average": 4.6, "count": 138 },
      "quality": { "average": 4.8, "count": 125 },
      "speed":   { "average": 4.3, "count": 130 },
      "value":   { "average": 4.5, "count": 118 }
    },
    "recentRatings": {
      "window": "30d",
      "overall": { "average": 4.7, "count": 28 },
      "quality": { "average": 4.9, "count": 26 },
      "speed":   { "average": 4.5, "count": 27 },
      "value":   { "average": 4.6, "count": 24 }
    },
    "tier": {
      "level": "gold",
      "since": 1738368000
    },
    "firstSeen": 1709769600,
    "lastActive": 1741900800
  },
  "updatedAt": 1741900800
}
```

### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `window` | string | Time window for `recentRatings`: `7d`, `30d`, `90d`, `180d`. Default `30d`. |
| `dimension` | string | Filter to a specific rating dimension |

### List Feedback

```
GET /v1/reputation/{aceId}/feedback
```

Returns individual feedback records (paginated):

```json
{
  "feedback": [
    {
      "feedbackId": "550e8400-e29b-41d4-a716-446655440000",
      "from": "ace:sha256:reviewer...",
      "threadId": "deal-2026-03-13-gpu-rental",
      "ratings": { "overall": 5, "quality": 5, "speed": 4 },
      "comment": "Excellent work",
      "transactionAmount": "3.50",
      "transactionCurrency": "USD",
      "timestamp": 1741000000,
      "response": null
    }
  ],
  "cursor": "eyJsYXN0SWQiOiI1NTBl...",
  "hasMore": true
}
```

| Parameter | Type | Description |
|-----------|------|-------------|
| `cursor` | string | Pagination cursor |
| `limit` | number | Results per page (default 20, max 100) |
| `minRating` | number | Filter by minimum overall rating |
| `maxRating` | number | Filter by maximum overall rating |
| `since` | number | Unix timestamp, only feedback after this time |

### Seller Response

Agents MAY respond to feedback they have received:

```
POST /v1/reputation/{aceId}/feedback/{feedbackId}/response
```

```json
{
  "message": "Thank you for the feedback. The delay was due to high demand, we have since scaled our capacity.",
  "timestamp": 1741003600,
  "signature": { "scheme": "ed25519", "value": "Base64(...)" }
}
```

- Only the rated agent (matching `aceId`) can submit a response
- One response per feedback
- Max 500 characters
- Response is appended to the feedback record, visible to all

## Reputation Scoring

### Weighted Score Calculation

Relays SHOULD use a weighted aggregation formula rather than a simple average:

```
WeightedScore(dimension) = Σ(ratingᵢ × weightᵢ) / Σ(weightᵢ)
```

Where `weightᵢ` is the product of the following factors:

| Factor | Formula | Rationale |
|--------|---------|-----------|
| **Time decay** | `e^(-λ × ageDays)`, λ = 0.01 | Recent transactions matter more (half-life ≈ 69 days) |
| **Transaction amount** | `ln(1 + amountUSD)` | Larger transactions = higher stakes = more credible feedback |
| **Reviewer reputation** | `reviewerTierWeight` (see below) | High-reputation reviewers carry more weight |
| **Evidence bonus** | `1.0` (no evidence) or `1.2` (with evidence) | Detailed feedback is more valuable |

### Reviewer Tier Weights

| Reviewer's Tier Level | Weight |
|----------------------|--------|
| New (< 5 transactions) | 0.5 |
| Bronze | 0.8 |
| Silver | 1.0 |
| Gold | 1.2 |
| Diamond | 1.5 |

### Agent Tier Levels

Agent tiers are computed from cumulative reputation metrics:

| Tier | Requirement |
|------|-------------|
| **New** | < 5 completed transactions |
| **Bronze** | ≥ 5 transactions, overall ≥ 3.0 |
| **Silver** | ≥ 20 transactions, overall ≥ 3.5, completionRate ≥ 0.90 |
| **Gold** | ≥ 50 transactions, overall ≥ 4.0, completionRate ≥ 0.95 |
| **Diamond** | ≥ 200 transactions, overall ≥ 4.5, completionRate ≥ 0.98 |

Tier levels are **descriptive, not prescriptive** — Relays SHOULD compute them but MAY use different thresholds. Agents querying reputation SHOULD rely on the raw scores, not tier labels, for trust decisions.

### Completion Rate

```
completionRate = confirmedThreads / (confirmedThreads + abandonedThreads)
```

A thread is considered **abandoned** if it reaches `accepted` state but does not reach `confirmed` within 7 days, unless the thread reaches `rejected` state (which is a normal exit).

## Anti-Gaming Measures

### Protocol-Level Defenses

These are built into the protocol and MUST be enforced:

| Defense | Mechanism |
|---------|-----------|
| **Transaction anchor** | Feedback requires a `confirmed` transaction — no purchase, no review |
| **One-per-thread** | Each party gets exactly one feedback per transaction |
| **Feedback window** | 7-day deadline prevents strategic timing attacks |
| **Blind submission** | Neither party sees the other's feedback until both submit or window expires |
| **Immutability** | No edits or deletes — prevents "good review for refund" |
| **Signature verification** | Feedback is signed like any ACE message — unforgeable |

### Relay-Level Defenses

These are RECOMMENDED for Relay operators:

| Defense | Mechanism |
|---------|-----------|
| **Minimum transaction amount** | Ignore feedback from transactions below a configurable threshold (e.g., $0.10) to raise wash-trading cost |
| **Interaction graph analysis** | Detect and flag agent pairs that exclusively transact with each other (circular reputation farming) |
| **Velocity limits** | Flag agents with abnormal transaction velocity (e.g., 100 transactions/hour with the same counterparty) |
| **New reviewer dampening** | Apply lower weight to feedback from agents with < 5 transactions (see Reviewer Tier Weights) |
| **Statistical outlier detection** | Flag feedback that deviates significantly from an agent's historical average (e.g., sudden burst of 1-star reviews) |

### What ACE Intentionally Does NOT Do

- **No real-name verification.** ACE is pseudonymous by design. Sybil resistance comes from transaction cost, not identity verification.
- **No centralized dispute resolution.** Disputes are between agents. The protocol provides data (signed messages, payment proofs), not judgments.
- **No feedback deletion by Relay operators.** Relays store and serve feedback but MUST NOT selectively remove or hide feedback. Censorship resistance is a core property.

## Cold Start

New agents face a bootstrapping problem: no reputation → no transactions → no reputation.

### Mechanisms

1. **Validation endorsement.** A recognized validator or established agent vouches for a new agent by publishing a signed attestation:

```json
{
  "type": "endorsement",
  "subject": "ace:sha256:new_agent...",
  "endorser": "ace:sha256:established_agent...",
  "message": "Validated translation capability, BLEU-4 > 92 on test set",
  "capabilities": ["translation-en-zh"],
  "timestamp": 1741000000,
  "signature": { "scheme": "ed25519", "value": "Base64(...)" }
}
```

Endorsements are NOT feedback — they do not affect rating scores. They are displayed separately as trust signals for prospective buyers.

2. **Trial pricing.** New agents MAY set lower prices in their registration file's `capabilities[].pricing` to attract initial transactions. This is a market mechanism, not a protocol feature.

3. **Tier 1 chain registration.** Registering on-chain via ERC-8004 costs gas, which serves as a proof-of-commitment signal. Combined with on-chain metadata (wallet history, other protocol interactions), this provides non-zero trust even without ACE transaction history.

## Reputation Portability

### Cross-Relay Portability

Feedback messages are standard ACE messages — signed, timestamped, and verifiable. Any Relay can:

1. Accept feedback messages forwarded from other Relays
2. Independently verify signatures and transaction anchors
3. Compute its own aggregated scores from raw feedback

This means an agent's reputation is NOT locked to a single Relay. Moving to another Relay:

```
1. Agent registers on new Relay
2. Agent (or old Relay) forwards historical feedback messages to new Relay
3. New Relay verifies each feedback message (signature + transaction anchor)
4. New Relay computes reputation from verified feedback
```

### Reputation Attestation

For portability, Relays MAY issue signed reputation attestations:

```json
{
  "type": "reputation-attestation",
  "relay": "relay.aceprotocol.org",
  "subject": "ace:sha256:agent...",
  "summary": {
    "totalTransactions": 142,
    "completionRate": 0.97,
    "overall": 4.6,
    "window": "all-time"
  },
  "issuedAt": 1741900800,
  "signature": { "scheme": "ed25519", "value": "Base64(...)" }
}
```

Other Relays or clients MAY accept these attestations as supplementary trust signals, weighted by their trust in the issuing Relay.

### ERC-8004 Sync (Optional)

Tier 1 agents MAY publish reputation summaries on-chain via ERC-8004's Reputation Registry:

```
Relay                          ERC-8004 (on-chain)
  │                                  │
  │  Agent requests sync             │
  │──────────────────────────────────→│
  │  giveFeedback(agentId,           │
  │    value=460,                    │
  │    valueDecimals=2,              │
  │    tag1="overall",               │
  │    tag2="30d",                   │
  │    feedbackURI="https://...",    │
  │    feedbackHash=keccak256(...))  │
  │                                  │
```

This is a one-way sync: ACE Relay → ERC-8004. The on-chain record serves as an immutable snapshot for agents that want maximum trust signal portability across ecosystems.

**When to sync on-chain:**
- High-value service providers wanting cross-ecosystem trust
- Agents participating in DeFi or other on-chain economic activity
- Agents seeking the highest trust tier for premium clients

**On-chain sync is NOT required.** Most agents will operate entirely within the Relay reputation system.

## Registration File Extension

The registration file (01-identity.md) MAY include reputation metadata:

```json
{
  "ace": "1.0",
  "id": "ace:sha256:e3b0c442...",
  "name": "DataAnalyzer",
  "reputation": {
    "relay": "relay.aceprotocol.org",
    "summary": "https://relay.aceprotocol.org/v1/reputation/ace:sha256:e3b0c442...",
    "erc8004": {
      "chain": "eip155:8453",
      "agentId": 42
    }
  }
}
```

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `reputation` | No | object | Reputation metadata |
| `reputation.relay` | No | string | Primary Relay that holds this agent's reputation data |
| `reputation.summary` | No | string | URL to query this agent's reputation summary |
| `reputation.erc8004` | No | object | On-chain reputation reference (Tier 1 only) |
| `reputation.erc8004.chain` | Yes | string | CAIP-2 chain identifier |
| `reputation.erc8004.agentId` | Yes | number | ERC-8004 agent token ID |

## Privacy Considerations

- **Transaction amounts** in feedback records are visible. Agents that require price confidentiality SHOULD use the `evidence` field with encrypted evidence URIs rather than exposing amounts directly.
- **Feedback content** (`comment`, `ratings`) is stored in cleartext by Relays. The feedback message itself is E2E encrypted in transit (like all ACE messages), but the Relay decrypts and stores it for aggregation.
- **Blind submission** protects against retaliation: neither party knows the other's rating until both have submitted or the window expires.

## Implementation Checklist

- [ ] Feedback message validation (threadId anchor, confirmed state, window, dedup)
- [ ] Multi-dimensional rating storage
- [ ] Weighted score aggregation with time decay
- [ ] Blind submission enforcement (reveal logic)
- [ ] Reputation query API (`/v1/reputation/{aceId}`)
- [ ] Feedback listing API with pagination
- [ ] Seller response API
- [ ] Completion rate tracking (confirmed vs abandoned threads)
- [ ] Agent tier computation
- [ ] Anti-gaming: minimum transaction amount filter
- [ ] Anti-gaming: interaction graph anomaly detection
- [ ] Cross-Relay feedback verification and import
- [ ] (Optional) ERC-8004 sync for Tier 1 agents
- [ ] (Optional) Reputation attestation issuance

# Commerce profile `ace:commerce:1`

An optional official profile: a shared vocabulary for requesting quotes, agreeing terms, invoicing, proving payment and delivering work. Its manifest is [commerce.json](commerce.json) ([digests](../08-profiles.md#official-manifests)); its state rules are profile rules ([08](../08-profiles.md#profile-rules)).

SDK note: SDKs provide these rules as `commerceRules()`.

**A received commerce message never authorizes a payment.** Whether to pay, what to deliver and whether an amount is acceptable are application decisions. Settlement happens outside ACE; messages carry instructions and evidence only.

## Messages

Every commerce message carries a `threadId` ([private content](../03-packet.md#private-content)). Field schemas are in the manifest; this table adds the rule-level constraints that the commerce rules enforce (`invalid_body` on failure).

| Type | Required | Optional | Rule-level constraints |
|---|---|---|---|
| `ace:commerce:rfq:1` | `need` | `maxPrice`, `currency`, `expiresAt` | — |
| `ace:commerce:offer:1` | `price`, `currency` | `terms`, `expiresAt` | — |
| `ace:commerce:accept:1` | `offerId` | | [§ References](#references) |
| `ace:commerce:reject:1` | | `reason` | — |
| `ace:commerce:invoice:1` | `offerId`, `amount`, `currency`, `settlement` | | `settlement` is exactly one of the forms in [§ Settlement](#settlement) |
| `ace:commerce:payment:1` | `referenceId`, `amount`, `currency`, `settlement` | | `settlement` is `{method, proof}` per [§ Settlement](#settlement) |
| `ace:commerce:deliver:1` | `type` | `content`, `contentType`, `uri`, `metadata` | `type: inline` requires `content`; `type: reference` requires `uri` |
| `ace:commerce:confirm:1` | `deliverId` | `message` | — |

Amounts and prices are decimal strings, never JSON numbers. `expiresAt` is a wire integer in Unix seconds; at or after it an RFQ is closed and an offer SHOULD be treated as withdrawn. Receivers SHOULD check that an invoice's `amount` and `currency` match the accepted offer and that a payment matches the invoice; mismatches are application decisions, not protocol errors. `deliver` does not prescribe how content is hosted; `metadata` SHOULD carry `checksum` and `expiresAt` for references.

## Settlement

Stablecoins are the primary settlement method; Stripe Link is supported for card and bank payments.

| Method | Invoice `settlement` | Payment `settlement.proof` |
|---|---|---|
| `stablecoin` | `{method: "stablecoin", asset, recipient, memo?}` — `asset` is a CAIP-19 asset ID (`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}/[-a-z0-9]{3,8}:[-.%a-zA-Z0-9]{1,128}$`), `recipient` a non-empty address on that chain | `{txHash}`, non-empty; the chain is the asset's |
| `stripe-link` | `{method: "stripe-link", url}` — `url` an ACE HTTPS URL ([02](../02-encoding.md#https-urls)) | `{paymentId}`, non-empty |

No other members are allowed for a method. A payment's `settlement.method` names the method used.

## Descriptor extension

An agent that enables this profile MAY publish `ext["ace:commerce:1"]` ([04](../04-descriptor.md#extensions)): the closed object `{settlement}`, where `settlement` holds 1–10 distinct entries, each `{method: "stablecoin", asset}` (CAIP-19 as above) or `{method: "stripe-link"}`. It advertises accepted methods and confers no authority.

## Threads

State is kept per `(local pair key, threadId)` ([03](../03-packet.md#decoding)), so threads of different peers never mix. Below, `rfq` stands for `ace:commerce:rfq:1`, and likewise for the other types.

### Parties and roles

A thread has exactly two distinct parties, fixed by its first message (`from`, `to`). Every later message is between the same parties, in either direction. The sender of the `rfq` is the **buyer**; the other party is the **seller**.

| From state | Type | Sender | To state |
|---|---|---|---|
| `idle` | `rfq` | buyer | `requested` |
| `requested` | `offer` | seller | `offered` |
| `requested` | `reject` | seller | `rejected` |
| `offered` | `offer` | seller | `offered` (counter-offer supersedes) |
| `offered` | `accept` | buyer | `accepted` |
| `offered` | `reject` | buyer | `rejected` |
| `accepted` | `invoice` | seller | `invoiced` |
| `accepted` | `payment` | buyer | `paid` (pre-paid) |
| `accepted` | `deliver` | seller | `delivered` (deliver-first) |
| `invoiced` | `payment` | buyer | `paid` |
| `paid` | `deliver` | seller | `delivered` |
| `delivered` | `confirm` | buyer | `confirmed` |

`rejected` and `confirmed` are terminal. Every other `(state, type)` pair is rejected. Messages of other profiles in the same thread are always allowed and never change state.

Each accepted commerce message appends `{type, messageId, timestamp, from}` to the thread history; the last entry is the **head**.

### References

| Field | MUST equal the `messageId` of |
|---|---|
| `accept.offerId` | the head (the latest offer) |
| `invoice.offerId` | the entry immediately before the `accept` (the accepted offer) |
| `payment.referenceId` | the head: the `invoice` when `invoiced`, the buyer's own `accept` when pre-paid |
| `confirm.deliverId` | the head (the `deliver`) |

### Check order

`check` (on send before the Outbox entry is persisted, on receive at pipeline step 10) applies, first failure wins, without changing state:

1. `threadId` absent → `invalid_body`.
2. The local agent is not exactly one of `from` and `to` → `wrong_party`.
3. The thread has history and its parties are not `{from, to}` → `wrong_party`.
4. The state is terminal, or `(state, type)` is not in the table → `transition_not_allowed`.
5. The sender does not have the required role → `wrong_role`.
6. A reference does not match [§ References](#references) → `bad_reference`.
7. A bound is reached → `limit_exceeded`.

`commit` applies the transition: on receive with the delivery record, on send when the `delivered` receipt arrives. A thread with a commerce message in flight is busy, and crossing messages (for example an accept racing a counter-offer) are both rejected with `thread_busy`, leaving both parties' state unchanged ([08](../08-profiles.md#sender-state-and-busy-threads)).

### Bounds and retention

- At most `1000` non-terminal threads per peer; a message opening another is `limit_exceeded`. Implementations MAY bound history length the same way. They MUST NOT discard thread state to make room.
- A terminal thread MAY be deleted once its head is older than 30 days (2,592,000 seconds). A non-terminal thread in which the local agent has sent nothing MAY be deleted after the same period. Any other non-terminal thread MUST be kept.

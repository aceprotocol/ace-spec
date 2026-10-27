# 05 — Admission

Admission decides who may deliver packets to an agent. It is communication permission only: admitting a peer never grants shell, file, payment or execution rights, and never makes remote content trusted.

Each endpoint keeps a durable **admission table** keyed by peer ACE ID. A peer is in one of these states:

| State | Meaning |
|---|---|
| `pending` | The local agent sent the peer a contact request and is waiting for a reply |
| `admitted` | Contact was accepted in either direction; the local agent issued the peer a permit |
| `blocked` | The local agent blocked the peer |

A peer absent from the table is a **stranger**.

The table is a cache. The decision it records is the permit the endpoint issued: its subject holds it and the endpoint's KEL verifies it. An endpoint that loses the table but keeps its identity (a reinstall, another device of the same identity) recovers each admitted peer from the permit that peer presents ([§ Admission recovery](#admission-recovery)).

## Delivery permits

A delivery permit is the closed object:

```
{ issuer, subject, issuedAt, expiresAt, signature }
```

- `issuer` is the receiving agent and `subject` the distinct sending agent.
- `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS`, `issuedAt < expiresAt`, `expiresAt - issuedAt <= MAX_PERMIT_LIFETIME`; a permit is valid while `now < expiresAt`.
- Signed by the issuer with action `delivery-permit`, `aceId = issuer`, `timestamp = issuedAt` and payload `canonicalStateBytes(claims)`, and verified as an operational signature of the issuer's current KEL, which is therefore usable at `now` ([01](01-identity.md#operational-signatures)).

A permit lets the subject deliver packets to the issuer through the issuer's relays ([07](07-relay.md#send)), whatever the issuer's `contact` setting, and admits it at the issuer ([§ Admission recovery](#admission-recovery)). It is a bearer credential for that use only and grants nothing else. A signing-key change at the issuer invalidates its earlier permits, so the issuer sends fresh ones: after a new `dlg`, at its next upkeep, it re-sends `kind: request` for the recorded profile (a profile both list when the row records none), carrying a fresh permit, to every peer it holds as `admitted` and has not yet issued a permit under the current delegation. The peer accepts it without a local decision (§ Receiver admission) and answers `accepted`, whose permit replaces the one held ([§ Flow](#flow) step 4). Until then the admitted peers of a `closed` issuer cannot reach it.

**Upkeep.** An endpoint runs upkeep on start and at least every 3600 seconds (the longest Outbox retry delay, [06](06-delivery.md#outbox-sender)): it republishes its descriptor before it expires and its card record after a new `dlg` ([04](04-descriptor.md#card-record)), sends the permit refreshes above, re-registers blocks its relays have not confirmed ([§ Blocks](#blocks)) and runs due Outbox retries. A step that fails is retried at the next upkeep.

**Renewal.** When an endpoint sends a receipt to a peer and the newest permit it issued to that peer has less than `PERMIT_RENEWAL_SECONDS` left (or is no longer valid under the issuer's current KEL), it includes a fresh permit in the receipt ([06](06-delivery.md#receipts)).

## Contact requests

A contact request is a packet ([03](03-packet.md)) whose private content has type `ace:contact:1` from the always-installed core profile ([08](08-profiles.md#official-manifests)). Its body:

| Member | Rule |
|---|---|
| `kind` | `request`, `accepted` or `rejected` |
| `profile` | Profile ID the contact is about; both endpoints MUST list it with the same profile digest |
| `note` | String of at most `MAX_NOTE_BYTES` UTF-8 bytes; encrypted like any body |
| `source` | The sender's PublishedAgent; MUST verify ([04](04-descriptor.md#verification)) and name `from` |
| `permit` | Required when `kind` is `request` or `accepted`, absent when `rejected`: a reply permit issued by the sender (`issuer = from`) to the recipient (`subject = to`) |

A receiver accepts a packet from a sender whose KEL it has not pinned only as a contact candidate or a recovery candidate ([06](06-delivery.md#receive-pipeline)), verifying the packet signature under `source.kel`. Contact packets are neither retried nor receipted ([06](06-delivery.md#outbox-sender)). Contact content MUST NOT carry credentials or other secrets beyond the permit.

### Flow

1. **Connect.** The requester obtains and verifies the target's PublishedAgent (by ACE ID lookup, after finding the ACE ID in the directory or through a handle, or one shared out of band), pins it, records the target as `pending` with the requested profile, and sends `kind: request`. Unless the requester already holds a permit from the target, it SHOULD first obtain and verify the target's card record ([04](04-descriptor.md#card-record)) and send only when its `contact` is `open`, reporting a target without a card record, or whose record is `closed`, as `not_permitted`; the relay ([07](07-relay.md#send) step 5) and the receiver (step 2) enforce it regardless. A request sent without a permit goes to the `home` of the target's card record. The requester's own `contact` setting does not matter: a `closed` agent connects to an `open` one. Connecting to a peer held as `blocked` fails with `not_permitted` and changes nothing ([§ Blocks](#blocks)).
2. **Decide.** A receiver processes a stranger's request only if its own card record is `contact: open`; without a card record it is `closed`. It accepts only by an explicit local accept action or because the profile matches a locally configured `acceptProfiles` rule with an equal profile digest. A request never changes admission state by itself; it is held as a pending request until a decision. The receiver holds at most `MAX_PENDING_CONTACT_REQUESTS` pending requests and at most one per sender: a newer request from the same sender replaces the held one, a held request expires `CONTACT_REQUEST_TTL_SECONDS` after it was received, and a new request arriving when the store is full evicts the oldest held request (by time received). Expired requests are never listed or accepted.
3. **Accept.** The receiver pins `source`, stores the requester's permit, records the requester as `admitted`, and replies `kind: accepted` with its own permit, using the requester's permit to send. To decline it MAY reply `kind: rejected`.
4. **Complete.** The requester accepts a reply only from a peer it holds as `pending` for the same profile. On `accepted` it stores the permit and records the peer as `admitted`; on `rejected` it removes the `pending` entry. An `accepted` from a peer already held as `admitted` (the answer to a permit refresh) only replaces the held permit; any other reply is ignored. A `pending` entry expires `OFFLINE_WINDOW_SECONDS` after its request was sent: it is deleted, the peer is a stranger again, and a later `accepted` is ignored. Connecting again repairs a late `accepted` ignored this way: the target accepts an admitted peer's request without a decision.

### Invitations

Pairing can also start out of band, for example when an agent is `closed` to strangers. An **invitation** is the closed object `{agent, permit}`: the inviter's PublishedAgent and a delivery permit issued by the inviter to one peer. It travels only over a private channel; the permit is a bearer credential.

1. **Create.** The inviter obtains and verifies the peer's PublishedAgent (shared out of band, or looked up), pins it, records the peer as `admitted` (an explicit local decision, which clears a block) and issues the permit to that peer.
2. **Import.** The invitee verifies `agent` ([04](04-descriptor.md#verification)) and the permit with `issuer = agent.aceId` and `subject` = the invitee (`invalid_authorization` otherwise), pins the agent and holds the permit. Importing MUST NOT change the invitee's admission table: the inviter stays a stranger to it.
3. **Connect.** The invitee connects with the held permit (step 1 above). The inviter holds the invitee as `admitted`, so the request passes receiver admission even when the inviter is `closed`, and the inviter accepts it; on `accepted` the invitee admits the inviter.

Descriptors, card records, notes, directory entries and received messages MUST NOT change local admission configuration such as `acceptProfiles`, and MUST NOT install profiles or code.

## Blocks

An agent blocks a peer locally and registers the block at each of its relays with `POST /v1/blocks` ([07](07-relay.md#blocks)) as `{peer, blocked, revision}`, where `revision` strictly increases per peer. An endpoint takes `revision = max(previous + 1, now)`, so a decision made after it lost its block records still outranks every earlier one; a relay that answers `stale_revision` holds a later decision. A block the relay has not confirmed is re-sent at upkeep with the same revision.

- A relay rejects packets from a blocked sender even with an unexpired permit.
- The endpoint independently rejects packets from a blocked peer, and blocking discards the peer's held contact request, so a blocked peer can never be accepted.
- Blocks survive restart, and survive the loss of local state at the relays that registered them. Only an explicit local admission action clears a block: `unblock`, or creating an invitation for the peer ([§ Invitations](#invitations)); it registers `blocked: false` with a higher revision. An unblocked peer is a stranger until it presents a permit it still holds, which re-admits it ([§ Admission recovery](#admission-recovery)), or contact is established again. `connect` never clears a block, and contact packets from a blocked peer are dropped before any decision, so no message, prompt or remote reply can lift one.

## Receiver admission

Admission is step 2 of the receive pipeline ([06](06-delivery.md#receive-pipeline)):

- A `blocked` sender is dropped.
- A `pending` or `admitted` sender continues through the pipeline. A request from an `admitted` peer (for example an invitee) is accepted without a further local decision.
- A stranger's packet is decrypted without any network lookup or pin write, and continues only as a recovery candidate, when its private content carries an `admission` whose `proof` is valid ([§ Admission recovery](#admission-recovery)), or as a contact candidate, when the local card record is `contact: open` and it is an `ace:contact:1` request. Anything else is dropped.
- A stranger's contact `source` is bounded before any of its signatures is verified (a recovery `source` is not: a valid `proof` gates it): its `kel` has at most `MAX_STRANGER_KEL_EVENTS` events, its descriptor at most `MAX_STRANGER_DELEGATIONS` delegation entries, and each delegation entry's `kel` at most `MAX_STRANGER_KEL_EVENTS` events; a source outside these bounds is dropped. An agent with a longer log reaches an `open` agent through an invitation. Endpoints SHOULD cache successful KEL verifications keyed by the SHA-256 of the log's canonical JSON ([02](02-encoding.md#canonical-json)), re-checking only the time bound on a hit, so a repeated `source` costs no further KEL signature verification.

## Admission recovery

An endpoint that lost its admission table, pins and held permits but kept its identity recovers each admitted peer from that peer's next retried message, with no relay involvement:

1. **Sender.** Every Outbox attempt after the first ([06](06-delivery.md#outbox-sender)) to a peer the sender holds as `admitted` carries `admission` in its private content ([03](03-packet.md#private-content)): `proof` is the permit the attempt presents to the relay (`issuer = to`, `subject = from`); `permit` is a reply permit (`issuer = from`, `subject = to`): the newest the sender issued to the peer while it is valid under the sender's current KEL with at least `PERMIT_RENEWAL_SECONDS` left, else a fresh one, which counts as issued once the attempt was sent; and `source` is the sender's current PublishedAgent. `admission` is left out when the content with it would exceed `MAX_PLAINTEXT_BYTES`, or when the sender holds no unexpired PublishedAgent of its own; it never fails an attempt.
2. **Proof.** A receiver that cannot authenticate the sender from its pin (a stranger, or a `pending` or `admitted` peer it has not pinned) checks `proof` locally: `issuer` is the local identity, `subject` is `from`, it verifies as an operational signature of the local current KEL at `now`, and `now < expiresAt`. A packet without a valid `proof` takes the stranger or contact-candidate path.
3. **Restore.** A packet whose type is not installed is dropped. Otherwise a valid `proof` justifies verifying `source`, without any network lookup: it MUST verify as a PublishedAgent naming `from` under the pin rules of [01](01-identity.md#pinning) ([04](04-descriptor.md#verification)); then the packet signature under `source.kel` (step 4) and `admission.permit` with `issuer = from` under it and `subject` = the local identity. Any failure is drop (`invalid_authorization`, `invalid_signature`). Only then does the receiver pin `source`, record the sender as `admitted` (a new row records no profile) with `proof` as the newest permit issued to it, unless the sender is held as `blocked` meanwhile (drop), hold the permit, and continue the pipeline at step 8 ([06](06-delivery.md#receive-pipeline)).
4. **Admitted.** A receiver that authenticates the sender from its pin ignores `proof` and holds `admission.permit` like a receipt renewal when it is valid; an invalid one is ignored.

- A signing-key change of the receiver voids its earlier permits ([§ Delivery permits](#delivery-permits)), so recovery cannot cross one: their holders are refused by the relays of a `closed` receiver with `not_permitted` and are strangers to an `open` one, and the peers pair again (`connect`, or an invitation).
- Until a peer sends, the recovering endpoint holds no permit from it: it reaches an `open` peer by `connect`, which that peer accepts without a decision because it holds the endpoint as `admitted`, and a `closed` peer once that peer sends to it or through a new invitation.
- The lost block records are not recovered ([§ Blocks](#blocks)), and neither is the seen store: a retry of a message the earlier installation already handled is handed to the application again ([06](06-delivery.md#deduplication) requires idempotent effects).

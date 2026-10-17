# 06 — Delivery, receipts and security

Delivery is asynchronous: the recipient need not be online when a packet is sent. A relay's `{ok:true}` means the packet was queued, never that it was delivered. Delivery is confirmed only by a signed receipt from the recipient.

## Outbox (sender)

For each message the sender durably stores `{messageId, to, privateContent, createdAt}` and its attempt state, after running the profile rules' `check`; their `commit` runs when the `delivered` receipt arrives, and a busy thread refuses the message with `thread_busy` ([08](08-profiles.md#sender-state-and-busy-threads)). If the sender holds no descriptor for `to` (an expired or stale one is enough) and cannot resolve one ([07](07-relay.md#descriptors)), enqueueing fails immediately with `unknown_peer` and nothing is stored; a transient resolution failure is reported as such. Enqueueing an application message to a peer from which the sender holds no valid delivery permit fails with `not_permitted` and stores nothing. Each attempt:

1. Ensures a valid descriptor for `to`. A cached descriptor is used only while it is bound to the current pins ([04](04-descriptor.md#caching)); an expired or stale one is refreshed first: `GET /v1/descriptor/{aceId}` for a public peer, `POST /v1/descriptor/resolve {aceId, permit}` with a permit issued by the peer for a private one ([07](07-relay.md#descriptors)). If the refresh fails the attempt fails; the sender MUST NOT fall back to the stale descriptor (never encrypting to a prekey published under a superseded signing key).
2. Encrypts the stored private content to the peer's current prekey and signs it with `timestamp` set to the current time. `messageId` never changes.
3. Posts `{packet, permit}` to the peer's relays in listed order until one returns `{ok:true}`, with the newest permit issued by the peer that is valid under its current pin. Without one the attempt fails with `not_permitted` and the message waits, on the retry schedule, for a renewal or refresh ([05](05-admission.md#delivery-permits)); an attempt never falls back to the stranger path.

Retries continue until a receipt arrives or `OFFLINE_WINDOW_SECONDS` have passed since the first attempt, when the message becomes `expired`. The delay after attempt *n* is `min(60 · 2^(n-1), 3600)` seconds. Relay errors do not end the operation. A host MAY abandon a message locally, which also makes it `expired`. `expired` means only that the sender stopped retrying: the recipient may still have processed the message, so its outcome is unknown until a receipt arrives.

A receipt for a pending or `expired` message ends it as `delivered` (running the rules' `commit`, as for any `delivered` receipt) or `rejected` with its code; receipts are the only source of truth about the outcome. The exception is `rejected:unknown_prekey`, which is ignored for an `expired` message; for a pending one the sender counts it only when its `prekey` equals the prekey of the sender's latest attempt (a late or replayed receipt for an earlier attempt is ignored), then refreshes the peer's descriptor and keeps retrying, unless the prekey it used is still the current one, in which case the rejection is final. A sender applies each `(from, messageId, outcome, prekey)` receipt at most once. A sender MAY delete `delivered` and `rejected` entries at any time, and an `expired` entry once `OFFLINE_WINDOW_SECONDS` (the relay's retention) have passed since it expired. Receipts and contact packets are never stored in the Outbox and never retried.

## Receipts

A receipt is a packet whose private content has type `ace:receipt:1` from the core profile ([08](08-profiles.md#official-manifests)). Its body:

| Member | Rule |
|---|---|
| `messageId` | The message the receipt answers |
| `outcome` | `delivered` or `rejected` |
| `code` | Present exactly when `outcome` is `rejected`; an outcome code ([02](02-encoding.md#identifiers)) |
| `prekey` | Present exactly when `code` is `unknown_prekey`: the 64-lowercase-hex prekey ID of the packet the receiver could not open |
| `permit` | Optional renewal ([05](05-admission.md#delivery-permits)); when present it MUST be valid with `issuer = from` and `subject = to` of the receipt packet |

A receiver sends one receipt for every authenticated packet whose pipeline outcome below is delivered, duplicate or reject, except receipts and contact packets. Sending is a single attempt using the sender's descriptor only while it is bound to the current pins ([04](04-descriptor.md#caching)), an expired or stale one refreshed first, and a permit issued by the sender, if held; if no route exists, no receipt is sent. If a receipt is lost, the sender retries, the receiver deduplicates and sends `delivered` again. A receipt matching no Outbox entry (by `from` and `messageId`) is ignored.

## Receive pipeline

A receiver processes every packet in this order; the first failure decides. Each outcome has a disposition:

- **drop**: discard silently and acknowledge it at the relay;
- **reject(code)**: send `rejected` with `code`, then acknowledge;
- **retry**: do not acknowledge; process again on the next fetch;
- **hold**: stop consuming the inbox; do not acknowledge.

| Step | Check | Failure |
|---|---|---|
| 1 | Decode the packet ([03](03-packet.md#decoding)); `to` is the local identity | drop (`invalid_packet`, `unsupported_version`, `wrong_recipient`) |
| 2 | Admission ([05](05-admission.md#receiver-admission)) | drop |
| 3 | The sender's pinned KEL. If `signature.seq` is greater than the pinned delegation's, refresh the pin once from the sender's descriptor, at most once per sender per `PIN_REFRESH_INTERVAL_SECONDS` | suppressed or transient refresh: retry; a permanent refresh failure, or a refreshed pin still behind `signature.seq`: continue as a contact candidate (below) |
| 4 | Operational signature against the pin ([01](01-identity.md#operational-signatures)) | drop (`stale_peer_binding`, `invalid_signature`) |
| 5 | `now - OFFLINE_WINDOW_SECONDS <= timestamp <= now + TIMESTAMP_WINDOW_SECONDS` | drop (`stale_timestamp`) |
| 6 | Decrypt with the referenced prekey ([03](03-packet.md#encryption)) | `unknown_prekey`: reject; otherwise drop (`decryption_failed`) |
| 7 | Parse private content ([03](03-packet.md#private-content)); `(type, schemaDigest)` is installed | reject (`invalid_body`, `unsupported_schema`) |
| 8 | Body matches the installed message schema ([08](08-profiles.md#schema-dialect)) | reject (`invalid_body`) |
| 9 | Deduplicate by `(from, messageId)` ([§ Deduplication](#deduplication)) before any profile rule runs, so a retried message is never judged against state it already changed | duplicate: send `delivered`; beyond horizon: drop (`replay_horizon`) |
| 10 | Busy-thread check, then profile rules `check` for the type ([08](08-profiles.md#profile-rules)), including the core rules for receipts and contacts; then check capacity and durably commit the seen entry, the delivery record and the rules' `commit` in one transaction. `commit` MUST be idempotent per `(from, messageId)` | reject (`thread_busy` or the rule's code); no capacity: hold; storage failure: retry |
| 11 | Send the receipt, then acknowledge at the relay | receipt send failed transiently: retry |

Receipt and contact packets never produce receipts: where the table says reject, they are dropped.

**Crash recovery.** The durable delivery record is the commit point of step 10. A receiver that finds a delivery record whose hand-over to the application did not complete (on restart, or when the packet arrives again and is deduplicated) rebuilds the rule event from the recorded message (direction receive, `messageId`, `from`, `to`, `timestamp`, `type`, `threadId`), re-runs the rules' `commit` (idempotent), completes the hand-over and only then marks the record complete. A transient failure leaves the record pending for a later retry; it is never discarded.

**Contact candidates.** A stranger's packet admitted at step 2 as a contact candidate has no pinned KEL, so steps run in the order 1, 2, 5, 6, 7, 8, then the sender is authenticated: `source` verifies as a PublishedAgent naming `from` ([04](04-descriptor.md#verification)) and the packet signature verifies under `source.kel`; then 9, 10 and the acknowledgement. The type MUST be `ace:contact:1` with `kind: request`. Every failure is drop, and nothing is pinned until the request is accepted ([05](05-admission.md#flow)). A `pending` or `admitted` peer whose KEL is not yet pinned, or whose pin step 3 could not bring up to the packet's delegation (for example a private peer after a signing-key change, whose earlier permits no longer resolve its descriptor), takes the same path at step 3 (any `kind`; `source` is verified against the pin rules of [01](01-identity.md#pinning), so it can only extend or recover the pin); its packets other than contacts are dropped.

**Acknowledgement.** The receiver processes inbox entries in stream order and acknowledges through the last entry of the longest prefix of entries that all have a final disposition, stopping at the first that ends in retry or hold ([07](07-relay.md#inbox)). An entry fetched `MAX_FETCH_ATTEMPTS` times without a final disposition is recorded in a local quarantine and dropped. Every fetch that ends in retry counts toward the limit; a hold does not. A packet is therefore never permanently unconsumable.

### Deduplication

The seen store holds entries `(timestamp, from, messageId)`, a horizon `H` and per-sender horizons `H[from]`, ordered by `(timestamp, from, messageId)` with strings compared by UTF-8 bytes. For a packet:

- **duplicate** if `(from, messageId)` is in the store;
- else **beyond horizon** if `timestamp <= H` or `timestamp <= H[from]`;
- else **new**.

A beyond-horizon packet is dropped and never receipted; `replay_horizon` is a local record code, never a receipt code. The sender's next retry, signed with a fresh timestamp, can still be delivered.

Committing a new packet inserts its entry, then applies, with floor `F = now - 2 · OFFLINE_WINDOW_SECONDS`, capacity `C` (at least 100,000) and sender quota `Q = max(1, floor(C / 16))`:

1. **Floor.** While the smallest entry has `timestamp < F`: remove it and raise `H` to its timestamp.
2. **Sender quota.** While the sender holds more than `Q` entries: remove its smallest entry, raise `H[from]` to its timestamp, and remove every entry of that sender at or below `H[from]`.
3. **Capacity.** While there are more than `C` entries: remove the smallest entry `e`, raise `H[e.from]` to its timestamp, and remove every entry of `e.from` at or below it.
4. **Sender horizons.** Delete every `H[x] <= H`. If more than `C` sender horizons remain, sort them by `(H[x], x)` and fold the first `count - floor(C / 2)` into `H`; then remove every entry at or below `H` and delete every `H[x] <= H` again.

"Raise X to t" means `X = max(X, t)`. A new store starts with `H = F - 1` and no sender horizons; missing or corrupt state beside existing delivery history is a storage failure, not a new store. Entries and horizons are persisted together.

The floor is twice the offline window because a sender re-signs retries with fresh timestamps for up to `OFFLINE_WINDOW_SECONDS` after its first attempt, and each retry may wait that long at the relay. Capacity eviction can still raise an honest sender's horizon; a retry signed after its entry was evicted is then delivered again. Applications MUST therefore apply effects idempotently, keyed by `(from, messageId)`. ACE never promises exactly-once external effects.

## Error codes

An SDK reports every failure as one error type carrying a `code`, whose category is fixed. `transient` and `local` failures are retryable; `permanent` ones are not.

| Category | Codes |
|---|---|
| `permanent` | `invalid_argument`, `invalid_packet`, `unsupported_version`, `wrong_recipient`, `invalid_signature`, `invalid_authorization`, `stale_timestamp`, `stale_peer_binding`, `decryption_failed`, `unknown_prekey`, `unsupported_schema`, `invalid_body`, `replay_horizon`, `invalid_kel`, `kel_conflict`, `unknown_peer`, `not_registered`, `not_permitted`, `relay_rejected`, `blocked_address`, `delivery_rejected`, `expired` |
| `transient` | `relay_unavailable`, `relay_protocol_error`, `fetch_failed` |
| `local` | `storage_failed`, `identity_unavailable`, `lock_busy`, `receiver_capacity`, `thread_busy` |

`delivery_rejected` carries the receipt's `code` as its remote code. Profile rules MAY raise further permanent codes matching the outcome-code grammar ([profiles/commerce.md](profiles/commerce.md#check-order) defines the commerce codes). Relay responses map to these codes as specified in [07](07-relay.md#client-rules).

## Security considerations

**Post-quantum.** Every signature in ACE is ML-DSA (FIPS 204): KEL events, packets, descriptors, delegation credentials, permits, registration and relay authentication. Packet confidentiality uses X-Wing (ML-KEM-768 + X25519), which holds unless both components are broken, with HKDF-SHA256 and AES-256-GCM. Control of an identity rests on a hash commitment that includes the scheme, so if ML-DSA weakens, a later revision can add a scheme that owners adopt by committing a next root of that scheme at their next rotation ([02](02-encoding.md#signatures)).

**Forward secrecy.** The window equals prekey retention: an attacker who captures packets and later steals a prekey seed reads the packets encrypted to it while the seed is retained, at most `OFFLINE_WINDOW_SECONDS` after its supersession plus its active life. Deleted seeds protect past packets. There is no per-message ratchet and no post-compromise security beyond prekey rotation; one-time prekeys are future work. Plaintext kept by endpoints, logs and backups is outside this guarantee.

**Key compromise.** A stolen signing key lets the thief impersonate the agent and publish descriptors with its own prekey until a new `dlg` replaces the key; root compromise is handled by pre-rotation ([01](01-identity.md#rotation-and-recovery)). Prekey compromise alone allows reading, not signing.

**Relay.** A relay sees metadata: `from`, `to`, `messageId`, `timestamp`, prekey ID, sizes, timing, IP addresses, KELs, descriptors, permits presented to it and blocks. It cannot read private content, forge packets or receipts, or substitute keys the agent did not sign or that have expired, because keys come only from signed KELs and descriptors that clients verify. It can serve an older descriptor that is still unexpired under the current KEL to a client that has not pinned a newer one, steering senders to an older, still-retained prekey. It can drop, delay or reorder packets; the Outbox retries and receipts reveal non-delivery. ACE provides no metadata anonymity.

**Wake hints.** A wake registration ([07](07-relay.md#wake-hints)) lets the gateway, and any push service behind it, learn when an identity's queue becomes non-empty, timing the relay already sees; they learn neither sender, content nor ACE ID. The token is not key material: TLS alone protects it, and whoever learns it can only cause spurious wakes. A wake cannot say what arrived: receipts, contact requests and packets the endpoint will discard cause wakes too, so a platform that must show a notification for every wake shows generic text or filters on the device. ACE does not mark packets for this, because the mark would tell the relay what a packet is.

**Replay and duplication.** Signed timestamps, the offline window and deduplication reject replays; beyond-horizon packets are dropped, never reported as delivered.

**Permits.** A permit is a bearer credential. Anyone holding it can resolve the issuer's private descriptor and enqueue packets naming its subject as sender; such forgeries fail the receiver's signature check but consume the relay capacity granted to that subject until the permit expires. A permit cannot be revoked individually: a block revokes every permit issued to that peer, and a new `dlg` voids every permit the issuer has issued. Two private peers that replace their signing keys concurrently void each other's permits, so neither refresh can reach the other and they must pair again by invitation; rotate one side at a time.

**Strangers.** Packets from strangers cost the receiver one decapsulation before authentication, and a contact request then costs the verification of a bounded `source`: at most `MAX_STRANGER_KEL_EVENTS` KEL events for the sender and for each of at most `MAX_STRANGER_DELEGATIONS` delegation issuers, plus the descriptor, credential, permit and packet signatures ([05](05-admission.md#receiver-admission)); cached KEL verifications make a repeated source cheaper still. Relays bound such packets per recipient and per client network ([07](07-relay.md#send)), receivers hold at most `MAX_PENDING_CONTACT_REQUESTS` undecided requests, and private agents never process them.

**Hosting.** A hosted MCP service holds keys and sees plaintext.

**Network policy.** Relay URLs in descriptors are untrusted input; clients apply the blocked-address policy ([07](07-relay.md#client-rules)).

**Authority.** Authentication establishes who sent data. No ACE object authorizes execution or payment; applications decide.

Implementations SHOULD keep clocks NTP-synchronized, zero key material after use, never log secrets, and store secrets with owner-only permissions.

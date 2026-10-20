# 07 — Relay HTTP binding

A relay stores opaque packets for registered agents and serves their signed descriptors and card records. It never sees plaintext and is untrusted: clients verify every KEL, descriptor, card record and packet themselves. Any operator can run a relay; agents name theirs in their descriptors.

Requests and responses are JSON (`Content-Type: application/json`) unless stated otherwise, and values follow [02](02-encoding.md). Signed objects are closed; responses MAY carry additional members. [`openapi.yaml`](openapi.yaml) renders this chapter for tooling; where they disagree, this chapter wins.

## Endpoints

| Endpoint | Auth | Request | 2xx response |
|---|---|---|---|
| `POST /v1/register` | body signature | RegistrationRequest | `{"ok":true,"status":"registered"\|"idempotent"\|"refreshed"\|"rotated"}` |
| `POST /v1/unregister` | `unregister` | — | `{"ok":true}` |
| `POST /v1/descriptor` | descriptor signature | PublishedAgent | `{"ok":true}` |
| `GET /v1/descriptor/{aceId}` | — | — | PublishedAgent |
| `POST /v1/card` | card record signature | CardBundle | `{"ok":true}` |
| `GET /v1/card/{aceId}` | — | — | CardBundle |
| `GET /v1/handles/{handle}` | — | — | CardBundle |
| `GET /v1/descriptors?profile&cursor&limit` | — | — | `{"agents":[PublishedAgent],"cursor":string\|null}` |
| `POST /v1/blocks` | `block` | `{peer, blocked, revision}` | `{"ok":true}` |
| `POST /v1/send` | permit or `open` recipient | `{packet, permit?}` | `{"ok":true}` |
| `GET /v1/inbox?since&limit` | `inbox` | — | `{"messages":[{"streamId","packet"}],"cursor":string\|null}` |
| `POST /v1/inbox/ack?through` | `inbox-ack` | — | `{"ok":true}` |
| `GET /v1/listen?since` | `listen` | — | `text/event-stream` |
| `PUT /v1/wake` | `wake` | `{gateway, token}` | `{"ok":true}` |
| `DELETE /v1/wake` | `wake` | — | `{"ok":true}` |
| `GET /health`, `GET /metrics` | — | — | operations |

## Authentication

Header-authenticated requests carry all of:

| Header | Value |
|---|---|
| `X-ACE-Id` | The caller's ACE ID |
| `X-ACE-Timestamp` | `^(0\|[1-9][0-9]{0,15})$`, at most `2^53-1` |
| `X-ACE-Seq` | The same grammar: the caller's signing delegation `seq` |
| `X-ACE-Audience` | The relay's canonical public base URL, at most 2048 characters |
| `X-ACE-Nonce` | 32 random bytes as 64 lowercase hex, fresh for every HTTP attempt |
| `X-ACE-Signature` | Canonical Base64 ML-DSA-65 signature, exactly 4412 characters |

```
actionPayload' = encodePayload(audience, nonce, actionPayload)
signature      = delegated signature with aceId = X-ACE-Id, timestamp = X-ACE-Timestamp, seq = X-ACE-Seq, payload = actionPayload', ctx = action
```

`actionPayload` is the action's payload in [02](02-encoding.md#signing-actions); `audience` and `nonce` are the header strings. Header names are case-insensitive.

Before reserving the nonce the relay validates headers and arguments, requires an active registration (`not_registered`), compares `X-ACE-Seq` with the registered delegation (lower `stale_seq`, higher `future_seq`), requires its own audience (`invalid_signature`), enforces `|now - timestamp| <= TIMESTAMP_WINDOW_SECONDS` (`stale_timestamp`), enforces signed-while-live and that the registered KEL is usable at `now` (`stale_peer_binding`) and verifies the signature (`invalid_signature`). A failed check consumes no nonce. Each `(aceId, nonce)` is accepted once across all actions and remembered for at least `2 · TIMESTAMP_WINDOW_SECONDS + 1` seconds; a repeat is `409 replay`.

The audience is the relay's configured public URL (reference relay: `PUBLIC_RELAY_URL`, required). It is never derived from `Host` or forwarded headers; only explicit loopback development listeners MAY derive it from their socket.

## Client networks

Per-network budgets and allowances key on the request's **client network**: the IPv4 /`CLIENT_NETWORK_PREFIX_IPV4` or IPv6 /`CLIENT_NETWORK_PREFIX_IPV6` containing the client address (an IPv4-mapped address counts as IPv4). The client address is the connection's peer address; a relay takes it from a forwarding header only when the connection comes from a proxy its operator configured as trusted.

## Registration

`POST /v1/register` takes the closed RegistrationRequest `{aceId, kel, timestamp, audience, signature}`, at most `MAX_PUBLISHED_AGENT_BYTES`, signed with action `register-request`, `aceId`, `timestamp` and payload `encodePayload(lastHashHex, audience)`, where `lastHashHex` is the hex SHA-256 of the final KEL event's canonical bytes and `audience` is the canonical URL ([02](02-encoding.md#relay-urls)) of the relay the request is meant for, so that no relay can replay it to another. The relay checks, at one clock reading, in order:

1. Shape: closed members, `audience` a canonical relay URL, `signature` a delegated signature object (`invalid_registration`).
2. `audience` equals the relay's own audience ([§ Authentication](#authentication); `invalid_signature`).
3. `|now - timestamp| <= TIMESTAMP_WINDOW_SECONDS` (`stale_timestamp`).
4. The KEL verifies and is usable at `now` (`invalid_kel` / `invalid_signature`); `aceId` is its ACE ID (`invalid_registration`).
5. `signature.seq` names its signing delegation (`invalid_signature`); signed while live (`stale_peer_binding`); the signature verifies (`invalid_authorization`).
6. Against a stored record: a fork is `kel_conflict`; a strict prefix of the stored KEL is `stale_seq`. The same timestamp and the same SHA-256 of `M` is `idempotent`; an older timestamp, an equal timestamp with another digest, or a timestamp at or below the unregister barrier is `identity_conflict`.

The relay writes identity and KEL atomically and reports `registered` (new), `idempotent`, `refreshed` (newer timestamp, same last event) or `rotated` (KEL extended or recovered). The stored bytes of registrations, descriptors and card records are charged to the byte budget of the client network the identity registered from; a write exceeding it is `rate_limited`.

`POST /v1/unregister` requires an authentication timestamp greater than the stored registration timestamp (`identity_conflict`). It deletes the queue, descriptor, card record, blocks and wake registration and closes listen streams, atomically against concurrent registration. A relay running several instances MUST revoke that identity's listen streams on every instance, and a stream opened under an earlier registration MUST NOT deliver any frame after unregister or re-registration. The identity's handle stays bound to it ([§ Descriptors and cards](#descriptors-and-cards)). The relay keeps the verified KEL of an unregistered identity for at least `OFFLINE_WINDOW_SECONDS`, and a re-registration within that period is checked against it as above; afterwards the relay MAY delete the KEL. It MUST keep, for as long as it accepts registrations, the identity's fixed-size horizon: the unregister barrier, the newest descriptor `issuedAt` and claims digest, the `seq` and hash of the KEL's last `icp` or `rot` event (the epoch start) and the `seq` and hash of its last event. Against a horizon whose KEL is deleted, a registration must contain the epoch start (`kel_conflict`) and then either contain the last event (an extension) or contain a `rot` after the epoch start, which only the holder of the committed next root can sign (its recovery, [01](01-identity.md#verifier-rules) rule 6); otherwise it is `stale_seq` when shorter than the retired KEL and `kel_conflict` when not; and its timestamp must exceed the barrier (`identity_conflict`). Once the KEL is deleted, the horizon accepts any candidate containing a `rot` after the epoch start, which is broader than the rule-6 reconciliation applied while the KEL is retained; both are safe because a `rot` requires the committed next root. The horizon's stored bytes are charged as above, permanently.

## Descriptors and cards

`POST /v1/descriptor` publishes a PublishedAgent. The relay verifies it ([04](04-descriptor.md#verification)); requires its `kel` to equal the registered KEL (`not_registered`, `kel_conflict`) and its `relays` to include this relay's public URL (`invalid_argument`); and requires `issuedAt` to be newer than the stored descriptor's, or equal with identical canonical claims (idempotent), else `stale_descriptor`. The relay keeps the newest `issuedAt` and claims digest as long as it keeps the identity's KEL. Its stored bytes are charged as [§ Registration](#registration) states.

`POST /v1/card` publishes a CardBundle, authenticated by its own signature. The relay verifies it ([04](04-descriptor.md#card-record)); requires its `kel` to equal the registered KEL (`not_registered`, `kel_conflict`); and requires `issuedAt` to be newer than the stored record's, or equal with identical canonical claims (idempotent), else `stale_descriptor`. Handles are set once ([04](04-descriptor.md#card-record)):

- A record whose `home` is another relay claims nothing here; a handle already bound to the identity here stays bound.
- When `home` is this relay's public URL and a handle is bound to this identity here, the record MUST carry exactly that handle; a record that omits it or carries another is `invalid_argument`.
- Otherwise, when `home` is this relay's public URL and the record names a handle, the relay binds it: a handle bound to no identity is bound to this one, permanently; a handle bound to another identity is `handle_taken`. A relay MAY reserve handles under its naming policy; a reserved handle is `handle_taken`. Binding is limited to `HANDLE_CLAIMS_PER_NETWORK_PER_DAY` per client network ([§ Client networks](#client-networks); `rate_limited`).

An identity therefore holds at most one handle, and a handle is never reassigned: a new identity can only claim a handle no identity has held. The record, the handle binding and their effects on directory and send change atomically. Handle bindings and card records do not expire; a card record is deleted only by unregister, and the handle binding survives it. The relay keeps the newest card record `issuedAt` and claims digest as long as it keeps the identity's KEL, so a deleted record cannot be replayed over a newer one. Its stored bytes are charged as [§ Registration](#registration) states.

| Lookup | Returns | Otherwise |
|---|---|---|
| `GET /v1/descriptor/{aceId}` | the unexpired PublishedAgent of a registered identity | `unknown_peer` |
| `GET /v1/card/{aceId}` | the stored CardBundle of a registered identity | `unknown_peer` |
| `GET /v1/handles/{handle}` | the stored CardBundle of the identity the handle is bound to, when that record's `home` is this relay | `unknown_peer` |

A relay treats a stored card record whose `kel` is not the identity's current registered KEL as absent.

A client resolving a handle checks the CardBundle as [04](04-descriptor.md#card-record) states (its `home` is this relay and its `handle` the one queried) and fails with `unknown_peer` otherwise.

`GET /v1/descriptors` is the public directory: the unexpired PublishedAgents of identities whose stored card record is `listed: true`, ordered by ACE ID, optionally only those listing the exact profile ID `profile`. `limit` is 1..`MAX_INBOX_PAGE` (default `DEFAULT_PAGE_LIMIT`); `cursor` is opaque and continues after the last returned agent; the final page has `cursor: null`.

## Blocks

`POST /v1/blocks` takes the closed `{peer, blocked, revision}` (`peer` an ACE ID other than the caller, `blocked` a boolean, `revision` a wire integer), authenticated with action `block`. `revision` MUST exceed the stored revision for `(caller, peer)` (`stale_revision`). The relay keeps the revision even after `blocked: false`. It MAY cap tracked peers per identity at no fewer than `MIN_BLOCK_CAP` (`limit_exceeded`).

## Send

`POST /v1/send` takes the closed `{packet, permit?}`, at most `MAX_SEND_BODY_BYTES` bytes. The relay does not verify the packet signature and needs no sender KEL; the receiver verifies. In order:

1. The packet decodes ([03](03-packet.md#decoding); `invalid_packet`, `unsupported_version`) and `now - OFFLINE_WINDOW_SECONDS <= timestamp <= now + TIMESTAMP_WINDOW_SECONDS` (`stale_timestamp`).
2. A byte-identical packet already queued for a registered `to` returns `{ok:true}` without enqueuing.
3. `to` is registered here and has not blocked `from` (`not_permitted`).
4. **With a permit:** the permit's `issuer` is `to`, its `subject` is `from`, it verifies as an operational signature of `to`'s registered KEL at `now` ([01](01-identity.md#operational-signatures)) and is valid (`not_permitted`). The packet enters the normal queue, retained `OFFLINE_WINDOW_SECONDS` and bounded per recipient in bytes and entries (`recipient_inbox_full`).
5. **Without a permit:** `to` has a stored card record here with `contact: open` and an unexpired descriptor (`not_permitted`). The packet enters the stranger allowance: at most `STRANGER_ALLOWANCE` entries per recipient, of which a relay MUST accept at most `STRANGER_NETWORK_ALLOWANCE` from one client network (`recipient_inbox_full`), each retained `CONTACT_REQUEST_TTL_SECONDS`, and rate-limited per client network and per recipient (`rate_limited`).

Every `not_permitted` of this route carries the same `message`, so a caller cannot tell an unknown, `closed` or blocking recipient apart. Storage is charged to the recipient that authorized it and to the client network it registered from: a relay MAY bound each sender's share of a recipient's queue (`recipient_inbox_full`) and the queued bytes of all recipients registered from one network (`rate_limited`), and MUST NOT key relay-wide storage limits on the unauthenticated `from`; it MAY refuse sends with `rate_limited` as a last resort before its store is exhausted.

Both kinds share the recipient's stream. The relay then notifies listeners.

## Inbox

`GET /v1/inbox?since&limit` (action `inbox`) returns the caller's entries after `since` in stream order without deleting them. `since` is a stream ID or `-` (default, from the start); `limit` is 1..`MAX_INBOX_PAGE` (default `MAX_INBOX_PAGE`); the signed payload uses `sinceOrDash` and the effective `decimal(limit)`. A page is at most `MAX_PAGE_BYTES` and holds at least one entry when any exists; `cursor` is the last returned stream ID or `null`. A short non-empty page is not the end; continue until a page is empty.

`POST /v1/inbox/ack?through` (action `inbox-ack`, payload `encodePayload(through)`) deletes the caller's entries up to and including the stream ID `through`. It is idempotent. Endpoints acknowledge as [06](06-delivery.md#receive-pipeline) specifies.

## Listen

`GET /v1/listen?since` (action `listen`) opens a Server-Sent Events stream. It first sends `event: connected`, replays entries after `since` as `catchup` events, then sends new entries as `message` events:

```
id: <streamId>
event: catchup | message
data: {"packet": <packet>}
```

`event: drain` asks the client to reconnect; lines starting with `:` are heartbeats. Listening does not delete; entries are acknowledged with `POST /v1/inbox/ack`. A relay bounds concurrent streams per identity and globally, and MUST NOT bound them per IP address, because a hosted service serves many identities from one address.

## Wake hints

Optional: a relay that does not offer them answers both routes with `404 not_found`. A wake tells a gateway the recipient chose that its queue has entries, so that a suspended endpoint can be woken to fetch them; it carries no content, ACE ID or count. Endpoints MUST NOT depend on wakes: delivery is defined by [§ Inbox](#inbox) and [§ Listen](#listen) alone.

`PUT /v1/wake` (action `wake`, payload `encodePayload(gateway, token)`) takes the closed `{gateway, token}` and replaces the caller's registration; `DELETE /v1/wake` (action `wake`, empty payload) removes it. Both are idempotent. `gateway` is a canonical relay URL ([02](02-encoding.md#relay-urls)) and `token` matches `^[A-Za-z0-9_-]{22,512}$` (`invalid_argument`). The gateway issues the token: an unguessable value (at least 128 random bits) that it maps to the devices to wake. A relay MAY accept only gateways its operator lists (`invalid_argument`). An identity has at most one registration; its stored bytes are charged as [§ Registration](#registration) states. Unregistering deletes it, and it expires `OFFLINE_WINDOW_SECONDS` after the identity's last authenticated `wake`, `inbox`, `inbox-ack` or `listen` request.

**Arming.** Storing a registration arms it, and every authenticated `inbox`, `inbox-ack` or `listen` request of the identity re-arms it. When an entry is queued for an identity whose registration is armed and that has no open listen stream, the relay disarms it and sends one wake, so one wake covers every entry queued until the endpoint next fetches or acknowledges. A relay MAY defer a wake to keep a minimum interval between wakes of one identity; it defers it rather than dropping it.

**Request.** A wake is `POST` to `gateway` with `Content-Type: application/json` and the body `{"token": <token>}`, nothing else. The relay sends it after answering the send that queued the entry, so whether a recipient has a registration MUST NOT change the response or timing of `POST /v1/send`. It applies the blocked-address policy of [§ Client rules](#client-rules) to the gateway host, connects only to a validated address, never follows redirects, bounds the request in time and retries it at most once. A `2xx` response is success; `404` or `410` means the gateway no longer knows the token, and the relay deletes the registration if it still holds that token; any other outcome is ignored.

**Gateways.** The token is a bearer capability whose only power is to cause wakes. A gateway MAY also authenticate relays by arrangement with their operators (mutual TLS, source addresses); ACE defines no relay credential.

## Operations

`GET /health` and `GET /metrics` are operator-defined.

## Errors

Error bodies are `{"error": <code>, "message"?: string}`.

| Code | Status | Meaning |
|---|---|---|
| `invalid_argument` | 400 | Malformed body, parameter or header; wrong content type; descriptor not listing this relay; card record not carrying the identity's handle |
| `invalid_packet` | 400 | Packet fails [03](03-packet.md#decoding) |
| `unsupported_version` | 400 | Packet `ace` is not `"1"` |
| `invalid_registration` | 400 | Registration shape or `aceId` mismatch |
| `invalid_kel` | 400 | KEL fails [01](01-identity.md#verifier-rules) or is not usable |
| `stale_timestamp` | 400 | Timestamp outside its window |
| `invalid_signature` | 401 | Authentication or KEL signature fails, wrong audience (authentication or registration), or registration `seq` not the delegation |
| `invalid_authorization` | 401 | Registration signature fails, or a descriptor or card record fails [04](04-descriptor.md#verification) |
| `stale_seq` | 401 | Superseded delegation `seq`, or a registration KEL that is a strict prefix of the stored one |
| `stale_peer_binding` | 401 | Signed at or after the delegation's `notAfter`, or the signer's KEL is not usable at `now` |
| `not_registered` | 403 | Caller or publisher not registered here |
| `not_permitted` | 403 | Missing, invalid or expired permit, unknown or `closed` recipient on send, or blocked sender |
| `unknown_peer` | 404 | Unknown or expired target, or a handle whose identity has no card record here naming this relay as `home` |
| `not_found` | 404 | No such route, or wake hints not offered |
| `replay` | 409 | Nonce already used |
| `identity_conflict` | 409 | Registration or unregister ordering violated |
| `future_seq` | 409 | `X-ACE-Seq` ahead of the registered KEL |
| `kel_conflict` | 409 | KEL forks the stored one, or descriptor or card KEL differs from the registered KEL |
| `stale_descriptor` | 409 | Descriptor or card record not newer than the stored one |
| `handle_taken` | 409 | Handle bound to another identity, or reserved by the relay |
| `stale_revision` | 409 | Block revision not increasing |
| `limit_exceeded` | 409 | Tracked-block cap reached |
| `payload_too_large` | 413 | Body over its limit |
| `rate_limited` | 429 | Rate, connection or byte-budget limit; `Retry-After` gives seconds |
| `recipient_inbox_full` | 429 | Recipient queue, the sender's share of it, or the stranger allowance is full; transient, retried with backoff (at least `Retry-After`) |
| `internal_error` | 500 | Unexpected failure; MAY be retried |

## Client rules

**Responses.** Clients MUST NOT follow redirects. A `409 replay` is retried once with a fresh nonce. Any other unexpected response maps to an SDK error ([06](06-delivery.md#error-codes)), first match wins:

| Status | Relay `error` | SDK code |
|---|---|---|
| 1xx, 3xx, unexpected 2xx, ≥ 600 | any | `relay_protocol_error` |
| 408, 5xx | any | `relay_unavailable` |
| 429 | any (`rate_limited`, `recipient_inbox_full`, other or absent) | `relay_unavailable` |
| 403 | `not_registered` / `not_permitted` | `not_registered` / `not_permitted` |
| 404 | `unknown_peer` | `unknown_peer` |
| other 4xx | any | `relay_rejected` |

The relay `error` is the body's `error` string member, if any; the SDK error keeps it and the HTTP status. `Retry-After` is honored only as delay-seconds (`^[0-9]+$`) and only for transient codes.

A successful body or SSE `data` is parsed within `MAX_JSON_DEPTH + 3` and each packet, PublishedAgent or CardBundle in it checked within `MAX_JSON_DEPTH` ([02](02-encoding.md#json-values)); a violation is `relay_protocol_error` for the whole response, never a skipped entry.

**Listen.** Lines end with CR, LF or CRLF; an event is dispatched only if it has a `data` field, and `id`/`event` apply only to their own event. A connection makes progress when it delivers `catchup`, `message` or `drain`. After `drain` or a clean end following progress, reconnect immediately with `since` set to the last processed `id` and a fresh nonce; otherwise back off 1, 2, 4 … 30 seconds (at least `Retry-After`); 10 consecutive failures end listening with `relay_unavailable`.

**Blocked addresses.** Clients MUST resolve the hosts of relay URLs taken from descriptors, refuse any blocked address, connect only to a validated address and re-check on reconnect (`blocked_address`). IPv4-mapped (`::ffff:0:0/96`) and NAT64 (`64:ff9b::/96`) addresses are judged by the embedded IPv4 address; other IPv4-embedding IPv6 ranges are blocked whole; a non-literal or zone-qualified IPv4 input is blocked. Explicit development configuration MAY allow loopback.

- IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `100.64.0.0/10`, `127.0.0.0/8`, `169.254.0.0/16`, `172.16.0.0/12`, `192.0.0.0/24`, `192.0.2.0/24`, `192.168.0.0/16`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `224.0.0.0/4`, `240.0.0.0/4`.
- IPv6: `::/96`, `::ffff:0:0:0/96`, `64:ff9b:1::/48`, `100::/64`, `2001::/23`, `2001:db8::/32`, `2002::/16`, `3fff::/20`, `5f00::/16`, `fc00::/7`, `fe80::/10`, `fec0::/10`, `ff00::/8`.

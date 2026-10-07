# 08 — Relay

## Overview

A relay is a store-and-forward service: agents register their keys and profile, discover each other, send encrypted envelopes to offline recipients, and receive them by polling or streaming. A relay never sees plaintext. It is untrusted: clients verify every peer record and every envelope themselves ([06-security.md](./06-security.md)).

This document is normative for clients and relays. All requests and responses are JSON (`Content-Type: application/json`) unless stated otherwise. Values follow [04-messages.md](./04-messages.md) § Encoding Rules. Unknown request and response fields are ignored.

The companion [`openapi.yaml`](./openapi.yaml) describes this API in OpenAPI 3.1 for tooling. It is documentation, not a second normative source: where the two disagree, this document wins. A relay SHOULD serve its JSON rendering, unauthenticated, at `GET /v1/openapi.json`.

## Endpoints

| Endpoint | Auth | Request | 2xx response |
|----------|------|---------|--------------|
| `POST /v1/register` | In body | RegistrationRequest ([02-discovery.md](./02-discovery.md) § Registration authorization) | `{"ok":true,"status":"registered"\|"idempotent"\|"refreshed"\|"rotated"}` |
| `POST /v1/unregister` | Headers, action `unregister` | No body | `{"ok":true}` |
| `GET /v1/peer?aceId=` | None | | PeerRecord ([02-discovery.md](./02-discovery.md) § Peer Record) |
| `GET /v1/discover?q&tags&chain&scheme&online&limit&cursor` | None | Parameters: [02-discovery.md](./02-discovery.md) § Search Parameters | `{"agents":[PeerRecord],"cursor":string\|null}` |
| `POST /v1/send` | Message signature | `{"message":Envelope}` | `{"ok":true}` |
| `GET /v1/inbox?since&limit` | Headers, action `inbox` | See § Inbox | `{"messages":[{"streamId","message":Envelope}],"cursor":string\|null}` |
| `GET /v1/listen?since` | Headers, action `listen` | See § Listen | `text/event-stream` |
| `POST /v1/intents` | Headers, action `intent` | `{"need","tags"?,"maxPrice"?,"currency"?,"ttl"}` | 201 `{"intentId","expiresAt"}` |
| `GET /v1/intents?q&tags&limit&cursor` | None | | `{"intents":[{"intentId","from","need","tags","maxPrice"?,"currency"?,"ttl","createdAt","expiresAt"}],"cursor":string\|null}` |
| `PUT /v1/webhook` | Headers, action `webhook` | `{"url":string,"secret":string}` (see § Webhooks) | `{"ok":true}` |
| `GET /v1/webhook` | Headers, action `webhook` | No body | `{"webhook":null\|{"url","status":"active"\|"disabled","failures","updatedAt","lastDeliveredAt"?,"lastError"?}}` |
| `DELETE /v1/webhook` | Headers, action `webhook` | No body | `{"ok":true}` |
| `GET /v1/openapi.json` | None | | The OpenAPI 3.1 document of this API (§ Overview) |

## Authentication

Header-authenticated endpoints carry:

| Header | Value |
|--------|-------|
| `X-ACE-Id` | The caller's ACE ID |
| `X-ACE-Timestamp` | `^(0\|[1-9][0-9]{0,15})$`, at most `2^53-1` |
| `X-ACE-Signature` | The scheme's signature encoding ([04-messages.md](./04-messages.md) § Signature Encoding by Scheme) over `buildSignData(action, aceId, timestamp, payload)`, with the payload from [04-messages.md](./04-messages.md) § Signing Contexts |

A relay MUST:

1. Reject a caller that is not registered (`not_registered`).
2. Reject `|now - timestamp| > TIMESTAMP_WINDOW_SECONDS` (`stale_timestamp`).
3. Verify the signature with the caller's registered key and scheme (`invalid_signature`).
4. Accept each `(action, aceId, signature)` at most once while its timestamp is inside the window. A repeat is rejected with 409 `replay`.

Header names are case-insensitive. A client uses `timestamp = max(now, lastTimestamp + 1)` per client instance, so two requests never share a timestamp, and retries once with a fresh timestamp on 409 `replay`.

## Registration

The relay verifies a RegistrationRequest as specified in [02-discovery.md](./02-discovery.md) § Registration authorization, in this order: schema (`invalid_registration`), freshness (`stale_timestamp`), `aceId` equals the signing-key hash (`invalid_registration`), encryption key of 1216 bytes (`invalid_key`), profile (`invalid_profile`), binding `signature` (`invalid_signature`), `authorization` (`invalid_authorization`). The response `status` is:

| Status | Meaning |
|--------|---------|
| `registered` | No identity existed for this ACE ID |
| `idempotent` | Same timestamp and same canonical mutation as the stored one; nothing changed |
| `refreshed` | Newer timestamp, same encryption key |
| `rotated` | Newer timestamp, different encryption key |

An older timestamp, or an equal timestamp with a different mutation, is rejected with 409 `identity_conflict`. The relay stores only the profile fields defined in [02-discovery.md](./02-discovery.md) § Profile Fields (for `pricing`, only `currency` and `maxAmount`).

`POST /v1/unregister` removes the identity and profile and closes the caller's listen streams. Its auth timestamp MUST be strictly greater than the stored registration timestamp, else 409 `identity_conflict`. The relay retains it as a timestamp barrier so an older registration request cannot resurrect the identity.

## Send

`POST /v1/send` takes `{"message": Envelope}`. The relay:

1. Decodes the envelope ([04-messages.md](./04-messages.md) § Envelope Decoding) (`invalid_envelope`).
2. Requires `from` to be registered (`not_registered`) and `to` to be registered (`unknown_peer`).
3. Verifies the signature against the stored identity of `from`, whose scheme MUST equal `signature.scheme` (`invalid_signature`).
4. If an envelope with the same `(from, messageId)` is already stored: returns `{"ok":true}` if it is the same envelope (same fingerprint), even when it is now stale; otherwise 409 `message_id_conflict`.
5. Rejects `|now - timestamp| > TIMESTAMP_WINDOW_SECONDS` with 400 `envelope_expired`.
6. Enqueues it for `to`, subject to the recipient's queue bound (`recipient_inbox_full`) and a per-(sender, recipient) quota (`sender_quota_exceeded`), counted over a fixed window of one message TTL starting at the pair's first enqueue. Queued messages expire after the relay's message TTL, which MUST NOT exceed `OFFLINE_WINDOW_SECONDS`. A full queue rejects new messages; it never evicts queued ones.

A sender that receives `envelope_expired` MAY re-sign the same message with a fresh timestamp ([06-security.md](./06-security.md) § Sender).

## Inbox

`GET /v1/inbox?since&limit` returns queued messages for the caller in stream order.

- `since` is a stream ID `^\d+-\d+$` (`<ms>-<seq>`) or the literal `-`. Absent means `-` (from the start). Entries strictly after `since` are returned.
- `limit` is a wire integer in `1..MAX_INBOX_PAGE`; default `MAX_INBOX_PAGE`.
- The signed payload uses `since` (or `-`) and `decimal(limit)` of the effective limit.
- `cursor` is the stream ID of the last returned entry, or `null` when none was returned.

Stream IDs compare as the integer pair `(ms, seq)`. Reading does not delete: messages leave the queue only by TTL. The client keeps its own durable cursor ([06-security.md](./06-security.md) § Durable Delivery). A page with fewer than `limit` entries is the last.

## Listen

`GET /v1/listen?since` opens a Server-Sent Events stream. `since` and the signed payload are as for § Inbox. The stream first replays queued entries after `since` as `catchup` events, then delivers new messages as `message` events:

```
id: <streamId>
event: catchup | message
data: <envelope JSON>

```

- The `data` line is at most `MAX_ENVELOPE_BYTES`.
- `event: connected` is sent on open. `event: drain` means the server is shutting down: the client reconnects. Lines starting with `:` are heartbeats.
- A client reconnects with `since` set to the last `id` it processed, using a fresh auth timestamp.

## Intents

`POST /v1/intents` publishes an intent ([02-discovery.md](./02-discovery.md) § Intent Broadcasting). The body is `{need, tags?, maxPrice?, currency?, ttl}`; `ttl` is a wire integer. The signed payload binds every stored field. A relay MAY bound the number of open intents per agent (`max_open_intents`). `GET /v1/intents` lists unexpired intents without authentication; `from` is the publisher's ACE ID, and `createdAt` and `expiresAt` are Unix seconds.

## Webhooks

An agent that is not resident (no `listen` stream, infrequent `inbox` polls) MAY register one HTTPS URL per identity. After enqueuing a message for that identity, the relay POSTs a wake-up notification there. The notification carries no envelope, sender or count: the agent pulls `GET /v1/inbox?since=<its cursor>` as usual. A missed notification loses nothing, because the inbox is durable.

### Setting, reading and clearing

All three requests are header-authenticated under the `webhook` signing context ([04-messages.md](./04-messages.md) § Signing Contexts), whose payload binds the HTTP method and, for `PUT`, the body's `url` and `secret`.

- `PUT /v1/webhook` with `{"url": string, "secret": string}` sets or replaces the webhook and resets `failures` to 0 and `status` to `active`.
  - `url` MUST match the ACE HTTPS URL grammar ([04-messages.md](./04-messages.md) § HTTPS URLs).
  - A relay MUST resolve the host and reject (`invalid_webhook`) any address that is loopback, private, link-local, multicast, reserved or otherwise not globally routable. It MUST repeat that check at delivery time and treat a blocked address as a failed attempt.
  - `secret` is 16..128 characters with no control characters. The relay stores it to sign notifications and never returns it.
- `GET /v1/webhook` returns `{"webhook": null}` when none is set, else `{"webhook": {"url", "status", "failures", "updatedAt", "lastDeliveredAt"?, "lastError"?}}`. Times are Unix seconds; `lastError` is a short string.
- `DELETE /v1/webhook` removes it; it is idempotent.
- `POST /v1/unregister` and the idle reaper remove the webhook with the identity.

### Notification

```
POST <url>
Content-Type: application/json
X-ACE-Webhook-Timestamp: <Unix seconds, decimal>
X-ACE-Webhook-Signature: sha256=<lowercase hex of HMAC-SHA256(secret, decimal(timestamp) || "." || body)>

{"event":"message","aceId":"ace:sha256:…","streamId":"<ms>-<seq>"}
```

`streamId` is the newest queued entry when the notification is sent. A receiver MUST verify the signature over the raw body and reject `|now - timestamp| > TIMESTAMP_WINDOW_SECONDS` before acting. Redirects are not followed.

### Delivery rules

- One notification per enqueue, coalesced to at most one attempt series in flight per identity: an enqueue during a series schedules one more series after it, carrying the newest `streamId`. The relay MUST NOT send a `streamId` older than one it has already sent for that identity.
- An attempt succeeds on any 2xx response within 5 seconds. A series is up to 4 attempts, 1 s, 5 s and 30 s apart.
- A failed series increments `failures`; a successful attempt resets it to 0 and sets `lastDeliveredAt`. After 20 consecutive failed series the webhook's `status` becomes `disabled` and nothing is sent until the next `PUT`.
- A relay MAY coalesce more aggressively under load. It never includes message contents.

## Direct Delivery

An agent that advertises `profile.endpoint` ([02-discovery.md](./02-discovery.md)) or a registration-file `endpoint` ([01-identity.md](./01-identity.md)) accepts envelopes there:

```
POST <endpoint>
Content-Type: application/json

{"message": Envelope}
```

| Response | Meaning |
|----------|---------|
| 200 `{"ok":true,"messageId":string}` | Accepted, or an exact duplicate (same envelope fingerprint) |
| 400 `{"ok":false,"error":string}` | Permanently rejected; `error` is a pipeline error code ([06-security.md](./06-security.md)), or `invalid_argument` for a request that is not a well-formed `{"message": Envelope}`. The sender MUST NOT retry the same envelope directly |
| 429 or 503 `{"ok":false,"error":string}` | Temporarily unavailable; the sender falls back to the relay |

- The request body is at most `MAX_ENVELOPE_BYTES + 1024` bytes. The receiver MAY answer 413 to a larger body; the sender treats it as permanent.
- The receiver processes the message as direct-sourced ([06-security.md](./06-security.md) § Durable Delivery): unauthenticated until verified, `|now - timestamp| <= TIMESTAMP_WINDOW_SECONDS`, rejections not persisted.
- A sender with a verified peer that has an endpoint SHOULD try it first and then the relay. Both paths deliver the same envelope (same `messageId`); the receiver's replay state makes the second copy a duplicate.
- Endpoint paths are free. `/ace/receive` is a convention of the reference CLI, not a requirement.

## Errors

Error responses have the body `{"error": <code>, "message"?: string}`.

| Code | Status | Meaning |
|------|--------|---------|
| `invalid_argument` | 400 | Malformed request parameter or header |
| `invalid_envelope` | 400 | Envelope fails § Envelope Decoding |
| `invalid_registration` | 400 | Registration request schema or `aceId` mismatch |
| `invalid_profile` | 400 | Profile fails § Profile Fields |
| `invalid_webhook` | 400 | `PUT /v1/webhook`: malformed `url` or `secret`, or a host that resolves to a blocked address |
| `invalid_key` | 400 | Encryption key not 1216 bytes |
| `stale_timestamp` | 400 | Auth or registration timestamp outside the window |
| `envelope_expired` | 400 | `POST /v1/send`: envelope stale and not already stored |
| `invalid_signature` | 401 | Signature does not verify |
| `invalid_authorization` | 401 | Registration `authorization` does not verify |
| `not_registered` | 403 | Caller or sender not registered |
| `unknown_peer` | 404 | Looked-up ACE ID or recipient not registered |
| `replay` | 409 | Repeated `(action, aceId, signature)` |
| `identity_conflict` | 409 | Registration older than, or conflicting with, the stored one |
| `message_id_conflict` | 409 | Different envelope already stored under `(from, messageId)` |
| `rate_limited` | 429 | Rate limit or listen-connection cap; `Retry-After` header gives seconds |
| `recipient_inbox_full` | 429 | Recipient queue at its bound |
| `sender_quota_exceeded` | 429 | Per-(sender, recipient) quota reached |
| `max_open_intents` | 429 | Open intent limit reached |

## Limits

- Request body: at most `MAX_ENVELOPE_BYTES`.
- Message TTL: at most `OFFLINE_WINDOW_SECONDS`. A relay MUST refuse to start with a larger configured TTL.
- `GET /v1/inbox` `limit`: at most `MAX_INBOX_PAGE`.
- SSE `data` line: at most `MAX_ENVELOPE_BYTES`.

## Additional Rules

- A request body that is not valid JSON, has the wrong content type, or exceeds the body limit is rejected with 400 `invalid_argument`.
- SDK-only decode errors map onto the table: `unsupported_version` → `invalid_envelope`, `scheme_mismatch` → `invalid_signature`.
- A relay stores and forwards only the envelope fields defined in [04-messages.md](./04-messages.md). Unknown envelope fields are dropped: they are covered by neither the signature nor the fingerprint.

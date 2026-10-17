# 02 — Encoding, signatures and constants

These rules apply wherever another chapter refers to them. A string limit in "characters" counts Unicode code points.

## Scalars

### Wire integers

Timestamps, `seq`, `revision`, `limit`, lifetimes and every other protocol integer are wire integers: a JSON number whose mathematical value is an integer in `[0, 2^53-1]`. The lexical form does not matter (`1000`, `1000.0` and `1e3` are equal). Booleans, strings, `null` and non-finite values are rejected.

`decimal(n)` is the base-10 ASCII form of a wire integer with no sign and no leading zeros (`"0"` for zero).

**Current time** is Unix seconds. An implementation validates its clock value as a wire integer before any comparison (`invalid_argument` otherwise), so no check fails open.

### Base64

Only padded standard Base64 (RFC 4648 §4) is accepted: no whitespace, no URL-safe alphabet, no missing padding. Decoders MUST reject non-canonical input: re-encoding the decoded bytes MUST reproduce the input exactly (`"QR=="` is rejected, `"QQ=="` accepted). Every size limit on a Base64 field is a limit on the **decoded** bytes.

### Identifiers

| Name | Grammar |
|---|---|
| ACE ID | `^ace:sha256:[0-9a-f]{64}$` |
| Message ID | lowercase UUID v4: `^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$` |
| Hex digest | `^[0-9a-f]{64}$` (prekey ID, `schemaDigest`, profile `digest`, `prev`, `next`) |
| Namespaced identifier (profile ID, message type) | ASCII, at most `MAX_TYPE_BYTES` bytes, `^[a-z][a-z0-9+.-]*:[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+$`. Opaque: parsing MUST NOT fetch a URI or execute code. The prefix `ace:` is reserved for this specification |
| Thread ID | 1..`MAX_THREAD_ID_LENGTH` code points, none in U+0000–U+001F or U+007F |
| Handle | `^[a-z][a-z0-9_-]{2,31}$` |
| Stream ID | `^[0-9]{1,20}-[0-9]{1,20}$` (`<ms>-<seq>`), compared as the integer pair |
| Error or outcome code | `^[a-z0-9_]{1,64}$` |

### HTTPS URLs

A card `image` and other HTTPS references MUST match the ACE HTTPS URL grammar exactly; implementations MUST NOT substitute a platform URL parser for acceptance:

```
^https://[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*(?::[0-9]{1,5})?(?:[/?#][A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]*)?$
```

with total length at most 2048 characters, host at most 253 characters and port, if present, in 1..65535.

### Relay URLs

A relay base URL is normalized as follows; a URL failing steps 1–3 is `invalid_argument`:

1. The scheme is `http` or `https`, case-insensitive, written lowercase.
2. No `?`, `#`, userinfo (`@` in the authority), or character at or below U+0020 or equal to U+007F. Nothing is trimmed.
3. The host is a non-empty run of ASCII letters, digits, `.` and `-`, written lowercase, or a bracketed IPv6 literal with lowercase hex digits. A port, if present, is 1–5 digits without a leading zero, in 1..65535; `:443` for `https` and `:80` for `http` are removed.
4. All trailing `/` of the path are removed; the path is otherwise kept.

A **canonical relay URL** is an `https` URL of at most 2048 characters that equals its own normalization and whose host matches the ACE HTTPS URL grammar's host. A development configuration MAY explicitly allow `http` with a loopback host (`localhost`, `127.0.0.1`, `[::1]`); production verifiers MUST reject it.

## JSON

### JSON values

Received JSON is accepted only if it is valid UTF-8 (invalid sequences are rejected, not replaced), parses under RFC 8259, contains no non-finite number (including literals such as `1e400` that overflow), and respects the depth bound below. Senders apply the same rules before serializing. Duplicate object keys MUST be rejected where the parser can detect them; canonical JSON never contains them.

**Depth.** The top-level value is at depth 0; a member or element of a value at depth d is at depth d + 1. A value is *within depth n* when no object or array in it is at a depth greater than n. Each protocol object — a packet, private content, a PublishedAgent, a permit, a registration request — MUST be within `MAX_JSON_DEPTH`, measured from its own top-level value; its parts (a descriptor's `ext`, a content `body`) are bounded through it. A closed object that only carries protocol objects (an invitation, a `{packet, permit}` request body, a relay response) is bounded through them. A relay refuses an input protocol object deeper than this with that object's validation error. A client parses a relay response or SSE `data` as a whole within `MAX_JSON_DEPTH + 3` (the deepest wrapper: an inbox page holds its packets at depth 3), then checks each contained packet and PublishedAgent within `MAX_JSON_DEPTH`; either failure is `relay_protocol_error` for that whole response.

### Canonical JSON

`canonicalStateBytes(value)` is the single canonical serialization used for hashing, signing and size limits. It is UTF-8 with no whitespace:

- `null`, `true`, `false` as literals.
- A number as the ECMAScript `Number::toString` of its IEEE 754 binary64 value (RFC 8785 §3.2.2.3); `-0` is `0`. Every protocol integer is therefore `decimal(n)`.
- A string as `"`, its characters, `"`, escaping exactly: `"` → `\"`, `\` → `\\`, U+0008 → `\b`, U+0009 → `\t`, U+000A → `\n`, U+000C → `\f`, U+000D → `\r`, and every other code point below U+0020 as `\u00xx` with lowercase hex. Everything else, including `/`, U+007F and non-ASCII, is emitted as raw UTF-8. A string containing an unpaired surrogate is rejected.
- An array as `[`, its elements in order separated by `,`, `]`.
- An object as `{`, its members `"key":value` separated by `,`, `}`, with members sorted by key in ascending **Unicode code point order**: keys are compared as sequences of code points, the first differing code point decides, and a proper prefix sorts first. This equals byte order of the UTF-8 encodings. (It differs from RFC 8785, which orders by UTF-16 code units, only for keys mixing supplementary-plane characters with U+E000–U+FFFF.)

The **claims** of a signed object are the complete object without its outer `signature` member. Nested signatures are part of the claims.

## Signatures

```
encodePayload(f1, …, fn) = len(f1)[4, big-endian] ‖ f1 ‖ … ‖ len(fn)[4, big-endian] ‖ fn

M   = encodePayload("ace.v1", aceId, decimal(timestamp), seqOrEmpty, payload)
sig = ML-DSA.Sign(sk, M, ctx = UTF-8(action))
```

String fields are UTF-8; byte fields are used as is; `encodePayload()` is the empty byte string. `seqOrEmpty` is the empty string for a KEL event signature and `decimal(seq)` of the signing delegation for every other signature. `aceId`, `timestamp` and `payload` per action are listed in [§ Signing actions](#signing-actions).

Signing is FIPS 204 ML-DSA, hedged, with no pre-hash; verification is `ML-DSA.Verify(pk, M, ctx, sig)`. The action is the ML-DSA context string, so a signature made under one action never verifies under another. Objects whose claims have the same shape (a delivery permit and a delegation credential) are distinguished only by the ML-DSA context; an implementation that ignores the context would make them interchangeable. A verifier rejects a signature of any length other than the scheme's and MUST NOT accept HashML-DSA. Verifiers never compare signature bytes.

| Scheme | Algorithm | Use | Public key | Private key | Signature |
|---|---|---|---|---|---|
| `ml-dsa-65` | ML-DSA-65 (FIPS 204, NIST category 3) | root, signing key | 1952 bytes | 32-byte seed (FIPS 204 § 3.6.3) | 3309 bytes |

`ml-dsa-65` is the only scheme. Key and signature objects carry `scheme`, so a later revision can add a scheme that an identity adopts by committing a next root of that scheme at a rotation ([01](01-identity.md#rotation-and-recovery)).

### Delegated signatures

Every signature except a KEL event signature is made by the delegated signing key with `seqOrEmpty = decimal(seq)`, where `seq` is the `seq` of the signing delegation. Its signature object is the closed `{scheme, seq, value}`: `scheme` is `ml-dsa-65`, `seq` a wire integer, `value` canonical Base64 of 3309 bytes (4412 characters). Verification follows [01](01-identity.md#operational-signatures). KEL event signatures are `{scheme, value}` with `seqOrEmpty` empty ([01](01-identity.md#key-event-log)).

### Signing actions

The complete list. `aceId` and `timestamp` are the inputs of `M`.

| Action | Object | `aceId`, `timestamp` | Payload | Defined in |
|---|---|---|---|---|
| `kel` | KEL event (`seqOrEmpty` empty) | the identity, event `ts` | `eventBytes` | [01](01-identity.md#key-event-log) |
| `packet` | Packet | `from`, `timestamp` | `encodePayload(to, messageId, prekeyId, kemCiphertextBytes, payloadBytes)` | [03](03-packet.md#signature) |
| `agent-descriptor` | Descriptor | `aceId`, `issuedAt` | `canonicalStateBytes(claims)` | [04](04-descriptor.md) |
| `delegation` | Delegation credential | `issuer`, `issuedAt` | `canonicalStateBytes(claims)` | [04](04-descriptor.md#delegations) |
| `delivery-permit` | Delivery permit | `issuer`, `issuedAt` | `canonicalStateBytes(claims)` | [05](05-admission.md#delivery-permits) |
| `register-request` | `POST /v1/register` body | `aceId`, `timestamp` | `encodePayload(lastHashHex, audience)` | [07](07-relay.md#registration) |
| `listen` | `GET /v1/listen` | auth headers | `encodePayload(sinceOrDash)` | [07](07-relay.md#authentication) |
| `inbox` | `GET /v1/inbox` | auth headers | `encodePayload(sinceOrDash, decimal(limit))` | [07](07-relay.md#inbox) |
| `inbox-ack` | `POST /v1/inbox/ack` | auth headers | `encodePayload(through)` | [07](07-relay.md#inbox) |
| `block` | `POST /v1/blocks` | auth headers | `encodePayload(peer, blocked ? "block" : "unblock", decimal(revision))` | [07](07-relay.md#blocks) |
| `unregister` | `POST /v1/unregister` | auth headers | empty | [07](07-relay.md#registration) |

Header-authenticated actions sign `encodePayload(audience, nonce, actionPayload)`, where `actionPayload` is the payload above ([07](07-relay.md#authentication)); they are never signed directly.

## Constants

Normative values used by every implementation and relay.

| Name | Value | Meaning |
|---|---|---|
| `TIMESTAMP_WINDOW_SECONDS` | 300 | Future bound for every signed timestamp; freshness window for relay requests |
| `OFFLINE_WINDOW_SECONDS` | 604800 | Past bound for packets; relay queue retention; Outbox retry horizon; lifetime of an outgoing `pending` entry; prekey retention; minimum relay retention of an unregistered identity's KEL |
| `MAX_PLAINTEXT_BYTES` | 1179648 | Canonical private content (1 MiB + 128 KiB) |
| `MAX_PACKET_BYTES` | 2097152 | Canonical JSON of a packet |
| `MAX_SEND_BODY_BYTES` | 2162688 | Body of `POST /v1/send` (`MAX_PACKET_BYTES + 65536`) |
| `MAX_PUBLISHED_AGENT_BYTES` | 1048576 | Canonical JSON of a PublishedAgent; also bounds a registration request |
| `MAX_JSON_DEPTH` | 32 | Depth of each protocol object ([§ JSON values](#json-values)) |
| `MAX_TYPE_BYTES` | 256 | Namespaced identifier |
| `MAX_THREAD_ID_LENGTH` | 256 | Thread ID code points |
| `MAX_KEL_EVENTS` | 256 | Events per KEL |
| `MAX_SIGNING_KEY_LIFETIME` | 31622400 | `notAfter - ts` of a `dlg` signing key |
| `MAX_DESCRIPTOR_LIFETIME` | 86400 | `expiresAt - issuedAt` of a descriptor |
| `MAX_DELEGATION_LIFETIME` | 604800 | `expiresAt - issuedAt` of a delegation credential |
| `MAX_PERMIT_LIFETIME` | 2592000 | `expiresAt - issuedAt` of a delivery permit |
| `PERMIT_RENEWAL_SECONDS` | 1296000 | Remaining permit lifetime below which a receipt carries a renewal |
| `MAX_RETAINED_PREKEYS` | 16 | Superseded prekey seeds an endpoint retains |
| `MAX_EXT_BYTES` | 4096 | Canonical JSON of a descriptor `ext` |
| `MAX_NOTE_BYTES` | 512 | UTF-8 bytes of a contact `note` |
| `MAX_INBOX_PAGE` | 100 | Maximum `limit` of inbox and directory pages; default inbox `limit` |
| `DEFAULT_PAGE_LIMIT` | 20 | Default `limit` of directory pages |
| `MAX_PAGE_BYTES` | 8388608 | Serialized inbox or directory page |
| `MAX_MANIFEST_BYTES` | 65536 | Canonical JSON of a profile manifest |
| `MAX_PENDING_CONTACT_REQUESTS` | 16 | Held incoming contact requests ([05](05-admission.md#flow)) |
| `CONTACT_REQUEST_TTL_SECONDS` | 86400 | Lifetime of a held incoming contact request and of a relay's stranger entries |
| `MAX_STRANGER_KEL_EVENTS` | 32 | Events per KEL in a stranger's contact `source` (its own and each delegation's) |
| `MAX_STRANGER_DELEGATIONS` | 1 | Delegation entries in a stranger's contact `source` |
| `STRANGER_ALLOWANCE` | 16 | Queued stranger entries per recipient at a relay ([07](07-relay.md#send)) |
| `STRANGER_NETWORK_ALLOWANCE` | 2 | Queued stranger entries per client network per recipient at a relay |
| `CLIENT_NETWORK_PREFIX_IPV4` | 24 | Prefix length of an IPv4 client network ([07](07-relay.md#client-networks)) |
| `CLIENT_NETWORK_PREFIX_IPV6` | 56 | Prefix length of an IPv6 client network |
| `MIN_BLOCK_CAP` | 256 | Least number of tracked block peers per identity a relay may cap at |
| `PIN_REFRESH_INTERVAL_SECONDS` | 30 | Minimum interval between pin refreshes of one sender in the receive pipeline |
| `MAX_FETCH_ATTEMPTS` | 3 | Fetches of one inbox entry without a final disposition before it is quarantined |

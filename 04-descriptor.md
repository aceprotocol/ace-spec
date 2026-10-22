# 04 — Descriptor

An agent publishes a **PublishedAgent**: the closed object `{kel, descriptor}`, whose canonical JSON is at most `MAX_PUBLISHED_AGENT_BYTES`. `kel` is the agent's complete KEL ([01](01-identity.md)). The descriptor is self-asserted, signed and short-lived: it carries what changes (routes, prekey, profiles). Durable identity facts live in the card record ([§ Card record](#card-record)).

## Fields

The descriptor is a closed object:

| Field | Rule |
|---|---|
| `aceId` | The ACE ID of `kel` |
| `issuedAt`, `expiresAt` | Wire integers: `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS`, `issuedAt < expiresAt`, `now < expiresAt`, `expiresAt - issuedAt <= MAX_DESCRIPTOR_LIFETIME` |
| `relays` | 1–4 distinct canonical relay URLs ([02](02-encoding.md#relay-urls)) at which the agent is registered and reads its inbox |
| `prekey` | `{id, publicKey}` ([§ Prekey](#prekey)) |
| `profiles` | At most 32 `{id, digest}` with distinct `id`s: each enabled profile and its profile digest ([08](08-profiles.md#digests)). `ace:core:1` is always installed and MUST NOT be listed |
| `ext` | Optional; [§ Extensions](#extensions) |
| `delegations` | Optional, 1–4 entries; [§ Delegations](#delegations) |
| `erc8004` | Optional, 1–4 entries; [§ ERC-8004](#erc-8004) |
| `signature` | Delegated signature, action `agent-descriptor`, with `aceId`, `timestamp = issuedAt` and payload `canonicalStateBytes(claims)` ([02](02-encoding.md#signing-actions)) |

## Verification

A verifier checks a PublishedAgent at one clock reading `now`, in this order; the first failure wins:

1. Shape: the closed objects and field rules above, including `ext`, `delegations` and `erc8004` shapes (`invalid_authorization`).
2. `kel` verifies and is usable at `now` ([01](01-identity.md#verifier-rules); `invalid_kel` / `invalid_signature`); `aceId` equals its ACE ID (`invalid_authorization`).
3. The signature verifies as an operational signature of that KEL, where signed while live also requires `issuedAt` to be at or after the `ts` of the delegating `dlg` ([01](01-identity.md#operational-signatures); `stale_peer_binding` / `invalid_authorization`).
4. Each delegation entry verifies ([§ Delegations](#delegations)). An entry that fails only because it has expired is dropped from the verifier's view; any other failure is `invalid_authorization`.

Every other invalid field invalidates the whole descriptor. Unknown members are invalid. Lookup results are always complete signed PublishedAgents, and directory entries complete signed CardBundles ([§ Card record](#card-record)); a client MUST verify each one and MUST NOT merge unsigned metadata into it. Peers pin descriptors under [01](01-identity.md#pinning). A verified descriptor proves who asserted its contents, not that they are true. A signer sets the `issuedAt` of a descriptor or card record to `max(now, ts of its last KEL event, issuedAt of its previous one + 1)`.

## Caching

A cached descriptor is bound to the KEL states it was verified under. A client uses it, to encrypt or to report its contents (delegations included), only while it is unexpired, its `kel` ends at the last event of the subject's current pin, and every delegation entry whose issuer the client has pinned still verifies under that pin ([§ Delegations](#delegations)). Otherwise it is stale: the client refreshes it and, if the refresh fails, reports that failure; it MUST NOT fall back to the stale descriptor. A delivery permit is presented only to relays named by a cached descriptor whose `kel` still ends at the subject's current pin (an expired one is fine), and only a permit that verifies under the issuer's current pin: a permit signed by a superseded key is never presented. A descriptor signed under a superseded key may name attacker-chosen relays, so it is refreshed only with the anonymous public lookup at its relays and the client's home relay. A newly verified descriptor replaces the cached one regardless of `issuedAt` only when the subject's KEL advanced (the cached one's `kel` no longer ends at the current pin). Under the same KEL a newer `issuedAt` replaces it, an equal `issuedAt` requires identical claims, and an older one never replaces it, even when the cached one is expired or stale through a delegation issuer's pin (no rollback). When an older candidate is refused, the client returns the cached descriptor only if it is usable, else it fails with `stale_peer_binding`.

## Prekey

`prekey.publicKey` is the canonical Base64 of a 1216-byte X-Wing public key ([03](03-packet.md#x-wing)); `prekey.id` is the lowercase hex SHA-256 of those 1216 bytes. A verifier recomputes the ID.

- An agent MAY rotate its prekey whenever it publishes a descriptor; the reference implementation rotates every 24 hours. Agents SHOULD NOT rotate more than `MAX_RETAINED_PREKEYS` times per `OFFLINE_WINDOW_SECONDS`.
- When a prekey is superseded, the agent keeps its seed for `OFFLINE_WINDOW_SECONDS` after the moment of supersession, then deletes it. It keeps at most `MAX_RETAINED_PREKEYS` superseded seeds, deleting the oldest first.
- A packet referencing a prekey the agent does not hold is rejected with `unknown_prekey` ([06](06-delivery.md#receive-pipeline)).
- Prekey seeds are secrets protected like identity seeds: in a key store readable only by the owner (file mode 0600) or sealed by hardware where available.
- A superseded prekey whose retention has ended MUST NOT open a packet, even when its seed has not been deleted yet. Implementations delete expired seeds whenever they open a packet or rotate, not only on publication.

SDK note: SDKs expose prekey storage as a `PrekeyVault` with `current()`, `rotate(now)`, `open(prekeyId)` and `prune(now)`.

The forward-secrecy window is the retention period ([06](06-delivery.md#security-considerations)).

## Card record

An agent states its durable identity facts in a **card record** and publishes it at its home relay, one of its descriptor's `relays`, as the closed **CardBundle** `{kel, card}`, whose canonical JSON is at most `MAX_PUBLISHED_AGENT_BYTES`. `kel` is the agent's complete KEL; `card` is the card record, a closed object whose canonical JSON is at most `MAX_CARD_RECORD_BYTES`:

| Field | Rule |
|---|---|
| `aceId` | The ACE ID of `kel` |
| `issuedAt` | Wire integer, `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS` |
| `home` | Canonical relay URL ([02](02-encoding.md#relay-urls)) of the relay that holds the record; `handle` belongs to its namespace |
| `handle` | Optional handle ([02](02-encoding.md#identifiers)); only with a `home` whose URL has no path, because a handle resolves at `https://host` |
| `card` | [§ Card](#card) |
| `pay` | Optional, 1–`MAX_PAY_ACCOUNTS` distinct CAIP-10 accounts ([02](02-encoding.md#identifiers)) at which the agent asks to be paid |
| `contact` | `open` or `closed`: whether the agent processes contact requests from strangers ([05](05-admission.md#flow)) |
| `listed` | Boolean: whether the agent appears in its home relay's directory ([07](07-relay.md#descriptors-and-cards)) |
| `signature` | Delegated signature, action `card-record`, with `aceId`, `timestamp = issuedAt` and payload `canonicalStateBytes(claims)` ([02](02-encoding.md#signing-actions)) |

A verifier checks a CardBundle at one clock reading `now`, in this order; the first failure wins:

1. Shape: the closed objects and field rules above, including both size bounds (`invalid_authorization`).
2. `kel` verifies and is usable at `now` ([01](01-identity.md#verifier-rules); `invalid_kel` / `invalid_signature`); `aceId` equals its ACE ID (`invalid_authorization`).
3. The signature verifies as an operational signature of that KEL, with `issuedAt` at or after the `ts` of the delegating `dlg` ([§ Verification](#verification) step 3; `stale_peer_binding` / `invalid_authorization`).

A card record does not expire: it stands until a newer `issuedAt` replaces it or the identity unregisters. A record signed under a superseded delegation fails step 3, so an agent re-signs its record after every `dlg`. A verified record proves who asserted it, not that it is true: a `pay` account is claimed, not proven to be controlled by the agent. An agent without a card record is treated as `contact: closed` and unlisted.

A client that has verified a card record for an identity MUST NOT accept one with an older `issuedAt`, nor one with an equal `issuedAt` and different claims (`stale_descriptor`). It keeps the highest `issuedAt` and the claims digest at it for each identity, durably, and checks them before the handle rule below.

A card record cannot be revoked by a newer one alone: a holder of the signing key can sign records, including `pay` accounts, until a new `dlg` replaces that key, and a client that has not pinned the identity's KEL accepts any record signed under a delegation within its `notAfter`. Revoking a `pay` account therefore requires a new `dlg`. A client SHOULD pin the identity's KEL, by looking up its descriptor ([§ Verification](#verification)), before relying on `pay`. When the descriptor lookup answers `unknown_peer` at every relay it asked (the identity has no live descriptor), a client MAY verify the card against the bundle's own KEL and pin that KEL under the same rules; it MUST surface that the KEL was not confirmed live. A transient or other failure at any relay asked MUST NOT trigger this fallback: the lookup fails instead. A KEL pinned this way is reported as not confirmed live, durably, until a live descriptor reconciled with the pin confirms it; until then the client looks the descriptor up again on each card lookup. Confirmed live means a relay served a verified descriptor under that KEL, not that the KEL is the identity's newest. A client MUST NOT present the `pay` accounts of a record whose KEL is not confirmed live as confirmed. A key holder can sign `issuedAt` up to `now + TIMESTAMP_WINDOW_SECONDS`, so after the `dlg` the owner's re-signed record can be refused as `stale_descriptor` for up to `TIMESTAMP_WINDOW_SECONDS`.

Every registered agent's unexpired descriptor can be looked up by ACE ID ([07](07-relay.md#descriptors-and-cards)); `contact` and `listed` decide only who may request contact and whether the agent is listed. A client looking up a card record by ACE ID asks the relays of the identity's descriptor in listed order until one serves it.

**Handles.** A handle is written `@name@host`, where `host` is the host (with its port, if any) of `home`, and the record member is the slug `name`. A handle is set once: an identity claims it with the first card record that carries it, and the relay of `home` binds it to that identity permanently, also after unregister; it is never reassigned or renamed. For as long as `home` names the same relay, every card record the identity publishes MUST carry the same `handle`. A record naming another `home` claims nothing at the earlier relay, whose binding stays; the handle there then resolves as `unknown_peer`. A client that has pinned a handle for an ACE ID at a `home` treats a CardBundle of that identity naming the same `home` with a different or missing `handle` as `invalid_authorization`. A client reading a handle address typed by a person MAY accept it without the leading `@` and in any ASCII case, lowercasing it before checking the grammar; records and requests carry only the canonical form. A client resolving `@name@host` queries `GET /v1/handles/{name}` at the relay of `host`, verifies the returned CardBundle and MUST check that its `home` is the relay it queried and its `handle` is `name`; otherwise the result is `unknown_peer`. The binding of `@name@host` to an ACE ID is trusted to the relay of `host`. Bindings are permanent, so a relay that resolves a handle to a different ACE ID than before has misbehaved detectably: a client MUST pin `(home, handle) → aceId`, durably, on its first resolution and treat a resolution to a different ACE ID as `invalid_authorization`. Contacts are saved by ACE ID; a handle only finds one.

## Card

The `card` member of a card record is a closed object; every member is optional:

| Member | Rule |
|---|---|
| `description` | At most 256 characters, no U+0000–U+001F or U+007F |
| `image` | ACE HTTPS URL ([02](02-encoding.md#https-urls)) |
| `tags` | At most 10 distinct strings matching `^[a-z0-9-]{1,32}$` |

The card carries what discovery needs and nothing that names the agent: a display name changes and is application data; the permanent handle is the protocol's human-readable identifier. Card contents are untrusted self-assertions. The tag `hosted` is reserved: it declares that a service holds the agent's keys. A hosted runtime MUST include it and MUST NOT allow its removal. No other tag has protocol meaning.

## Extensions

`ext` is an object whose keys are profile IDs listed in `profiles`, whose values are JSON objects, and whose canonical JSON is at most `MAX_EXT_BYTES`. A profile defines its own `ext` value: an official profile's chapter states the schema, which every verifier enforces ([profiles/commerce.md](profiles/commerce.md#descriptor-extension)); a key for an official profile that defines no `ext` is invalid. Values for third-party profiles are opaque objects. No `ext` value confers authority.

## Delegations

A delegation entry is the closed object `{kel, credential}`. It states one edge between two identities: **the issuer declares that the subject acts on its behalf.** It grants no execution, payment or communication right. The issuer is called the controller and the subject the delegate; there is no role enumeration. The issuer revokes by not renewing.

`credential` is the closed object:

```
{ issuer, subject, issuedAt, expiresAt, signature }
```

signed by the issuer with action `delegation`, `aceId = issuer`, `timestamp = issuedAt` and payload `canonicalStateBytes(claims)`. An entry is valid when, in order:

1. `issuer != subject`, `subject` equals the descriptor's `aceId`, `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS`, `issuedAt < expiresAt`, `expiresAt - issuedAt <= MAX_DELEGATION_LIFETIME`, and issuers are distinct across entries;
2. `kel` verifies and its ACE ID equals `issuer`; when the verifier has pinned the issuer, `kel` is reconciled with that pin under [01](01-identity.md#pinning) (a fork, or a carried prefix whose credential is signed by a superseded delegation, invalidates the entry) and the reconciled state is used from here on;
3. the signature verifies as an operational signature of that state;
4. `now < expiresAt` (otherwise the entry is expired and dropped).

## ERC-8004

An `erc8004` entry is the closed object `{agentRegistry, agentId}` binding the ACE identity to an ERC-8004 agent. `agentRegistry` is the CAIP-10 account of the registry (`^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$`, for example `eip155:8453:0x…`; any chain); `agentId` is the registry's chain-native agent identifier: when the registry's CAIP-2 namespace (the part of `agentRegistry` before the first `:`) is `eip155`, a decimal string matching `^(0|[1-9][0-9]{0,77})$` (the ERC-721 token ID); for any other namespace, 1–128 characters matching `^[A-Za-z0-9]{1,128}$` (for example a Solana base58 address). Entries are distinct.

The binding holds only when both directions hold: the signed descriptor names the on-chain agent, and that agent's registration file (its `tokenURI`) contains a service entry `{"name": "ACE", "endpoint": "<aceId>"}`. A registration file confirms the binding exactly when it is a JSON object whose `services` array contains an object with `name` equal to `"ACE"` and `endpoint` equal to the ACE ID. Reading the chain and the `tokenURI` is the host's task; the core contains no chain client. ACE defines no chain signature format.

SDK note: SDKs provide this check as the pure function `verifyErc8004Registration(registrationJson, aceId) -> bool`.

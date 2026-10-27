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
| `signature` | Delegated signature, action `agent-descriptor`, with `aceId`, `timestamp = issuedAt` and payload `canonicalStateBytes(claims)` ([02](02-encoding.md#signing-actions)) |

## Verification

A verifier checks a PublishedAgent at one clock reading `now`, in this order; the first failure wins:

1. Shape: the closed objects and field rules above, including the `ext` shape (`invalid_authorization`).
2. `kel` verifies and is usable at `now` ([01](01-identity.md#verifier-rules); `invalid_kel` / `invalid_signature`); `aceId` equals its ACE ID (`invalid_authorization`).
3. The signature verifies as an operational signature of that KEL ([01](01-identity.md#operational-signatures); `stale_peer_binding` / `invalid_authorization`).

Any invalid field invalidates the whole descriptor. Unknown members are invalid. Lookup results are always complete signed PublishedAgents, and directory entries complete signed CardBundles ([§ Card record](#card-record)); a client MUST verify each one and MUST NOT merge unsigned metadata into it. Peers pin descriptors under [01](01-identity.md#pinning). A verified descriptor proves who asserted its contents, not that they are true. A signer sets the `issuedAt` of a descriptor or card record to `max(now, ts of its last KEL event, issuedAt of its previous one + 1)`.

## Caching

A cached descriptor is bound to the KEL states it was verified under. A client uses it, to encrypt or to report its contents, only while it is unexpired and its `kel` ends at the last event of the subject's current pin. Otherwise it is stale: the client refreshes it and, if the refresh fails, reports that failure; it MUST NOT fall back to the stale descriptor. A delivery permit is presented only to relays named by a cached descriptor whose `kel` still ends at the subject's current pin (an expired one is fine), and only a permit that verifies under the issuer's current pin: a permit signed by a superseded key is never presented. A descriptor signed under a superseded key may name attacker-chosen relays, so it is refreshed only with the anonymous public lookup at its relays and the client's home relay. A newly verified descriptor replaces the cached one regardless of `issuedAt` only when the subject's KEL advanced (the cached one's `kel` no longer ends at the current pin). Under the same KEL a newer `issuedAt` replaces it, an equal `issuedAt` requires identical claims, and an older one never replaces it, even when the cached one is expired (no rollback). When an older candidate is refused, the client returns the cached descriptor only if it is usable, else it fails with `stale_peer_binding`.

## Prekey

`prekey.publicKey` is the canonical Base64 of a 1216-byte X-Wing public key ([03](03-packet.md#x-wing)); `prekey.id` is the lowercase hex SHA-256 of those 1216 bytes. A verifier recomputes the ID.

- An agent MAY rotate its prekey whenever it publishes a descriptor, and SHOULD NOT rotate more than `MAX_RETAINED_PREKEYS` times per `OFFLINE_WINDOW_SECONDS`.
- When a prekey is superseded, the agent keeps its seed for `OFFLINE_WINDOW_SECONDS` after the moment of supersession, then deletes it. It keeps at most `MAX_RETAINED_PREKEYS` superseded seeds, deleting the oldest first.
- A packet referencing a prekey the agent does not hold is rejected with `unknown_prekey` ([06](06-delivery.md#receive-pipeline)).
- Prekey seeds are secrets protected like identity seeds.
- A superseded prekey whose retention has ended MUST NOT open a packet, even when its seed has not been deleted yet. Implementations delete expired seeds whenever they open a packet or rotate, not only on publication.

## Peer prekeys

Besides its published prekey, an endpoint offers each peer a **peer prekey**: an X-Wing public key carried as `prekey` in every packet it sends that peer ([03](03-packet.md#private-content)), to which the peer encrypts its next first-attempt application message ([06](06-delivery.md#outbox-sender)). The endpoint that generated the key is its **issuer**; the peer that received it is its **holder**. Its ID is the lowercase hex SHA-256 of the 1216 bytes, as for a published prekey.

**Issuer.** Per peer, the issuer keeps at most two seeds: the *offered* key and the *in-use* key.

- The first packet to a peer generates its offered key; every later packet to that peer carries the same offered key until it is used or deleted.
- When a packet from the peer opens under the offered key, the issuer, before acknowledging that packet at its relay: deletes the in-use seed, makes the offered key the in-use key, and generates a new offered key for its next packet. A packet opening under the in-use key changes nothing.
- A seed, offered or in use, is deleted `OFFLINE_WINDOW_SECONDS` after the timestamp of the last packet that carried it as the offered key.
- A peer prekey opens only packets whose `from` is the peer it was offered to; any other packet referencing it is `unknown_prekey`.
- Seeds are protected like published prekey seeds and survive restarts. They are lost with the endpoint's state; the Outbox recovers ([06](06-delivery.md#outbox-sender)).

**Holder.** The holder keeps at most one key per peer.

- A packet that opened (step 6) and whose sender is pinned, at step 3 or by the recovery path ([05](05-admission.md#admission-recovery)), records its `prekey` as the held key for `from` when the packet's `timestamp` is greater than the held key's, bound to the pin state (the digest of the last pinned KEL event) it was authenticated under; duplicates at step 9 record too. A contact packet, and any packet whose sender has no pin when it is processed, records nothing.
- The held key is used only while the peer's pin is the one it is bound to and less than `OFFLINE_WINDOW_SECONDS` have passed since the timestamp of the packet that carried it. It is dropped when the peer is blocked and when a receipt `rejected:unknown_prekey` names it.

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
| `erc8004` | Optional, 1–4 distinct `{agentRegistry, agentId}`: `agentRegistry` a CAIP-10 account; `agentId`, when the CAIP-2 namespace of `agentRegistry` is `eip155`, a decimal string matching `^(0\|[1-9][0-9]{0,77})$`, otherwise a string matching `^[A-Za-z0-9]{1,128}$` |
| `contact` | `open` or `closed`: whether the agent processes contact requests from strangers ([05](05-admission.md#flow)) |
| `listed` | Boolean: whether the agent appears in its home relay's directory ([07](07-relay.md#descriptors-and-cards)) |
| `signature` | Delegated signature, action `card-record`, with `aceId`, `timestamp = issuedAt` and payload `canonicalStateBytes(claims)` ([02](02-encoding.md#signing-actions)) |

A verifier checks a CardBundle at one clock reading `now`, in this order; the first failure wins:

1. Shape: the closed objects and field rules above, including both size bounds (`invalid_authorization`).
2. `kel` verifies and is usable at `now` ([01](01-identity.md#verifier-rules); `invalid_kel` / `invalid_signature`); `aceId` equals its ACE ID (`invalid_authorization`).
3. The signature verifies as an operational signature of that KEL ([§ Verification](#verification) step 3; `stale_peer_binding` / `invalid_authorization`).

A card record does not expire: it stands until a newer `issuedAt` replaces it or the identity unregisters. A record signed under a superseded delegation fails step 3, so an agent re-signs its record after every `dlg`. A verified record proves who asserted it, not that it is true: a `pay` account is claimed, not proven to be controlled by the agent. An agent without a card record is treated as `contact: closed` and unlisted.

Like `pay`, an `erc8004` entry is claimed, not proven. The claim holds only when the registry's registration file for that agent (its `tokenURI`) is a JSON object whose `services` array contains `{"name": "ACE", "endpoint": "<aceId>"}`; reading the chain is the host's task and the core contains no chain client.

A client that has verified a card record for an identity MUST NOT accept one with an older `issuedAt`, nor one with an equal `issuedAt` and different claims (`stale_descriptor`). It keeps the highest `issuedAt` and the claims digest at it for each identity, durably, and checks them before the handle rule below.

A card record is revoked only by a new `dlg`: the signing key can sign records, `pay` and `erc8004` included, until a `dlg` replaces it ([06](06-delivery.md#security-considerations)). A client MUST NOT rely on `pay` or `erc8004` of a record unless it has pinned the identity's KEL from a live descriptor ([§ Verification](#verification)) and the record verifies under that pin; a client that looks a card up for that purpose therefore looks the descriptor up first and fails with the descriptor's error.

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

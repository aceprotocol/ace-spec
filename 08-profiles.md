# 08 — Profiles

A profile gives application meaning to private content. It is a versioned set of message types, each with a bounded data schema and an immutable digest. A profile never changes identity verification, admission, deduplication or delivery, and installing one never grants execution authority. There is no central catalogue: official and third-party profiles use the same mechanism.

## Installation and announcement

An endpoint installs a manifest only through its local management interface. Receiving a manifest, URI, descriptor or message MUST NOT install anything, and implementations never fetch schema references or run downloaded validators. The core profile is always installed. An agent lists each other enabled profile in its descriptor `profiles` as `{id, digest}` with the profile digest ([04](04-descriptor.md#fields)). Two endpoints share a profile only when ID and profile digest are both equal; an equal ID with another digest is incompatible.

Implementations MAY bound installed manifests. An endpoint MUST reject a manifest that defines a message type an installed manifest already defines.

## Manifest format

A manifest is the closed object `{id, messages}` whose canonical JSON is at most `MAX_MANIFEST_BYTES`. `id` and every message `type` are namespaced identifiers ([02](02-encoding.md#identifiers)); third-party manifests MUST NOT use the reserved `ace:` prefix. `messages` holds 1–32 closed objects `{type, schema}` with distinct types; each `schema` has `type: "object"`. An invalid manifest is `invalid_argument`.

### Schema dialect

`schema` is a bounded subset of JSON Schema, not a general interpreter. Each schema node is a closed object with `type` (one of `object`, `array`, `string`, `integer`, `boolean`, `null`), an optional `enum`, and only these type-specific keywords:

| Type | Keywords | Matches |
|---|---|---|
| `object` | `properties` (object, at most 64 names), `required` (distinct names present in `properties`), `additionalProperties` (boolean) — all three REQUIRED | A JSON object containing every `required` name, whose listed members match their schemas, and which has no other member unless `additionalProperties` is `true` (other members are then unchecked) |
| `array` | `items` (REQUIRED schema), `maxItems` (optional, ≥ 0) | A JSON array of at most `maxItems` elements, each matching `items` |
| `string` | `maxLength` (optional, ≥ 0, in code points) | A JSON string |
| `integer` | `minimum`, `maximum` (optional, inclusive, `minimum <= maximum`) | A JSON number whose value is an integer in `[-(2^53-1), 2^53-1]` and within the bounds |
| `boolean`, `null` | none | `true`/`false`; `null` |

All bounds are integers in `[-(2^53-1), 2^53-1]`. Schemas nest at most 8 edges below the root. `enum` holds 1–64 values, each matching the node without its `enum`; a value matches `enum` when its canonical JSON equals that of a member. A JSON `null` matches only a `null` schema: an optional member is omitted, never `null`. Unknown or inapplicable keywords, `$ref` and any loader or code are rejected.

## Digests

There is one digest algorithm, over canonical JSON ([02](02-encoding.md#canonical-json)):

```
profile digest = lowercaseHex(SHA-256(canonicalStateBytes(manifest)))
message digest = lowercaseHex(SHA-256(canonicalStateBytes({type, schema})))
```

The profile digest identifies a profile in descriptors and contact requests. The message digest is the `schemaDigest` of private content ([03](03-packet.md#private-content)) and binds its type. Changing any part of a manifest changes its digest; incompatible semantics SHOULD use a new versioned ID. A digest is an agreement identifier, not evidence that a service is trustworthy.

## Official manifests

The official manifests are the files in [`profiles/`](profiles/). Every SDK bundles these exact files and computes digests from them; they are exempt from the reserved-prefix rule.

| File | Profile ID | Profile digest | Announced |
|---|---|---|---|
| [core.json](profiles/core.json) | `ace:core:1` | `66f46d4b8951b75f98abae24a72ceffa173c4e27748d09be78b8d6382ddc8222` | never; always installed |
| [text.json](profiles/text.json) | `ace:text:1` | `48619350eaea46b2d60f7ce71fe55867e00c8dd081796b408fb6a95692b8b307` | when enabled |
| [delegation.json](profiles/delegation.json) | `ace:delegation:1` | `fc1653477df13c6c8be00d34ce4811d90365053c0afd2b858f90603eab474964` | when enabled |
| [commerce.json](profiles/commerce.json) | `ace:commerce:1` | `30583f0a1acd86ac5a217d706df1c27dc7caea5d4f2deed6112807679afab053` | when enabled |

| Message type | Message digest | Rules |
|---|---|---|
| `ace:receipt:1` | `a79fea8c61d30c484fdc9ba71fee310c612da84f84827fe2c4b2e99e5708d3e3` | [06](06-delivery.md#receipts) |
| `ace:contact:1` | `29fc76bbaa5a437aa068f823b1f2b2466c89fed6b2ea4b9cfa7c31cc80df15e9` | [05](05-admission.md#contact-requests) |
| `ace:text:1` | `e91541145d670369cf651d062e6bb8a94ce2605d4a9f2261ceef1d8a29c2e7da` | none: `{message}` plain text |
| `ace:delegation:1` | `4beba7c7640936f14d9eb90843726f6a53afc75c6798cb02fa914c09af5b24b1` | [delegation](profiles/delegation.md) |
| `ace:commerce:rfq:1` | `7b3fc71d8e538ff2f5ca0189d81feb237aa31e1f49787e951b90e9e17c1207d5` | [commerce](profiles/commerce.md) |
| `ace:commerce:offer:1` | `0fb206d333aa41734407402ce4e44157720c39a9ffc4325750ebfb8d0c7f8179` | [commerce](profiles/commerce.md) |
| `ace:commerce:accept:1` | `59e5e6fd0df886bab94d439f138cbaf1990c3af7cfe44484581c501d37e76c23` | [commerce](profiles/commerce.md) |
| `ace:commerce:reject:1` | `ad51a8ad82f9bdde6b2d7f709430836359b09be66b32cfe4d8352d8c84a8dff6` | [commerce](profiles/commerce.md) |
| `ace:commerce:invoice:1` | `4020571cb3dbbb4e104b13e5e37a54e1b426d989e101f5c3b3de49fc680739a5` | [commerce](profiles/commerce.md) |
| `ace:commerce:payment:1` | `33a1fde87d16bf5ad5d4387d73e0823ed14ccd15149f51bee938b54be8d95ff5` | [commerce](profiles/commerce.md) |
| `ace:commerce:deliver:1` | `ff1d8025af3f87eee33afb8d2d88452365c41c84b55bba13e96fbf94907b9fd2` | [commerce](profiles/commerce.md) |
| `ace:commerce:confirm:1` | `876f22d60311651917fb7aee630368b885b8378fa1d0ac9dd91b17a65d8800d7` | [commerce](profiles/commerce.md) |

A third-party example is [examples/translation-profile.json](examples/translation-profile.json).

## Profile rules

Rules that a schema cannot express (references between messages, state machines, embedded signed objects) are **profile rules**. A rule governs a set of message types and sees, for each message, the event `{direction: "send" | "receive", from, to, messageId, timestamp, type, threadId?}` (for `send`, `timestamp` is the time the Outbox entry was created) and the body. It has two steps:

- **check** runs on `send` before the Outbox entry is persisted (before encryption for receipts and contacts, which bypass the Outbox) and on `receive` at pipeline step 10 ([06](06-delivery.md#receive-pipeline)). It reads state only and fails with an ACE error whose code becomes the `rejected` receipt code.
- **commit** applies state changes, idempotently per `(from, messageId)`. On `receive` it runs inside the transaction that persists the delivery record; on `send`, as below.

### Sender state and busy threads

A message is **governed** when some installed rule lists its type. For a governed message with a `threadId`, the thread `(peer, threadId)` is **busy** while such a message from the local agent is pending in its Outbox. The sender:

1. runs `check` at enqueue; enqueueing another governed message on a busy thread fails with `thread_busy` before `check`, and nothing is stored;
2. runs `commit` only when the `delivered` receipt for the message arrives, so its state follows what the receiver applied;
3. changes no rule state on a `rejected` receipt; the thread is free again;
4. frees the thread without any state change when the message expires or is abandoned; the outcome is then unknown, and a late `delivered` receipt still runs `commit` ([06](06-delivery.md#outbox-sender)).

On receive, a governed message on a thread that is busy towards its sender is rejected with `thread_busy` at step 10, before `check`. When both parties send on one thread at once, both messages are therefore rejected and neither side's state changes; the parties then continue from the unchanged state. A message without a `threadId`, or of a type no rule governs, never makes a thread busy.

The core rules for receipts and contacts are always active. Rules for official profiles are optional modules ([commerce](profiles/commerce.md#threads)). The core pipeline contains no profile-specific branches.

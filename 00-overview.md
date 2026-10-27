# 00 — Overview and conformance

ACE (Agent Commerce Engine) is an open protocol for agent **identity**, **private communication** and a shared **vocabulary for economic interaction**. Every signature is ML-DSA and every packet is encrypted with the hybrid post-quantum KEM X-Wing.

ACE lets an agent state what it wants reliably, learn which interaction rules a peer supports, and exchange information securely. Choosing a counterparty, negotiating terms, deciding whether to trade and executing anything are decisions for agents and applications. ACE grants no execution, payment or shell authority.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

## Layers

| Layer | Contents | Requirement |
|---|---|---|
| Core | KEL identity ([01](01-identity.md)), encodings and signatures ([02](02-encoding.md)), packets ([03](03-packet.md)), descriptors with their optional Delegation and ERC-8004 members, and card records ([04](04-descriptor.md)), admission ([05](05-admission.md)), delivery and receipts ([06](06-delivery.md)), the relay HTTP binding ([07](07-relay.md)), profile manifests ([08](08-profiles.md)) | MUST implement |
| Official profiles | `ace:text:1`, `ace:commerce:1` ([profiles/commerce.md](profiles/commerce.md)) | Installed when needed; same mechanism as third-party profiles |
| Applications | Execution authorization, budgets, wallet approval flows, payment execution | Outside ACE |

A **profile** is a versioned set of message types with immutable schema digests. The core profile `ace:core:1` (receipts and contact requests) is always installed. Other profiles are installed by local configuration only; receiving a message, descriptor or manifest never installs anything.

## Objects at a glance

- A **KEL** (key event log) names an identity `ace:sha256:<hex>` and delegates its operational signing key.
- A **PublishedAgent** `{kel, descriptor}` announces relays, a current X-Wing prekey and enabled profiles. It is signed and lives at most 7 days.
- A **packet** is the only object exchanged between agents. It is encrypted to the recipient's prekey and signed by the sender. Its plaintext is private content `{type, schemaDigest, threadId?, body}`.
- A **CardBundle** `{kel, card}` carries the agent's card record: its permanent handle, card, payment accounts, whether strangers may request contact and whether it is listed. It is signed and does not expire.
- A **delivery permit** is signed by a receiver and lets one sender deliver to it.
- A **receipt** (`ace:receipt:1`) reports the receiver's outcome for one message. Contact requests (`ace:contact:1`) bootstrap admission.

## Conformance

A conforming endpoint implements every core chapter, including the receive pipeline in [06](06-delivery.md#receive-pipeline) in its stated order, and reproduces the shared vectors. A conforming relay implements [07](07-relay.md). Implementations MUST reject anything this specification does not define where an object is described as closed; they MUST NOT add fallbacks to other formats.

File layouts, language APIs and storage formats are not protocol requirements unless a chapter states otherwise.

## Trust boundaries

| Party | Sees | Trusted for |
|---|---|---|
| Endpoint (agent runtime holding keys) | Keys and plaintext | Everything it signs and decides |
| Relay | Registered KELs, published descriptors and card records, permits presented to it, blocks, packet metadata, IP addresses and timing ([06](06-delivery.md#security-considerations)) | Availability, and the binding of its handles to ACE IDs ([04](04-descriptor.md#card-record)). It cannot read private content or forge signatures; clients verify everything they receive from it and pin each handle's ACE ID on first resolution, so a changed binding is detected |
| Hosted MCP service | Keys and plaintext of the identities it hosts | It is a custodial endpoint. Hosted identities carry the `hosted` card tag ([04](04-descriptor.md#card)) |

Relays are replaceable: any operator can run the binding in [07](07-relay.md), and an agent chooses its relays in its descriptor. No relay, chain, wallet or central registry is required to join, discover or communicate.

Security properties and limits are stated once, in [06](06-delivery.md#security-considerations).

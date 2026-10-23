# Specification backlog

Not normative. Open work for future revisions.

- **One-time prekeys.** An optional extension publishing a batch of single-use X-Wing prekeys, narrowing the forward-secrecy window from prekey retention to a single message. Needs a relay-side claim protocol and exhaustion fallback.
- **KEL checkpointing.** A continuity proof that lets peers and relays verify a long-lived identity from a pinned head instead of the full log, lifting the `MAX_KEL_EVENTS` and `MAX_PUBLISHED_AGENT_BYTES` ceilings without deleting verified history.
- **Further signature schemes.** A scheme other than `ml-dsa-65` is added only by a revision; identities adopt it by committing a next root of that scheme at a rotation ([02](02-encoding.md#signatures)).
- **Signed-document ordering across a KEL advance.** Clients order cached descriptors by the KEL first and `issuedAt` only within one KEL state, but card records at clients, and descriptors and card records at relays, order by `issuedAt` alone. After a `dlg` that revokes a stolen key, a record the thief signed at `now + TIMESTAMP_WINDOW_SECONDS` blocks the owner's re-signed record for up to that window. One rule (a record under an advanced KEL replaces the stored one regardless of `issuedAt`) needs relays and the relay horizon to record the KEL state each stored record was accepted under.
- **Independent cryptographic review** of the complete composition (KEL, delegated signatures, prekey packet encryption, relay authentication) before the first release.
- **Recovering blocks after state loss.** Relays keep enforcing the blocks an endpoint registered, but an endpoint that lost its state cannot read them back ([05](05-admission.md#admission-recovery)). An authenticated `GET /v1/blocks` would let it restore its local block records.

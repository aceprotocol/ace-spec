# Specification backlog

Not normative. Open work for future revisions.

- **One-time prekeys.** An optional extension publishing a batch of single-use X-Wing prekeys, narrowing the forward-secrecy window from prekey retention to a single message. Needs a relay-side claim protocol and exhaustion fallback.
- **KEL checkpointing.** A continuity proof that lets peers and relays verify a long-lived identity from a pinned head instead of the full log, lifting the `MAX_KEL_EVENTS` and `MAX_PUBLISHED_AGENT_BYTES` ceilings without deleting verified history.
- **Further signature schemes.** A scheme other than `ml-dsa-65` is added only by a revision; identities adopt it by committing a next root of that scheme at a rotation ([02](02-encoding.md#signatures)).
- **Independent cryptographic review** of the complete composition (KEL, delegated signatures, prekey packet encryption, relay authentication) before the first release.

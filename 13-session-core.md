# Authenticated secure delivery and shared session core

ACE network clients use `SecureTransport` around their existing signed application envelope. TypeScript, Python and Swift implement the same four-frame handshake with one shared OpenMLS engine. ACE CLI, hosted MCP and SoulPass route network ingress through `SecureMailbox`; static application packets are rejected. Low-level `createMessage`, `parseMessage` and `Inbox.receive` remain application codecs, not the network security boundary.

Each application delivery uses a **fresh two-member MLS group**. This removes persistent secret snapshots, epoch synchronization and concurrent-commit merging from the delivery protocol. There is no legacy mode or automatic fallback. Both endpoints must explicitly allow the exact peer identity and the recipient must be online to complete the handshake. An unavailable recipient leaves the original Outbox operation pending.

## Separation of responsibilities

ACE authenticates agent identities and the exact setup transcript. MLS manages per-message secrets and epoch updates. Resource grants authorize application effects. An MLS credential containing an ACE ID is a label, not proof that the owner of that ACE identity enrolled the credential. An authenticated MLS message likewise does not authorize a payment, device enrollment or resource administration.

The common implementation uses [OpenMLS](https://github.com/openmls/openmls), pinned to 0.9.1, with its RustCrypto provider 0.6.0 and [RFC 9420](https://www.rfc-editor.org/rfc/rfc9420.html) ciphersuite 1: X25519, AES-128-GCM, SHA-256 and Ed25519. No draft post-quantum MLS suite is enabled. The existing outer X-Wing construction does not turn this suite into post-quantum forward secrecy or post-quantum identity authentication. The integration requires its own cryptographic review; using an upstream library is not a substitute for it.

Only two distinct ACE identities are admitted to a context. Each has a fresh MLS signing key, separate from its ACE identity key. The enrolled roster, credentials and signing keys are immutable within that context. Incoming commits may perform a pure self-update of the peer's HPKE material. Add, Remove, arbitrary proposals, PSKs, external joins, and changing enrolled signing identities are rejected. A device label, principal role or message type does not relax these checks.

## State and erasure

Secret state stays inside the Rust engine. There is no secret export, import, snapshot or resume operation. A restart requires a fresh context and fresh authenticated setup. Previously queued ciphertext cannot be decrypted by the fresh context; an application must resolve delivery and retransmit using its original stable operation ID. It must not create a second financial effect or silently downgrade to static application encryption.

Invalid inputs are evaluated on an internal transaction copy. Only successful transitions replace the active ratchet. Transaction copies never leave the engine. Rust heap allocations are overwritten before deallocation, including serialized in-memory storage rows; unused creator bootstrap key material is discarded. Secret-bearing endpoint structs use dedicated boxed allocations so container reuse does not retain an old inline provider RNG after removal. This is best-effort heap hygiene, not protection against live process inspection, VM snapshots, swap, stack temporaries, CPU registers, retained application plaintext or host-language copies of delivered plaintext.

Past epochs and resumption PSKs are not retained. The current epoch retains at most 32 skipped message keys per sender and refuses forward jumps greater than 128 generations. Delayed messages outside those bounds fail. Once an epoch changes, old-epoch messages fail. These bounds also apply to the low-level engine. The delivery profile never calls `update()` or reuses a group for another delivery, so it has no network epoch-update protocol or concurrent commit branch.

A compromised participant must generate and contribute fresh key material before recovery can exclude a passive copy of its old state. An update by only the other participant does not heal it. This does not promise recovery against an attacker still controlling the endpoint or the ACE identity key.

## Durable generation barrier

Every SDK context has a random local identifier and a non-secret metadata record at `mls/gates/<context>.json`. It includes the two ACE IDs, enrolled local MLS signature public key, monotonically increasing generation, version and closed state. It contains neither plaintext nor ratchet secrets. Keep it in the private operational state backend: publishing it would expose agent relationships and activity counters; it is not a public audit record. Context identifiers and engine handles are local references, never network credentials.

Each SDK serializes its calls and performs the following under a coordinated storage scope:

1. Compare the complete persisted record with the instance's expected record. A missing or changed record is a failure, not first use.
2. Check the engine's identity binding and generation against that same expected record. Never copy a newer persisted counter into an old engine.
3. Persist generation `n + 1` before invoking a transition at generation `n`.
4. Invoke the engine. A syntactically valid transition consumes its generation even when the ciphertext or MLS operation is rejected; the ratchet itself changes only on success.
5. Verify the engine now reports generation `n + 1`, and complete the storage scope before releasing any result.

A store error, lost write/release acknowledgement, unexpected engine failure or generation mismatch permanently closes the SDK context and deletes its in-memory engine state. An ordinary invalid ciphertext error is returned after the durable generation is consumed, without discarding otherwise valid ratchet state. There is no retry that rewinds a key or adopts a changed counter. Closing a context checks and deletes its gate before deleting live secret state; a missing gate is terminal, never first use. Failure still destroys the in-memory context. Completed contexts leave no permanent closed-gate tombstone.

This barrier prevents a stale client from using a context when the trusted external state has advanced. MemoryStore and FileStore cannot protect against rollback of the entire host. TypeScript and Swift can use the existing pinned EtcdStore. Python supports a scoped coordinated-store callback, but does not yet ship an etcd implementation. The same quorum trust and administrator limitations described in [resource grants](./10-resource-grants.md) apply. A lost acknowledgement deliberately sacrifices availability, including a produced but unreleased message, rather than continuing an uncertain session.

The generation barrier is **not a delivery journal**. The caller must persist authenticated application delivery before acknowledging it. Business operation IDs, execution reservations and nonce evidence remain necessary. No application should treat `PairwiseMLS.receive()` alone as exactly-once execution.

## Bounded interfaces

| Boundary | Limit |
| --- | --- |
| Engine plaintext (complete inner envelope in the delivery profile) | 40,000 bytes |
| Serialized MLS message | 48,000 bytes |
| Key package | 8,192 bytes |
| JSON engine command | 140,000 bytes |
| Endpoint storage after a transition | 4 MiB |
| Live endpoints per engine | 256 |
| Native engine instances | 64 |
| State generations / local endpoint handles | At most `2^53 - 1` |

The smaller plaintext limit leaves space for MLS framing, canonical Base64 and the generic ACE private-content wrapper. Limits are checked before applying a transition. Error responses are fixed codes and do not include decrypted data. The engine does not fetch schemas, peer records, code or cryptographic providers from the network.

Native callers supply valid pointer ranges and release each result buffer exactly once using the matching library function. The C ABI uses numeric engine IDs rather than engine pointers. Swift and Python adapters copy results before freeing and wiping the native buffer, validate ABI version 1, reject use after close and reject inherited native engines after `fork()`. An initialized native runtime must be followed by `exec()` in a forked child before it is used again. WASM is initialized explicitly from a trusted built artifact, with no crypto fallback.

## Normative delivery transcript

Every control frame is a signed, X-Wing encrypted ACE 2.0 private-content packet with type `urn:ace:secure-delivery:2`, no thread ID, and schema digest:

```text
SHA-256(UTF-8("ace.secure-delivery.v2:hello,offer,data,ack;fresh-pairwise-mls;exact-envelope;outcome-receipt;120s"))
```

The decoded frame is a closed object: unknown or missing members fail. All frames contain `kind`, `attempt` (32 random bytes, lowercase hex), `expiresAt` (absolute integer Unix seconds), `messageId` (the original application message UUID), and `digest` (the exact signed application envelope fingerprint from document 04). The identity-authenticated outer sender/recipient bind both sides. A received frame must have `now < expiresAt <= now + 120` and `expiresAt <= outer.timestamp + 120`.

| Frame | Additional members | Required checks |
| --- | --- | --- |
| `hello` | None | Locally admitted sender, bounded fresh attempt, exact application identity and digest commitment |
| `offer` | `nonce`, `keyPackage` | Echo the hello binding; receiver creates a fresh 32-byte hex nonce and single-use MLS key package; sender verifies the ACE signer and pending attempt before creating a group |
| `data` | `nonce`, `welcome`, `ciphertext` | Echo that offer nonce; receiver joins only the context that issued it; immutable two-member roster; decrypt and match the complete inner envelope's sender, recipient, message ID and fingerprint |
| `ack` | `nonce`, `ciphertext` | Same attempt, deadline, message and offer nonce; sender decrypts an MLS application message containing the exact receipt string below |

The key package, Welcome and MLS ciphertext use canonical Base64, bounded by the shared engine. ACE signatures cover the complete encrypted frame. The outer data signature therefore binds the Welcome and encrypted application to the authenticated sender; an old offer cannot select a fresh pending attempt. The receipt plaintext is exactly:

```text
ace.delivery.outcome.v1:<attempt>:<nonce>:<messageId>:<digest>:<outcome>
```

`<outcome>` is `delivered`, `duplicate`, or `rejected:<code>` where `<code>` is the receiver's permanent pipeline error code (`^[a-z0-9_]{1,64}$`). `delivered` and `duplicate` acknowledge the application operation. `rejected:<code>` tells the sender that the receiver's Inbox permanently refused the inner envelope: the sender reports `delivery_rejected` with that remote code, keeps the operation pending for the host to abandon, and never retries it automatically. A retryable receiver failure (storage, handler) produces no receipt at all: the attempt expires and the sender retries a fresh attempt. The receiver must run the original Inbox signature, replay, application-profile and durable callback checks before releasing this receipt. Receipt authentication proves that endpoint's acceptance under this contract, not payment execution, chain finality, honest remote software or user consent. Payment authorization and digest-bound execution receipts remain separate.

## Local admission and revocation

Communication admission defaults to deny. A trusted local administrative action enables a full ACE identity after identity verification. The admission row is read before the sender's identity is resolved or pinned: a frame from an unadmitted identity is dropped without any network lookup or peer-store write. Discovery, a profile role, a label, incoming text and remote schemas never enable a peer. SoulPass pairing and `msg peer allow/revoke`, ACE CLI `peer allow/revoke`, and MCP `ace_peer_policy` apply this local policy. They do not grant financial authority.

The private policy row binds version, peer, allowed state and a monotonically increasing generation. Every policy write advances the generation, including re-enabling. Sender snapshots are checked before data disclosure and after the receipt; receiver offers and prepared receipts bind their generation. Revoked attempts cannot be resumed after re-enabling. Receiver commit and policy mutation serialize on the same peer lock: a commit that acquired it before revocation may finish; revocation does not recall a committed message or an already released packet. Resource revocation is checked independently at the effect executor.

Key rotation updates the verified X-Wing binding, never the ACE signing identity or admission decision. Replacing an ACE signing identity requires new admission. There is no shared global controller role and no multi-device MLS group: fanout is one independent delivery per explicitly admitted identity.

## Crash, retry and concurrency

The original Outbox persists the signed application envelope and permanent operation ID. It is delivered over a fresh session on every attempt. The sender keeps no attempt journal: an interrupted attempt is abandoned and the next `deliver` starts a fresh one for the same operation. Only a verified MLS receipt allows the Outbox to acknowledge the application operation. Relay storage or an HTTP 200 alone cannot acknowledge it. A control-frame expiry remains a retryable handshake failure and never re-signs the application. Only an original envelope older than the default seven-day offline window is locally marked expired; any independent business deadline remains immutable.

The receiver persists an offer and retains its ephemeral keys only in memory. An offer surviving process loss cannot be reissued with replacement keys under the same challenge. After successful decryption it persists the exact inner envelope with a null outcome, invokes the idempotent Inbox callback while the group is still alive, encrypts the receipt for the callback's outcome (`delivered`, `duplicate` or a permanent rejection code), records outcome and receipt, destroys the group and only then releases the receipt. A replayed data frame for a completed attempt returns the same receipt. A crash between decryption and the recorded outcome ends that attempt: the group's secrets are never persisted, so the row stays at a null outcome and a replayed data frame is `session_closed`; the sender's attempt expires and its fresh attempt is deduplicated by the original Inbox. No ratchet key is ever used twice. If the attempt expired, the sender starts a fresh attempt for the same application operation, which the original Inbox deduplicates.

The journal is private and requires the same trusted durable backend as the host's messaging state. Failed writes or uncertain lock release fail closed. Receipt expiry bounds retry records; expired receiver records are swept during receive activity. Completed context gates are deleted. No secret session snapshot is stored. Application plaintext, original Outbox ciphertext and private Inbox logs have their own retention policy and can remain readable after endpoint compromise.

Incoming operations serialize locally and hold a peer policy lock through durable handover. Callbacks must persist/enqueue work rather than synchronously wait for another network response. Senders never hold a peer lock while awaiting a reply. Mailbox responders always send their offer/receipt through the relay; direct requests may use an advertised endpoint. This avoids two simultaneously receiving endpoints waiting for each other's direct receive lock. A sending process can read replies with an independent non-destructive cursor while another process owns the application receiver. Only the receiver advances its durable mailbox cursor.

There are at most 32 incoming and 32 outgoing attempts per transport, 1,024 live receiver journal rows, and a 120-second handshake lifetime. The **entire original signed application envelope** must fit in the engine's 40,000-byte plaintext bound; this is not a 40 KB body allowance. Split larger content into application-level references/chunks with explicit digest and authorization rules. HTTP adapters must apply bounded network timeouts and cancellation. Python's synchronous exchange callback cannot be forcibly interrupted by the transport. A short-lived MCP receive call may wait to finish an offer it issued, up to the handshake deadline; otherwise destroying its keys would make every such delivery fail.

## Security claims and release boundary

After both ephemeral contexts are erased, later compromise of static ACE identity/X-Wing keys alone does not decrypt captured past application deliveries under the classical MLS assumptions. It can expose outer control frames and traffic metadata. This is not post-quantum forward secrecy or post-quantum authentication. Fresh groups limit exposure between attempts, but do not recover trust from an attacker retaining an identity signing key or control of an endpoint. Stored application plaintext, inner Outbox envelopes, host snapshots and backups are outside this network-capture claim.

The shared provider and the complete ACE/MLS composition, native ABI, erasure model and failure recovery still require independent cryptographic review before production release. Passing implementation tests is not that review. Release artifacts must be built from reviewed, pinned source and verified in their target environments; local checksums detect packaging mismatch but are not provenance attestations.

## Evidence and source build

Component tests cover two-way communication, reordered messages, bounded skipped keys, replay/tamper rejection, old-epoch erasure, missing/stale generation state, lost storage acknowledgements, immutable membership, limits and restart without secret import. Python rejects inherited native runtime use after fork.

Two live harnesses exercise TypeScript/WASM, Python/native and Swift/native: `tests/interop.mjs` checks MLS primitives; `tests/secure_interop.mjs` runs all six directed ACE-authenticated hello/offer/data/ack combinations with original Inbox verification. Network and application tests cover concurrent bidirectional traffic, static downgrade refusal, malformed frames, stable operation IDs, rejected-envelope receipts, restart without receipt replay, handler failure, and revoke/re-enable. Build and verification commands are in [the ace-session-core repository](https://github.com/aceprotocol/ace-session-core#readme).

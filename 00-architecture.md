# ACE architecture and release boundary

ACE provides agent identity, authenticated private communication and resource-scoped delegation. SoulPass is a financial application agent using those same interfaces. A resource's issuer administers it and grants narrower rights to a subject ([10-resource-grants.md](./10-resource-grants.md)); the principal roles `controller` and `delegate` ([09-principal.md](./09-principal.md)) describe who approves and who acts within one account. Both are relationships in policy, not global identity classes, message categories or product privileges.

The source workspace implements the layers below. The protocol is pre-release: there is one current format and no compatibility mode. Source tests and local builds establish the exercised behavior; independent cryptographic review and deployment verification remain release requirements.

## Boundaries

| Layer | Responsibility | What it does not establish |
| --- | --- | --- |
| Identity | Signing keys, full ACE ID, signed encryption-key bindings and rotation barriers | Trust in descriptions, vendor names, model output or self-declared roles |
| Communication | Generic private content, authenticated fresh MLS delivery, local peer admission, durable receipts | Execution authority, payment success or user consent |
| Application schema | Namespaced type plus immutable schema digest; installed deterministic validation | Permission to fetch code, execute unknown schemas or obey incoming text |
| Resource authority | Trusted issuer, attenuated grants, epochs/revocation, atomic budgets, exact intent and one-time release | Global safety from a copied local balance or an untrusted storage administrator |
| Financial executor | Exact sponsored Solana/EVM effect, durable nonce/evidence, read-only reconciliation | Finality from a relay acknowledgement or transaction hash alone |
| Optional audit | Salted commitments, Merkle proofs, checkpoints and witness verification | Automatic publication, metadata anonymity, proof of user consent or payment execution |

## Identity and extensible private content

ACE 2.0 exposes only the routing and verification envelope. Application type, schema digest, thread, body, correlation and grant references are encrypted. All SDKs support plain text and structured custom schemas. Unknown schemas remain data; they cannot select executable code, modify policy or authorize an effect. No wallet is needed for basic identity or communication.

First contact requires a signed encryption-key binding. Peer stores retain the newest verified binding and issuer-scoped principal horizon independently of their disposable cache. Missing records, role descriptions and cache removal cannot silently replace that trust. The local horizon is not a global revocation service.

Commerce and same-account coordination are explicitly installed application profiles. The generic pipeline does not derive authority from `request`, `decision`, `controller`, a shared account string or an LLM's interpretation of text. SoulPass's generic receive path has no chain-role polling or account-affiliation gate.

## Authenticated delivery

[Secure delivery](./13-session-core.md) wraps the original Outbox envelope in a fresh two-member MLS group. TypeScript, Python and Swift use one pinned OpenMLS engine through WASM/native bindings. The hello/offer/data/ack transcript binds the verified ACE identities, random attempt and receiver nonce, exact application message ID and fingerprint, MLS setup and key confirmation. Every incoming peer requires explicit local admission; discovery never grants it.

A new group for every attempt removes persistent ratchet snapshots, session restoration, network epoch ordering and concurrent-commit recovery. Group secrets never leave the engine. Completed context gates are deleted; missing or changed gates fail closed. Revocation advances the peer's policy generation, so re-enabling cannot revive an unfinished old attempt. This policy is separate from resource-grant revocation.

All ACE CLI, MCP and SoulPass network receive paths use `SecureMailbox`. There is no fallback to a static application packet. The original Inbox handles validation, profiles, durable callbacks and deduplication after MLS authentication. Receivers journal the inner envelope and prepared receipt before handover, then release the receipt only after commit. A crash or lost receipt retries the same original operation over a fresh group. Relay storage or direct HTTP acceptance alone does not complete a send.

Both peers must be online for a handshake, bounded to 120 seconds. Limits include 32 concurrent incoming/outgoing attempts per transport and 40,000 bytes for the complete inner signed envelope. Replies use the relay even when requests arrive directly, avoiding simultaneous direct-request deadlocks. A sender can independently read replies while another process holds the receive lock. Short-lived MCP receive calls finish offers they issue before releasing their keys, subject to the handshake deadline.

After ephemeral state erasure, later theft of static identity/encryption keys alone does not decrypt captured past application deliveries under classical MLS assumptions. This claim excludes stored plaintext, private application logs, original Outbox envelopes and host snapshots. X-Wing's hybrid KEM does not make the classical MLS suite or identity signatures post-quantum. There is no claim of recovery from an attacker retaining an identity signing key or ongoing endpoint control.

## Resource-scoped authorization

[Exact-intent capabilities](./10-resource-grants.md) bind issuer, subject, executor/audience, resource, actions, typed constraints, validity interval, grant ID, policy epoch and bounded parent chain. Verification begins at a locally configured authority; every delegation must narrow rights. Unknown critical constraints fail closed. All three SDKs share validation and adversarial vectors.

An effect requires a typed immutable intent and a valid grant. The intent binds the actual executor and effect, absolute deadline and permanent operation ID. Human approval binds the same canonical digest. Re-signing transport cannot extend a request deadline or change an already-bound intent.

TypeScript and Swift `ExecutionAuthority` coordinators reserve all profile-derived budget dimensions atomically and consume a one-time signature-release gate after rechecking current epoch, revocation and deadline. The authoritative state is shared across executors. A stale or unavailable quorum must stop execution; copied per-device budgets are not an alternative.

Private FileStore uses kernel locks, permanent lock inodes, no-follow opens and directory synchronization. It is suitable only within its documented single-host trust model; whole-host rollback is outside that model. TypeScript/Swift EtcdStore pins a cluster identity and fences every access using the current lock token. Tests cover races, lease loss, lost committed responses, real snapshot restore and cross-SDK release. Hosted MCP's Redis lease fencing protects receive ownership; asynchronous Redis failover is not authoritative financial storage.

## SoulPass financial execution

[The financial profile](./12-soulpass-payments.md) binds account, chain, canonical asset, integer base-unit amount, recipient, fee ceiling, absolute deadline and operation ID. Pairing admits communication and proposals only. Every autonomous payment additionally requires an explicit resource grant; human-approved payments bind the reviewed typed effect.

Human and delegated adapters use one `AgentPaymentProfile`. Solana and EVM execution enforce the exact sponsored transaction and never fall back to self-paid gas, deployment or re-signing an unresolved attempt. Nonce bindings and recoverable evidence are durable before simulation or any other signature disclosure. Current policy/deadline are checked again immediately before release, including after storage waits. Sponsor refusal cannot erase evidence of a reusable authorization.

Submission, confirmation, refusal and unknown outcome remain distinct. Recovery reconciles the existing operation against its exact effect and chain finality before further action. A confirmed payment still needs a digest-bound execution receipt even when its request deadline has since elapsed. A communication receipt is never such a payment receipt.

## Optional public ledger

[Audit APIs](./11-audit.md) produce fresh-salted commitments, inclusion/consistency proofs and signed checkpoints. Durable log/witness services and explicitly configured witness quorums are implemented. Publication is opt-in and does not gate private communication. No on-chain anchoring or automatic publication is enabled.

A public ledger should contain minimal commitments or batched roots. Private statements can be selectively disclosed with proofs. Do not publish peer IDs, grant contents, payment types, correlation IDs or private operational journals by default. Encryption does not hide packet sizes, timing, endpoints or on-chain transactions. An append-only root proves publication order under its consensus assumptions, not the completeness or truth of undisclosed events.

## Verification and release requirements

The repository includes shared byte-level vectors; TS/Python/Swift message interoperability; a common MLS engine harness; all six directed authenticated-delivery SDK combinations; real CLI/MCP/SoulPass network tests; and adversarial replay, tamper, downgrade, revoke/re-enable, storage-failure and recovery tests. Financial tests separately exercise concurrent budgets, stale authority, lost responses, nonce/evidence journaling and no duplicate effect after restart. See the reproducible commands in [the ace-session-core repository](https://github.com/aceprotocol/ace-session-core#readme).

Independent cryptographic review of the complete composition remains a production-release gate. Release CI must pin coherent reviewed SDK/spec/application commits and build native/WASM artifacts from those sources; local checksums alone are not provenance attestations. Deployment requires the chosen quorum's operational and lost-quorum recovery procedures. Optional public audit deployment or on-chain anchoring is an application choice, not missing machinery needed for ordinary private messaging. No service, payment, public log or on-chain anchor was deployed as part of this implementation.

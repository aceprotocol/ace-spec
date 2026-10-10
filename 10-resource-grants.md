# Exact-intent resource grants

Communication authenticates a speaker. Execution requires a capability rooted in the executor's locally configured resource authority. Account affiliations, product names, message types, schema URLs, text and model outputs never establish that authority. An issuer is an authority for a resource; a subject receives a capability from it. The same identity can fill different roles for different resources.

The minimal grant authorizes **one exact intent**, not an extensible policy language. Standing allowances belong in the resource authority's installed application policy. That authority evaluates the allowance and issues an exact grant. This avoids interpreting arbitrary sender-provided predicates or partially enforcing an unfamiliar restriction. No schema URL is fetched during verification.

## Intent

The closed object has exactly these members:

| Member | Meaning |
| --- | --- |
| `operationId` | UUIDv4, permanent effect identity within the resource |
| `audience` | Exact executor ACE ID |
| `resource` | Namespaced resource identifier; no wildcard |
| `action` | Namespaced action identifier; no wildcard |
| `schemaDigest` | 64 lowercase hex digest of the installed action profile |
| `details` | JSON object containing the complete effect and all constraints |
| `expiresAt` | Absolute Unix second; no new authorization release at or after it |

Hash using the cross-SDK operation digest from document 06. The entire object is bound, including recipient, fees or any other profile fields. JSON is limited to depth 32 and 60,000 UTF-8 bytes. Every object field name in an execution intent must already be Unicode NFC; verifiers reject other spellings rather than normalizing signed data. Text values retain their exact bytes. Numbers in details follow the cross-SDK binary64 rules; integer financial amounts should be strings. The installed profile derives all worst-case resource costs from the signed effect. There is no caller-provided `units` or `charges` field: duplicating an amount or fee outside its authoritative details creates two competing interpretations. A token symbol, floating-point balance or caller-chosen cost estimate is insufficient.

## Grant and delegation

A grant is the closed object `{claims, signingPublicKey, signature:{scheme,value}}`. `signingPublicKey` is canonical padded Base64. Claims have exactly:

```
{grantId, issuer, subject, audience, resource, intentDigest,
 issuedAt, expiresAt, epoch, parent, delegationDepth}
```

IDs are UUIDv4 for `grantId` and ACE IDs for issuer, subject and audience. Timestamps and epoch are nonnegative safe integers; `issuedAt < expiresAt`. Parent is null for the root, otherwise the 64-hex operation digest of the parent's **claims**. Signature randomness cannot change a parent reference. Delegation depth is an integer 0–7. Sign with the normal ACE signing construction, action `grant`, ACE ID `issuer`, timestamp `issuedAt`, and payload `encodePayload(claimsDigest)` where the digest is a lowercase hex string.

Verification takes a root-to-leaf chain of 1–8 grants, the exact intent, authenticated sender, local executor, current resource policy and local time. Reject unless:

1. All objects are closed, IDs and integers are valid, and every signature verifies with a key deriving its claimed issuer ACE ID.
2. The root key and algorithm equal the locally trusted authority, with null parent. The request cannot supply this trust root.
3. Every grant binds the same intent digest, audience, resource and current policy epoch, is currently valid, covers the intent deadline, and is not revoked. Grant IDs cannot repeat.
4. Each child links the parent's claims digest and is signed by its subject. Its validity interval is within the parent's and its delegation depth is strictly smaller.
5. The final subject equals the authenticated requesting agent. The intent's audience equals the actual executor.

A child therefore cannot change the effect, resource, executor, expiration or any field from which resource costs are derived. Unknown fields are rejected rather than silently discarded. Pure chain verification is **not** proof of current revocation state, budget availability or execution completion.

## Private execution request

The optional generic extension `urn:ace:execute:1` carries the closed body `{intent, grants}`. Its exact UTF-8 schema descriptor is:

```json
{"fields":["intent","grants"],"type":"urn:ace:execute:1","version":1}
```

Use SHA-256 of those bytes as `schemaDigest`. All three SDKs expose this descriptor/digest and a bounded parser. The wrapper is limited to 60,000 UTF-8 bytes and 1–8 grants. Unknown fields are rejected. Parsing confers no permission and does not install a profile or validate a grant. Only the executor's installed action profile and authoritative current policy can release an effect.

The intent's operation ID persists across retransmission in different ACE message IDs. The authenticated message sender must equal the leaf grant subject. A financial, storage or other agent may use the same wrapper; neither the type label nor an advertised principal role changes its rights. Type, schema, intent and grants remain inside the ordinary encrypted packet.

## Authoritative reservation

The TypeScript and Swift SDKs provide `ExecutionAuthority`, a reference coordinator backed by scoped `CoordinatedStore` / `ACECoordinatedStore` state access. Provision it explicitly with a trusted resource authority, executor, installed schema digest, allowed actions, deterministic synchronous profile validator and a map of integer budgets. Each map key is a namespaced accounting dimension (for example a canonical asset ID); each value is a canonical decimal integer string, `0` or 1–78 digits without leading zeros. Maps contain 1–32 dimensions. Dimensions are chosen by installed policy, never added from request metadata. All devices and agents using this resource must reach the **same** authority state; copying a FileStore to each device creates separate budgets and is invalid deployment.

Under one exclusive lock, reservation loads the current policy epoch and revocations, verifies the chain and installed profile, checks the permanent operation binding, derives the complete charge map, checks every dimension and durably commits all budget deductions together. An unknown dimension fails even when its proposed cost is zero. Insufficient fee budget rejects the entire reservation without deducting the payment amount. Changing an operation's intent or sender is rejected. Concurrent retries produce one `reserved` result and subsequent `existing` results. Concurrent distinct operations cannot exceed any stored budget. The profile returns costs synchronously; asynchronous or malformed results fail closed. The implementation rehashes the intent after validation to reject a profile that changes signed claims. An acknowledged durable write precedes the first result.

Only a new `reserved` result permits starting an effect. `existing`, a lost response or a crash require reconciling the executor's durable journal. Never automatically repeat an effect or refund an uncertain reservation. Immediately before the first signature or effect leaves the executor, `release` rechecks the current epoch, revocations, grant chain and absolute deadline under the same lock, then durably consumes a one-time release flag. Simulation of a transaction containing a usable signature is already authorization release. The deadline is checked again after durable writes and lock release, which may wait on a quorum. Crossing the deadline consumes the operation but refuses disclosure. A second release is rejected, including after restart or a lost write acknowledgement. Revocation and epoch changes serialize with both reservation and release; they cannot undo a signature already released. Time expiration alone cannot establish that a transaction was never broadcast. This deadline bounds authorization disclosure, not chain inclusion: an already released transaction follows its chain-specific signed validity window. `hasReservation` can read the exact authenticated sender/intent binding after grant expiry or revocation without releasing any permission.

Revocation and epoch methods are trusted administrator APIs. The generic SDK does not infer administrator rights from messages. SoulPass provides an opt-in private ACE execution endpoint described in document 12. It executes the effect at the authoritative host and returns evidence, not a transferable reservation or signing permit. A network adapter must authenticate clients, bind their verified identities and protect administrator operations. Production replication requires linearizable storage and rollback protection. The reference FileStore provides single-host persistence and exclusion, not distributed consensus or rollback-proof backups. Authority files contain private authorization metadata and must not be published as audit records.

Operations use independent permanent records, avoiding a bounded monolithic operation table or history scans on each reservation. A write-ahead record is durable before the operation record and updated budget head are written; every request recovers incomplete writes under the same lock before checking policy. An uncertain write can consume a reservation without releasing permission; retry returns `existing` and must reconcile. Revocations remain bounded to 10,000 per epoch; reaching that bound rejects changes until an explicit epoch advance. Epoch changes retain every budget and operation binding; provisioning refuses an existing namespace.

## Replicated authority backend

`EtcdStore` in TypeScript's `@ace-protocol/sdk/node` and Swift's `ACE` implements the scoped state interface using a trusted etcd v3 quorum. This is an optional executor implementation, not an ACE wire-protocol dependency. Other vendors can use another backend with the same linearizability, durability and fencing guarantees. `coordinate(name, body)` gives the callback a data handle bound to that exact lock acquisition; callers must not retain it or detach work. The replicated handle becomes invalid when the callback ends. All authority operations and SoulPass payment/nonce journals use scoped access. `FileStore` remains a local implementation; it does not gain quorum or rollback guarantees from implementing this interface.

Each acquisition uses an etcd lease and a random lock value. Every read, write, delete and list page is an atomic transaction that compares that value against the live lock. Reads are linearizable, and list pagination pins one revision. An expired or revoked lease cannot be renewed by a stale callback or used to overwrite a successor. Unlock compares the same value, so it cannot delete a replacement lock. The default lease is 60 seconds without renewal: finite authority critical sections must complete within it. This backend does not implement long-lived Inbox locks.

An uncertain response, unavailable quorum, changed cluster identity or lost lock permanently disables that client instance. Create a new instance only to resume from authoritative state and reconcile effects; never treat reconnect as permission to execute an old operation. A release that committed but lost its response remains permanently consumed. WAL recovery uses the same fenced scope; no cached head, local fallback, automatic refill or new namespace is used on errors.

Operator configuration pins one HTTPS origin, namespace and decimal `clusterId`; HTTP is restricted to numeric loopback for local tests. Redirects are refused, requests time out, responses are bounded, and credentials are local configuration only. Protect the private namespace with least-privilege etcd authentication/authorization and trusted TLS termination. Data lives under `/ace/<namespace>/data/`, locks under `/ace/<namespace>/locks/`; neither may be exposed through the public audit service. etcd's request-size/quota limits must accommodate the installed profile's bounded records. Capacity errors stop the operation rather than truncating history. Authority records are at most 1 MiB; the generic store's 64 MiB ceiling does not override server limits.

The quorum is the trust root for current state. Restoring a stale client disk does not restore its budgets because there is no local authority cache. Standard etcd snapshot restoration creates a new cluster identity and is refused by the pinned client. **Never automatically discover or update that pin after recovery.** A coordinated rollback of the entire quorum that preserves its identity, malicious storage administration, stolen write credentials, or rollback of both state and the operator's trust configuration is outside this guarantee. Recovering a lost quorum requires a separately reviewed reconciliation and reauthorization procedure before signing resumes; this implementation does not provide one. Changing a namespace or pin is not recovery. Replication does not erase local plaintext or provide forward secrecy.

The integration suite starts three isolated local etcd processes. It covers concurrent reservations across quorum members, exactly one release, lease revocation, stale-owner writes, quorum loss/restart, lost committed responses, real snapshot restoration, and TypeScript-to-Swift reservation/release interoperability. From `sdk-ts`, set `ACE_ETCD_BIN` to the verified etcd executable, with `etcdctl` and `etcdutl` beside it, and run:

```sh
ACE_ETCD_BIN=/path/to/etcd ACE_SWIFT_INTEROP=1 npx vitest run tests/etcd-store.integration.test.ts
```

The Swift sibling checkout is required for the cross-language test. Ordinary SDK test runs skip external-service cases when these variables are absent; a skipped suite is not replication validation.

## Implementation boundary

All three SDKs create and verify grants and share valid and invalid byte-level vectors. The TypeScript and Swift coordinators test concurrent reservations across multiple budget dimensions, fee exhaustion without partial deduction, restart at every durable write boundary, revocation, epoch changes, unsupported profiles, changed intents and lost acknowledgements. SoulPass shares one deterministic payment profile between human consent and its opt-in delegated Solana/EVM executor. The CLI includes local authority administration and an ACE message service. Solana and EVM autonomous execution and an optional etcd authority backend are implemented. Document 09's optional account coordination receive filter remains an affiliation filter, never a substitute for this execution boundary.

For financial execution, derive principal and worst-case fee charges separately when they use different assets, and add them when both use the same asset. Reserve the fee ceiling before submission; do not refund an uncertain transaction automatically. The generic coordinator does not implement asset identification or fee estimation itself. A profile must validate the actual execution plan against the signed details before releasing an irreversible operation.

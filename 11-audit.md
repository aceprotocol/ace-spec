# Optional private audit

Audit is independent of delivery and authorization. All three SDKs expose salted commitments, Merkle tree construction, inclusion and consistency verification, and signed checkpoints. They never publish data or trigger an effect automatically.

## Private statements and openings

For exact statement bytes `statement`, generate a fresh secret 32-byte cryptographic random `salt`:

```
commitment = SHA256(UTF8("ace.audit.commitment.v1\0") || salt || statement)
```

Keep both the salt and statement private. Each publication needs a new salt, including repeated identical statements. Publish only the 32-byte commitment or a batch root. Unsalted hashes of short text, amounts or identifiers permit guessing. A commitment to encrypted packets should not be replaced by publishing the packets: long-lived public ciphertext archives increase exposure to later key compromise.

Intentional disclosure supplies the exact statement bytes and salt plus an inclusion proof. The verifier recomputes the commitment, verifies inclusion against a trusted checkpoint, then independently verifies the disclosed statement's signatures and semantics. Inclusion is not consent, proof of payment, or proof that all relevant events were disclosed.

## Merkle tree

Use the SHA-256 construction and proof ordering in [RFC 9162, section 2.1](https://www.rfc-editor.org/rfc/rfc9162.html#section-2.1):

- Empty root: SHA256 of zero bytes.
- Leaf: SHA256(`0x00 || commitmentBytes`).
- Node: SHA256(`0x01 || leftHashBytes || rightHashBytes`).
- Split a nontrivial range at the largest power of two strictly smaller than its size.

Public hashes are 64 lowercase hex characters. Proof verification accepts safe integer sizes up to 2^53−1, consumes every proof node exactly, and rejects malformed, truncated or excess proofs. Proof length is at most 54 nodes. Inclusion uses a zero-based index. Consistency binds the old prefix root to the new larger tree; decreasing size is invalid. Equal sizes require identical roots and an empty proof. Size zero requires the specified empty root.

The in-memory reference builder accepts at most 65,536 commitments and owns an immutable copy. It is a bounded builder, not a durable log service.

## Signed checkpoint

The closed wire object is:

```
{logId, size, root, timestamp, signer, signature:{scheme,value}}
```

`logId` is a UUIDv4 identifying the log, `size` and `timestamp` are safe nonnegative integers, and `signer` is its operator's ACE ID. Sign using ACE action `audit`, ACE ID `signer`, the checkpoint timestamp, and `encodePayload(logId, decimal(size), rawRootBytes)`.

The verifier requires a **locally trusted operator key**. Do not accept a key merely because the checkpoint names it. When a prior checkpoint exists, verify both signatures, equal log ID, nondecreasing timestamp and a valid consistency proof. Persist accepted checkpoints durably before reporting acceptance. An operator key change requires a separate trusted policy update.

A client retaining its checkpoint rejects a conflicting view, shrinkage or non-prefix growth. Clients must exchange checkpoints or consult witnesses to detect an operator serving isolated, individually consistent forks. A valid timestamp is a signed operator claim, not independent evidence of freshness.

## Independent witnesses

The checkpoint claim digest is the 32-byte output of its ACE signing construction above, encoded as 64 lowercase hex characters. It does not hash the signature bytes: randomized signatures over identical claims identify the same checkpoint.

A witness receipt is a closed object:

```
{logId, operator, checkpointDigest, timestamp, witness, signature:{scheme,value}}
```

The operator and witness are distinct ACE IDs. The witness signs ACE action `audit-witness`, its own ACE ID, its observation timestamp, and `encodePayload(logId, operator, rawCheckpointDigestBytes)`. The observation timestamp is a safe nonnegative integer no earlier than the checkpoint timestamp. Verify the checkpoint and receipt against separately configured trusted operator and witness keys. A named key in the response does not establish trust. Unknown fields, signature-scheme substitution and mismatched claim digests fail verification.

A witness starts from an explicitly provisioned trusted checkpoint. For each subsequent checkpoint it verifies the operator signature, log ID, nondecreasing timestamp and append-only consistency against its durable horizon. Equal size requires the same root; a later signed time is allowed. It atomically persists the accepted checkpoint and signed receipt **before releasing the receipt**. Missing or corrupt state fails closed and cannot be reset by an HTTP request. Repeating identical claims returns the same durable receipt. Run witnesses under independent administration, keys and storage; multiple keys held by one operator do not establish independence.

Clients configure a fixed witness set of size `N` (1–32), a maximum `f` faulty witnesses and threshold `q`. Require `q <= N-f` and `2*q > N+f`; for example, 3 of 4 with at most 1 faulty witness. Count each configured witness once, exclude the log operator, and reject unknown or duplicate receipts. Honest quorum intersection prevents accepting incompatible prefixes while the stated fault bound and witness persistence hold. A policy change needs separately trusted coordination; responses cannot choose a weaker policy or replace the witness set.

Both checkpoint and receipt times must satisfy the client's configured maximum age and future skew against its own trusted clock. An explicit operator heartbeat can refresh the signed checkpoint time without appending an event, after which witnesses can attest the new claims. Old receipts do not refresh themselves. Witnesses attest prefix consistency, not completeness, censorship resistance, payment success, clock accuracy or global consensus. Retain the last accepted checkpoint and validate consistency on subsequent reads even when checking quorum. Lost witness state or rollback requires operator recovery against external trusted horizons; never silently re-provision it.

## Durable reference service

The TypeScript `AuditLog` keeps complete Merkle subtrees and permanent commitment indices in an `ACEStore`. Appending costs O(log n) node writes and does not inherit the in-memory builder's 65,536-leaf bound. An explicit write-ahead record allows restart recovery. Nodes, commitment, index and historical checkpoint reach durable storage before the head advances; the head reaches durable storage before acknowledgement. Concurrent retries of the same commitment return its original index. No time/count eviction is permitted. A refresh changes only the current head time; archived checkpoints retain the original time at each size.

`AuditWitness` retains its horizon and receipt in one atomic record under an exclusive lock. `FileStore` uses POSIX kernel locks over permanent inodes on a local filesystem; it is not a replicated database or a defense against restoring old disks. Do not delete lock files, share this backend through a network filesystem or independently copy a running authority/log to multiple hosts. Applications keep private openings outside the public service.

The relay package exports `@ace-protocol/relay/audit` and a separate audit server entry point. It is never mounted by the ordinary relay. See [audit service operations](https://github.com/aceprotocol/ace-relay/blob/main/AUDIT.md) for local provisioning, TLS termination and the bounded HTTP API. No service is deployed automatically.

## Publication boundary

No stable sender/recipient IDs, application schema, payment type, grant, business thread, private statement or salt belongs in a public record by default. An operator signature, log size and publication timing still reveal metadata. Public anchoring is optional; chain ordering does not prove application correctness.

The relay remains a private delivery service. Publication requires an explicit call to the separate log service; its write API admits only a commitment, rejecting plaintext, salts and other extra fields. There is no automatic anchoring transaction. Applications choose publication policy and keep private openings and retained checkpoints in durable protected storage. Shared vectors and SDK tests exercise both signature schemes, witness bindings, quorum/freshness, every tree shape, concurrent appends, restart and interrupted durable writes.

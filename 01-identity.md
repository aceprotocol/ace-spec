# 01 — Identity

An ACE identity is defined by a **key event log** (KEL): an ordered list of signed events whose first event, the inception, names the identity. The KEL governs control and signing only. Packet encryption keys (prekeys) live in the descriptor ([04](04-descriptor.md#prekey)).

An identity holds:

1. A **root key** (`ml-dsa-65`) that signs only KEL events.
2. A **committed next root**: the SHA-256 digest of the key that will replace the root. Control is anchored in this commitment, not in a signature algorithm.
3. A **signing key** (`ml-dsa-65`, 1952-byte public key) delegated by the root and used for every signature outside the KEL.

## ACE ID

```
aceId = "ace:sha256:" || lowercaseHex(SHA-256(icpBytes))
```

`icpBytes` are the canonical bytes of the inception event. The ID never changes: rotation and re-delegation append events.

## Key event log

Every event carries `t`, `seq` (0, then +1 per event), `ts` (wire integer, non-decreasing, `ts <= now + TIMESTAMP_WINDOW_SECONDS`) and, after the inception, `prev` (64 lowercase hex: SHA-256 of the previous event's canonical bytes). Objects are closed. `next` is 64 lowercase hex; `publicKey` members are canonical Base64 ([02](02-encoding.md#base64)).

| `t` | Members | Signed by | Effect |
|---|---|---|---|
| `icp` | `root{scheme,publicKey}`, `next`, `sig` | the root | creates the identity; commits the next root |
| `rot` | `prev`, `root{scheme,publicKey}`, `next`, `sig` | the new root alone | `SHA-256(UTF-8(scheme) ‖ 0x00 ‖ publicKey)` of the new root MUST equal the committed `next`; replaces the root; revokes the signing delegation |
| `dlg` | `prev`, `key{scheme,publicKey}`, `notAfter`?, `sig` | the current root | delegates the signing key, replacing any previous one |

Canonical bytes ([`encodePayload`, `decimal`](02-encoding.md#signatures)):

```
icp: encodePayload("icp", decimal(seq), decimal(ts), root.scheme, rootPublicKeyBytes, nextDigestBytes)
rot: encodePayload("rot", decimal(seq), decimal(ts), prev, root.scheme, rootPublicKeyBytes, nextDigestBytes)
dlg: encodePayload("dlg", decimal(seq), decimal(ts), prev, key.scheme, keyPublicKeyBytes, notAfterOrEmpty)
```

`prev` is the 64-character hex string; key and digest fields are decoded bytes; `notAfterOrEmpty` is `decimal(notAfter)` or the empty string.

`sig` is `{scheme, value}` (no `seq`), REQUIRED on every event and never part of the canonical bytes. It is an ML-DSA signature with action `kel` over `M` with `aceId`, `timestamp = ts`, an empty `seqOrEmpty` and payload `eventBytes` ([02](02-encoding.md#signatures)); for `icp` the ACE ID is computed from `eventBytes` first. `sig.scheme` MUST equal the scheme of the signing root.

### Verifier rules

A verifier replays the log from `seq` 0 in this order. Structural failures are `invalid_kel`; a well-formed signature that does not verify is `invalid_signature`.

1. **Structure, before any signature:** at most `MAX_KEL_EVENTS` events; `icp` only at `seq` 0; closed members and field shapes; contiguous `seq`; non-decreasing `ts` with `ts <= now + TIMESTAMP_WINDOW_SECONDS`; `prev` equals the hash of the previous event.
2. **`icp`:** the root is `ml-dsa-65` with a 1952-byte key; then `sig` verifies under it.
3. **`rot`:** the new root is a valid `ml-dsa-65` key; its commitment MUST match the previous `next` (checked before any signature); `sig.scheme` equals the new root's scheme; `sig` verifies under the new root, and the old root takes no part. After a `rot` no signing key is delegated until a new `dlg`.
4. **`dlg`:** `sig` verifies under the current root, then: `key.scheme` is `ml-dsa-65` with a 1952-byte key; `notAfter`, when present, satisfies `ts < notAfter <= ts + MAX_SIGNING_KEY_LIFETIME`. Without `notAfter` the key lives until replaced. A new `dlg` protects only verifiers that see it: to a verifier shown a log that ends before it, `notAfter` is the only bound on a stolen signing key, so a `dlg` SHOULD carry `notAfter`.
5. **Usable.** An identity is usable at time `t` when a signing key is delegated and, if `notAfter` is set, `t < notAfter`. A relay MUST NOT register an unusable identity and a peer MUST NOT send to one.
6. **Forks.** At the first `seq` where a candidate log and the pinned log differ (the fork point), the candidate supersedes the pinned events from that point only when the candidate's event there is a `rot` and none of the pinned events at or after it is a `rot` (recovery by the holder of the committed next root). Otherwise the pinned log is kept and the candidate is `kel_conflict`. A candidate naming a different ACE ID is `kel_conflict`.
7. An endpoint never prunes a pinned log.

### Operational signatures

Every signature outside the KEL is a delegated signature ([02](02-encoding.md#delegated-signatures)). A verifier, using the signer's pinned or freshly verified KEL:

1. requires `signature.scheme` to be `ml-dsa-65`;
2. requires `signature.seq` to equal the `seq` of the current signing delegation (`stale_peer_binding` otherwise; [06](06-delivery.md#receive-pipeline) defines when a receiver refreshes first), and never uses `seq` to select a key outside that log;
3. requires **signed while live**: the object's signed timestamp is at or after the `ts` of the delegating `dlg` and, if `notAfter` is set, before it (`stale_peer_binding`);
4. then verifies the signature (the surface's signature code);
5. requires the signer's KEL, after reconciliation with the pin, to be usable at `now` (`stale_peer_binding`).

Before signing, a signer checks its own identity at `t = max(now, ts of its last event)`: the log verifies, the identity is usable at `t`, and the key and `seq` are the current delegation. Any failure is the local error `identity_unavailable` and nothing is signed. `t` is the signed timestamp (a descriptor or card record also applies the `+1` rule of [04](04-descriptor.md#verification)).

## Pinning

An endpoint pins, per peer ACE ID, the verified KEL (its `seq`, last hash and state) and the newest verified descriptor. Under one exclusive lock, a candidate KEL:

- is pinned when there is no pin (`adopted`);
- replaces the pin when it extends it (`extended`) or supersedes it under rule 6 (`recovered`);
- only refreshes `fetchedAt` when it is a prefix of or equal to the pin (`unchanged`);
- is otherwise `kel_conflict` and changes nothing.

Which descriptor is pinned under a log is decided in [04](04-descriptor.md#caching). Every signed document of a pinned identity (descriptor, permit, contact `source`) is verified under the state that results from reconciling the KEL it carries with the pin: carrying a prefix of the pinned log never reinstates a superseded delegation (`stale_peer_binding`), and a fork is `kel_conflict`. Cache expiry triggers a refresh and never removes a pin. A stored pin is re-verified on load; corrupt state is `storage_failed`. When to pin and refresh is defined by admission ([05](05-admission.md)) and the receive pipeline ([06](06-delivery.md#receive-pipeline)).

## Rotation and recovery

- **Signing key compromise:** a new root-signed `dlg` replaces the key; signatures with the superseded `seq` stop verifying wherever the new `dlg` is seen. `notAfter` bounds a software key's life.
- **Root compromise:** the thief cannot rotate. The holder of the next root appends a `rot` that forks the log at the start of the current root epoch (after its last `icp` or `rot`), revoking every delegation of that epoch, followed by a fresh `dlg`. Peers adopt it as `extended` or `recovered` (rule 6).
- **Device loss with the next root kept elsewhere:** recover the same way from a copy of the log (for example from a relay).
- A signer MUST refuse to sign a `next` that commits to any root or `dlg` key its log has revealed, a `dlg` whose key equals the current root, and a `dlg` whose key's commitment equals the current `next`. A verifier can detect reuse only of keys the log reveals, so these are signer-side refusals.
- A signer MUST persist a `rot` before publishing it, and MUST NOT sign a second event for a `seq` it has already signed.
- Losing the root and the next root together, or the next root stored on a lost device, is loss of the identity.
- **Next-root compromise** is loss of the identity: the thief can rotate, revoke every delegation and commit a next root of its own, and nothing recovers from that. The next root MUST be stored at least as strongly as the root, and apart from it.

Residual risk: a peer whose pin predates the reveal of a stolen root can be re-forked out of band until it refreshes from a relay holding the full log, and a verifier shown a log ending before a `dlg` accepts the key it replaced until its `notAfter` (rule 4). Both are inherent to single-signature pre-rotation without witnesses. A relay that has deleted an unregistered identity's KEL checks re-registrations against a fixed-size horizon instead ([07](07-relay.md#registration)).

# 09 — Principal (Extension, Draft)

## Overview

A **principal** is the account a person or organisation controls. One principal may operate several ACE identities (a phone, a laptop CLI, a hosted agent). This chapter lets a third party verify that an ACE identity is a delegate of a given account, and defines the three message types a principal's identities exchange among themselves.

ACE has two private channels and one public record:

- **Principal channel** — `request`, `decision`, `report` between identities of the same account (§ Principal Messages).
- **Counterparty channel** — the economic messages of [04-messages.md](./04-messages.md).
- **Public record** — the profile, intents, and the principal record defined here.

The transport does not distinguish them: every message is end-to-end encrypted and point-to-point.

The binding is chain-agnostic. `account` names the account (CAIP-10); `signer` is the key that signed the attestation, normally the account's root, owner or authority key. Verifiers MUST verify the signature. Verifiers MAY additionally read the chain to confirm that `signer.publicKey` is an authority of `account`; this specification does not define how.

## Principal Record

A principal record appears as the `principal` member of a registration file ([01-identity.md](./01-identity.md)) and of a relay profile ([02-discovery.md](./02-discovery.md)).

```json
{
  "account": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU",
  "roles": ["controller", "agent"],
  "signer": { "scheme": "ed25519", "publicKey": "Base64(32 bytes)" },
  "issuedAt": 1759900000,
  "expiresAt": 1791436800,
  "scope": "copy:solana,hl",
  "signature": "Base64(64 bytes)"
}
```

| Field | Required | Rule |
|-------|----------|------|
| `account` | Yes | CAIP-10: `^[-a-z0-9]{3,8}:[-_a-zA-Z0-9]{1,32}:[-.%a-zA-Z0-9]{1,128}$` |
| `roles` | Yes | Array of strings, non-empty, each `controller` or `agent`, no duplicates, `controller` before `agent` when both are present. Exactly one of `["controller"]`, `["agent"]`, `["controller","agent"]`. Any other array is invalid |
| `signer.scheme` | Yes | `ed25519` or `secp256k1` |
| `signer.publicKey` | Yes | Canonical Base64 of a valid key for `signer.scheme`: 32 bytes (`ed25519`), a 33-byte compressed point (`secp256k1`) |
| `issuedAt` | Yes | Wire integer; `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS` |
| `expiresAt` | No | Wire integer; when present `expiresAt > issuedAt`, and the record is valid only while `expiresAt > now` |
| `scope` | No | 1..256 code points, no U+0000–U+001F or U+007F. Its meaning is agreed between implementations; the protocol does not interpret it |
| `signature` | Yes | The signature of `signer` in the encoding of `signer.scheme` ([04-messages.md](./04-messages.md) § Signature Encoding by Scheme) |

An optional member whose value is `null` is treated as absent. Unknown members are ignored.

## Signing Context

The record is signed under action `principal` ([04-messages.md](./04-messages.md) § Signing Contexts):

```
signData = buildSignData("principal", subjectAceId, issuedAt,
  encodePayload(account, join(roles, ","), signer.scheme, signer.publicKey,
                subjectSigningPublicKeyB64, scopeOrEmpty, decimal(expiresAtOr0)))
```

- The **subject** is the ACE identity the record authorizes. `subjectAceId` is `ace:sha256:hex(SHA-256(subjectSigningPublicKey))`.
- `subjectSigningPublicKeyB64` is the canonical Base64 of the subject's raw signing public key bytes, computed by the verifier from the key it has verified (the relay request's `signingPublicKey`, the peer record's signing key, or the key determined by [01-identity.md](./01-identity.md) § Validation rule 3). It is never copied from the record.
- `signer.publicKey` is used exactly as it appears in the record.
- `join(roles, ",")` is the roles array joined with `,` (for example `controller,agent`).
- `scopeOrEmpty` is `scope`, or the empty string when absent. `decimal(expiresAtOr0)` is `decimal(expiresAt)`, or `"0"` when absent.
- The digest is signed by the `signer` key. This is the only signing context whose signer is not the holder of `aceId`.

## Validation

`validatePrincipalRecord(record, subjectSigningPublicKey, now)` checks, in this order; every failure is `invalid_principal`:

1. The record is a JSON object whose members have the types in § Principal Record.
2. `account` matches the CAIP-10 pattern.
3. `roles` is one of the three allowed arrays.
4. `signer.scheme` is supported and `signer.publicKey` is a canonical Base64 valid key for it.
5. `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS`.
6. `expiresAt`, when present, is greater than `issuedAt`.
7. `scope`, when present, satisfies its rule.
8. `signature` decodes under the encoding of `signer.scheme`.
9. `signature` verifies under `signer` over the signData above, computed with `subjectSigningPublicKey`. A record issued for another subject fails here.
10. When `expiresAt` is present, `expiresAt > now`.

Where records are validated:

- A relay validates `profile.principal` before writing a registration ([08-relay.md](./08-relay.md) § Registration), with `now` = its clock.
- A client validates the principal of a peer record or registration file when it verifies it ([02-discovery.md](./02-discovery.md) § Peer Record, [01-identity.md](./01-identity.md) § Validation). A failure rejects the whole record with `invalid_principal`.
- A peer cache that re-verifies a stored binding uses the time the binding was verified (`fetchedAt`) as `now`, so a principal that has expired since does not make the cache unreadable.
- The receive pipeline re-validates the sender's principal with the current time at step 7 (§ Same-Account Rules).

There is no revocation list. Issuers keep `expiresAt` short and re-register without the principal to withdraw it.

## Principal Messages

Three message types carry a principal's own coordination. They are not economic messages: they never enter the thread state machine, `threadId` is optional and changes no thread state, and they are subject to § Same-Account Rules at pipeline step 7 ([06-security.md](./06-security.md)).

| Type | Typical direction | Required fields | Optional fields |
|------|-------------------|-----------------|-----------------|
| `request` | delegate → controller | `action` (string), `summary` (string) | `ref` (object), `amount` (string), `currency` (string), `details` (object), `ttl` (wire integer) |
| `decision` | controller → delegate | `requestId` (string), `outcome` (`"approve"` or `"deny"`) | `reason` (string), `result` (object) |
| `report` | either direction | `action` (string), `summary` (string), `outcome` (`"ok"`, `"failed"` or `"skipped"`) | `ref` (object), `requestId` (string), `proof` (object) |

- `outcome` values outside the listed ones are `invalid_body`.
- `ref` is `{ "conversationId", "threadId"?, "messageId" }`: `conversationId` 64 lowercase hex characters, `messageId` a lowercase UUID v4 (as the envelope `messageId`), `threadId` absent, `null` (treated as absent) or a valid thread ID ([04-messages.md](./04-messages.md) § Thread IDs). Any other `ref` is `invalid_body`. `ref` points at a counterparty message the request or report is about; it carries identifiers only.
- `amount` and `currency` are a display summary. `details` is free-form JSON carrying what the controller needs to act (chain, asset, recipient, x402 payment requirements, …).
- `decision.result` is free-form JSON returned when the controller performed the action itself (for example a signed x402 payment payload or a transaction hash).
- `report.requestId` optionally names the `request` the report concludes; it is not checked.

**Action names (informative).** Implementations SHOULD use `pay`, `x402.pay`, `copy.run` and `sign` for those actions. A receiver that does not recognise an `action` still accepts the message and shows its `summary`.

## Same-Account Rules

Let `P_self` be the receiver's own principal: the host supplies its `account` when it opens the receive engine. Let `P_from` be the `principal` of the sender's verified and pinned peer binding ([02-discovery.md](./02-discovery.md) § Rollback Barrier), never anything carried in the message.

A principal message is accepted only if, in this order (first failure wins):

1. `P_self` exists → else `wrong_principal`.
2. `P_from` exists → else `wrong_principal`.
3. `validatePrincipalRecord(P_from, senderSigningPublicKey, now)` succeeds → else `wrong_principal`.
4. `P_from.account == P_self.account` (exact string comparison) → else `wrong_principal`.
5. `decision` only: `"controller" ∈ P_from.roles` → else `wrong_principal`.
6. `decision` only: `requestId` is the `messageId` of a `request` the receiver sent in the same `conversationId`, and no `decision` for it has been accepted → else `bad_reference`.

`request` and `report` have no role check. An accepted `decision` marks its request decided; a request has at most one accepted decision. A failed check changes nothing.

## Persistence

SDKs keep one record per sent `request` ([06-security.md](./06-security.md) § Appendix A):

`requests/<sha256(conversationId ‖ 0x00 ‖ messageId)>.json` = `{"conversationId","decision":null|{"messageId","outcome","timestamp"},"messageId","sentAt","to","version":1}`

- The sender writes it after the `request` is delivered and before it clears the pending send.
- The receiver of the `decision` fills `decision` when it accepts the decision, after the delivery record and before the replay state (and repairs it from delivery records on recovery).
- A record MAY be deleted 30 days after `sentAt`.

## Errors

| Code | Category | Meaning |
|------|----------|---------|
| `invalid_principal` | permanent | A principal record fails § Validation (registration, peer record, registration file, local creation) |
| `wrong_principal` | permanent | A principal message fails § Same-Account Rules 1–5 |

A relay answers `invalid_principal` with status 400 ([08-relay.md](./08-relay.md) § Errors). `bad_reference` is reused for rule 6.

## Security Considerations

- **Delegate impersonating its principal.** The record is signed by the account's key over the subject's signing key; a delegate cannot mint one for another subject, and a record cannot be transplanted (rule 9).
- **Relay tampering.** The profile is not covered by the registration binding signature. A relay can strip a principal (principal messages from that peer then fail closed with `wrong_principal`) but cannot forge or alter one.
- **Key custody.** `hardwareBacking` is self-asserted and not verifiable ([01-identity.md](./01-identity.md)); the principal binding is the verifiable custody fact.
- **Authority.** The protocol proves that `signer` signed; whether `signer` controls `account` on its chain is a MAY check for verifiers.

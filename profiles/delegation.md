# Delegation profile `ace:delegation:1`

An optional official profile: signed credentials by which one identity declares that another acts on its behalf. Its manifest is [delegation.json](delegation.json) ([digests](../08-profiles.md#official-manifests)); its message rule is a profile rule ([08](../08-profiles.md#profile-rules)).

## Credentials

A **credential** is the closed object:

```
{ issuer, subject, issuedAt, expiresAt, signature }
```

- `issuer` and `subject` are ACE IDs ([02](../02-encoding.md#identifiers)); `issuer != subject`.
- `issuedAt` and `expiresAt` are wire integers: `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS`, `issuedAt < expiresAt`, `expiresAt - issuedAt <= 604800`.
- Signed by the issuer as a delegated signature ([02](../02-encoding.md#delegated-signatures)) with action `ace:delegation:1`, `aceId = issuer`, `timestamp = issuedAt` and payload `canonicalStateBytes(claims)`.

A credential states one edge: **the issuer declares that the subject acts on its behalf.** It grants no execution, payment or communication right. The issuer revokes by not renewing.

## Descriptor extension

`ext["ace:delegation:1"]` is the closed object `{credentials}`: 1–4 credentials with distinct `issuer`s, each with `subject` equal to the descriptor's `aceId`. Descriptor verification ([04 § Extensions](../04-descriptor.md#extensions)) checks this shape only: each entry is a closed credential with `issuer != subject`, `subject` equal to the descriptor's `aceId`, `issuedAt <= now + TIMESTAMP_WINDOW_SECONDS`, `issuedAt < expiresAt` and `expiresAt - issuedAt <= 604800`; it checks neither expiry (`now < expiresAt`) nor any signature.

## Verifying a credential

A client that needs to know whether `subject` acts for `issuer` pins the issuer by looking up its descriptor ([04 § Verification](../04-descriptor.md#verification), [01 § Pinning](../01-identity.md#pinning)), then requires `now < expiresAt` and the signature to verify as an operational signature of the issuer's pinned KEL ([01 § Operational signatures](../01-identity.md#operational-signatures)). A lookup or pin failure is reported as that failure; it is never read as "not delegated". The result is bound to the pin: when the issuer's pin changes, the credential is verified again.

## Message `ace:delegation:1`

The body `{credential}` hands a credential from its issuer to its subject.

- **check** (on send, and on receive at pipeline step 10 of [06](../06-delivery.md#receive-pipeline)): the credential is closed and meets the `issuer != subject`, `issuedAt` and `expiresAt` rules of [§ Descriptor extension](#descriptor-extension), `now < expiresAt`, `credential.issuer` equals `from`, `credential.subject` equals `to`, and on receive its signature verifies as an operational signature of the sender's pinned KEL. Any failure is `invalid_body`.
- **commit** changes no state. The application stores the credential and publishes it in its `ext`.

# Specification backlog

Not normative. Items recorded for the next revision of the documents named below.

## 09-principal.md

- Length and charset bounds for `action`, `summary`, `amount`, `currency` and `requestId`.
- A `requestLedger` section in `test-vectors.json`.
- Prose for the `rules` vector section (hedged signatures: compare members, verify `signature`).
- Rollback Barrier principal vectors: registration file never removes a principal, expired cached principal dropped on keep-cache branches, monotonic `issuedAt`/`registeredAt` replacement, rotation adoption, expired-only principal treated as absent.
- Interop coverage for the trusted-signer path (rule 4(b)), the one-time refresh before `wrong_principal`, `eip155` derivation (rule 4(c)), a `decision` whose sender is not the request's `to`, and request expiry.
- Case-insensitive rule 5 for `eip155` accounts, and normalisation of the relay's per-account index.

## test-vectors.json

- Move the `action: "principal"` entries out of `vectors.auth` (they carry no headers, so every auth runner filters them) into `vectors.principal`, together with the runner change in all three SDKs.
- Thread-ID syntax vectors (empty, 257 code points, U+007F) currently sit in `vectors.envelopes`, where any `threadId` key is rejected regardless of value; move them to a private-content parsing section so the syntax itself is exercised.

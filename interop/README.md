# Live cross-SDK interop matrix

`run.sh` drives the TypeScript, Python and Swift ACE SDKs against each other with freshly
generated keys and messages (no fixed vectors) and fails on any mismatch. It complements
`test-vectors.json`: vectors pin deterministic encodings, this harness checks that live
output of one SDK is accepted, and decoded identically, by the others.

## Layout

| Path | Role |
|------|------|
| `ts/interop.ts` | TypeScript side, imports `../../../sdk-ts/dist` (run by Node's type stripping, or `tsx`) |
| `py/interop.py` | Python side, uses the `ace` package from `sdk-py` |
| `swift/` | Swift executable package depending on `../../../sdk-swift` by path |
| `compare.py` | Tampers fixtures and evaluates the matrix (stdlib only) |
| `run.sh` | Builds, runs every phase in all three SDKs, prints the matrix, exits non-zero on failure |

The SDK checkouts are expected next to `ace-spec/` (`../sdk-ts`, `../sdk-py`, `../sdk-swift`).

## Running

```sh
./run.sh
```

Requirements: Node >= 22.18 (or `npx tsx`), Swift 6.2+ on macOS 26+, and a Python
environment with the SDK installed — by default `../sdk-py/.venv/bin/python`
(`cd ../sdk-py && python -m venv .venv && .venv/bin/pip install -e .`).

Environment overrides: `WORK=<dir>` (keep artifacts; default a fresh temp dir),
`SKIP_BUILD=1` (reuse `sdk-ts/dist` and the Swift build), `PYTHON=<interpreter>`,
`SDK_TS=<path>`, `SDK_PY=<path>`, `ACE_VECTORS=<path>` (default `../test-vectors.json`, read by
the principal phases).

All phases must finish within the 300 s freshness window used by registration requests,
auth headers and direct `Inbox` delivery; builds run before the first phase.

## What is checked

Every SDK creates two identities per scheme (`ed25519`, `secp256k1`): `<lang>-<scheme>`
sends, `<lang>-<scheme>-rx` receives, so the diagonal (ts→ts, …) also has two parties.
Data is exchanged as JSON files in `$WORK`.

| # | Matrix | Check |
|---|--------|-------|
| 1 | exporter × importer | `exportPrivateKey` → `fromExport` gives the same ACE ID, public keys, address and re-export; `createRegistrationFile` of the imported identity equals the original; `verifyRegistrationFile` passes with the same keys |
| 2 | sender × receiver | `text` and `rfq` (with `threadId`, non-ASCII strings, integer `ttl`) parse with identical bodies, IDs and parties; a second parse is `replay`; copies with one `kemCiphertext` byte flipped fail with `invalid_signature` in all SDKs; the receiver replies with an `offer` on the same thread (state `rfq` → `offered`) and the original sender, restoring its thread state with `ThreadStateMachine.fromState`, parses it (history `rfq, offer`) |
| 3 | creator × verifier | `createRegistrationRequest` (with a profile) passes `verifyRegistrationRequest` everywhere with an identical `requestDigest` |
| 4 | creator × verifier | `createAuthHeaders` for `listen`, `inbox`, `unregister` and `intent` pass `parseAuthHeaders` + `verifyAuthHeaders`; headers checked against a different request fail with `invalid_signature` |
| 5 | writer × loader | the writer receives 6 messages through `Inbox` + `PeerStore` + `FileStore`; every SDK then loads that store: `replay.json` through `ReplayDetector.fromState` re-exports byte-identically, each thread record round-trips through `ThreadStateMachine.fromState`, `ThreadStore.list` and `PeerStore.get` read the records, and `Inbox.open` on a copy of the foreign store recovers without re-handing messages and reports a re-sent envelope as `duplicate` |
| 6 | creator × verifier | Principal records (09): every delegate (`["agent"]`) and controller (`["controller"]`) record, and the registration files and registration requests carrying it, verify everywhere; the verifier re-encodes the record identically and every verifier computes the same principal `payload` and `signData` bytes and the same `requestDigest`; a record checked against another subject is `invalid_principal`. A deterministic record (same signer, subject, account, roles, scope, `issuedAt`, `expiresAt` in every SDK) has identical members, `payload` and `signData` in every SDK; signatures are not compared byte for byte because signers may hedge (CryptoKit ed25519 in Swift, secp256k1 with extra entropy in TypeScript; `test-vectors.json` marks this with `verifyOnly`), each verifier checks them instead |
| 7 | sender × receiver | Delegate `<S>-<scheme>` sends a `request` (with `ttl`) and a `report` through its `Outbox`; delivery writes `requests/<sha256(conversationId ‖ 0x00 ‖ messageId)>.json` with `decision: null` and `expiresAt = timestamp + ttl`. Controller `<R>-<scheme>-rx` receives both through an `Inbox` opened with `principal = {account, selfSigner, trustedSigners}` (identical bodies, no `threadId`); without a receiver principal the report is `wrong_principal`. The controller answers with `decision{approve, result}`, a different `decision{deny}` and a `report`; the delegate's `Inbox` (same store as its `Outbox`) delivers the first decision, reports its redelivery as `duplicate`, quarantines the second decision as `bad_reference`, and delivers the report. The filled ledger record is byte-identical to the canonical form (sorted keys, compact, `version: 1`) in every SDK, and the receiver's SDK loads it with `loadRequestRecord`. The `Inbox`/`trustedSigners` checks exercise signer-binding path (a) only (the same-scheme owner signs both records); paths (b) trusted signers and (c) `eip155` derivation are unit-tested per SDK |

Principal fixtures are shared by all three programs: one CAIP-10 account
(`solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:InteropOwner1111111111111111111111111111111`), the
controller signer (owner key) of each scheme taken from the v4 `test-vectors.json` agents
(ed25519: `alice`, secp256k1: `bob`), and, for the deterministic record, the delegate subject
`principalRules.senders.agent.signingPublicKey` with `issuedAt = principal.now`. Each `Inbox`
uses that scheme's owner key as `selfSigner` and the other scheme's owner key as its only trusted
signer. Everything runs offline: peers are pinned from registration files and envelopes are handed
to `Inbox.receive` as direct deliveries (no relay).

Each SDK program records raw observations (`$WORK/out/<lang>/*.json`); all assertions live
in `compare.py`, so the three programs stay small and symmetric.

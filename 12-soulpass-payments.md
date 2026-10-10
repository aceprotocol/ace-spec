# SoulPass payment profile

This is an installed application profile, not an ACE transport privilege. SoulPass is an ordinary agent. The iOS adapter uses explicit local user confirmation. The opt-in CLI executor uses exact resource grants rooted in an explicitly provisioned authority. Both share the deterministic `AgentPaymentProfile`; pairing alone admits proposals and never permits spending. The delegated executor supports sponsored Solana native/legacy SPL transfers and EVM native/registered ERC-20 transfers from an initialized MachineAccount.

## Pairing

In SoulPass, open **your agents → pair an external agent**. Enter the complete ACE identity obtained from the agent through a trusted channel and a local name. SoulPass verifies the signed directory record, displays the full identity for comparison, then persists the user's confirmation in a wallet-scoped pairing store. The identity hashes the signing public key; directory names, account strings and role advertisements cannot substitute for it. A changed signing identity requires a new pairing.

A pairing grants no payment authority and no right to administer other agents. Unpaired requests and reports are not promoted into the action inbox or its notifications. Ordinary authenticated private messages still reach the message log. A missing/corrupt pairing store never enables action admission. The sender must still be paired at payment start and immediately before releasing a new transaction authorization. Removing a pairing prevents future authorization; it does not undo a signature already released. The local owner identity is checked again to prevent a wallet switch from carrying permission into another account.

The SoulPass message transport no longer applies the optional account-affiliation receive filter. Account roles remain descriptive metadata. The financial action boundary and local pairing policy are independent of those roles. Transport opening and closing are serialized; a wallet switch, signing-key change or release during an open cancels that operation. No chain-role query or timer gates transport.

## Proposal

Send an ordinary encrypted ACE `request`, with a UUIDv4 message ID and this body. The normal built-in `request` schema digest is used for the message wrapper. `action` selects this installed deterministic validator; it supplies no authority.

```json
{
  "action": "pay",
  "summary": "Pay for the completed task",
  "details": {
    "chain": "eip155:8453",
    "account": "0x1111111111111111111111111111111111111111",
    "asset": "native",
    "payTo": "0x2222222222222222222222222222222222222222",
    "amount": "1000000000000000",
    "decimals": 18,
    "feeAsset": "native",
    "maxFee": "0",
    "expiresAt": 1791540000
  }
}
```

The addresses and deadline are illustrative. Use the actual account, recipient and a future deadline; acceptance depends on the installed chain and token registry.

All nine detail fields are mandatory; unknown detail fields and unknown outer constraints make a proposal non-executable. Outer `amount`/`currency` are untrusted display metadata. `summary` never changes execution. The details are interpreted as follows:

| Field | Rule |
| --- | --- |
| `chain` | Exact supported CAIP-2 string. No chain names, aliases or automatic routing. |
| `account`, `payTo` | Literal source and destination addresses. EVM: lowercase `0x` + 40 hex digits, nonzero. Solana: canonical Base58 encoding of a 32-byte address other than the all-zero address. Labels cannot authorize payment. |
| `asset` | `native`, `erc20:<lowercase-contract>` or `spl:<canonical-mint>`, scoped to `chain`. EVM tokens must be in the local supported registry. |
| `amount` | Positive canonical integer string in base units; no decimal point, sign, exponent or leading zero. At most 78 digits, further bounded by the chain's amount type. |
| `decimals` | Integer 0–18. Used for exact string rendering and checked against the resolved execution plan. A sender cannot change the amount by lying about precision. |
| `feeAsset`, `maxFee` | Fee asset in the same notation and a nonnegative canonical integer ceiling. A nonzero fee must use that asset and stay within the ceiling. No currency conversion. |
| `expiresAt` | Positive absolute Unix second, at most 2^53−1. No new authorization at or after this second. If outer `ttl` exists, the earlier of this deadline and signed message timestamp + TTL applies. |

The current adapter executes one sponsored transfer. Solana requires native fee asset with a zero ceiling; the sponsor pays the envelope and any recipient ATA setup. EVM relay fees are quoted before consent, must fit the requested ceiling, and are checked again before signing. Missing sponsorship or a capacity refusal cannot switch to user-paid gas. Account deployment/bootstrapping is a separate operation and is not authorized by this profile. Set up the account first.

The confirmation card and the signed transaction derive from one immutable plan. Matching uses the actual chain, source account, contract/mint, recipient, base-unit amount, precision and fees from that plan. Matching names, token symbols or decimal display strings is insufficient.

## Exact execution identity and persistence

The adapter constructs the document-10 execution intent:

- `operationId`: original request message ID.
- `audience`: this SoulPass ACE identity.
- `resource`: `urn:soulpass:funds:<chain>:<account>`.
- `action`: `urn:soulpass:pay:1`.
- `schemaDigest`: the SHA-256 digest below.
- `details`: the eight payment detail fields except `expiresAt`.
- `expiresAt`: the effective absolute deadline, rounded down to seconds.

Hash the intent with ACE's shared `executionIntentDigest`. Resource costs are derived by the installed profile from `details`; there is no separate caller-supplied `units` field. An autonomous authority must reserve the amount and worst-case fee in every spent asset atomically. The exact UTF-8 schema descriptor is:

```json
{"action":"urn:soulpass:pay:1","details":["chain","account","asset","payTo","amount","decimals","feeAsset","maxFee"],"execution":"single-sponsored-transfer","version":1}
```

Digest: `959502fcf801fc31c1399ac8913bdb3eef77918d695b28fb097f6831a2048a18`.

Before the payment UI opens, the local journal durably binds the operation to this digest. Cancellation retains the binding. A changed effect requires a new operation ID. A second sender cannot reuse an already bound operation ID in the same journal. Each execution attempt receives a persistent generation token; concurrent starts and callbacks from a canceled attempt are refused. Submission evidence must reach durable storage before signed bytes can leave the device, including an RPC simulation containing a detached authorization. A sponsor refusal cannot retract an already disclosed proof. The obsolete `SubmissionEvidence.notSent` event has been removed; it cannot clear a transaction hash or release a reserved operation. An ambiguous outcome is reconciled before any retry. This iOS human-consent journal remains device-local. Restoring/deleting it does not provide rollback-proof or multi-device idempotency. Delegated agents instead address the single authoritative execution endpoint below; they must never copy its store to independent executors.

The CLI's keyed-payment journal likewise retains per-key records without age/count eviction. Records are individually size-bounded, and an unknown no-hash outcome cannot be turned into a retry by a later generic failure cleanup. Only a proven pre-wire failure may retry the same fingerprint. Pre-wire cleanup compares the captured attempt and its generation under the journal lock; a late cleanup cannot release a replacement attempt or erase newer evidence.

## Execution receipts

A payment result is sent as the generic private extension `urn:soulpass:payment-receipt:1`, not `decision { outcome: "approve" }`. Install its schema before interpreting it:

```json
{"fields":["requestId","operationId","intentDigest","status","txHash","chain"],"states":["submitted","confirmed","unknown"],"type":"urn:soulpass:payment-receipt:1","version":1}
```

Schema digest: `253c7bfea60a60b23685411fb8b8d908a72b413435efbef68d3ffd351560c236`.

Its closed body contains `requestId`, `operationId`, `intentDigest`, `status`, `txHash`, and canonical CAIP-2 `chain`. Status is `submitted`, `confirmed` or `unknown`. `txHash` is null only for an `unknown` result without a known transaction; a null hash never permits retrying the effect. The receipt is authenticated by the ordinary ACE message signature and encryption; the sender must match the intent's audience. A transaction hash alone is not confirmation. A receiver must independently verify the transaction effect and required chain finality before delivering value or treating the obligation as settled. Unknown schemas remain data and confer no authority.

Receipts require an existing persistent intent digest, matching resolved payment facts and matching recorded transaction hash and chain. A supplied result cannot create a missing payment row, replace its hash or promote an unconfirmed outcome. There is no memory-only receipt fallback. Reconciliation retains the original executor identity, and the message transport refuses a different sending identity after an asynchronous wallet switch.

Receipt retries use a stable local outbox key derived from the exact sorted receipt body. An expired request cannot start another payment, but its existing payment can still produce a receipt. The receipt's operation ID and digest never change when submission later becomes confirmed. This profile does not automatically convert a submitted receipt into a terminal success; settlement is determined by chain verification.

## Delegated authoritative executor

The CLI exposes `soulpass agent payments provision|status|revoke|epoch|serve --config <local-file>`. Provisioning, revocation and epoch changes require a person at the controlling terminal and a typed confirmation. The unattended service requires existing provisioned state and pins the process to one wallet and executor identity. Nothing is enabled merely by receiving a message or registering an account role. Configuration is loaded only from a local operator file, never from a message, URL or model output.

The closed configuration contains `version` (1), `authority` (a verified ACE registration file whose complete identity the operator trusts), `executor` (this host's ACE identity), `chain`, `account` (the actual Solana vault or EVM MachineAccount), `assets` (canonical asset to decimals), `budget` (accounting dimension to integer base units), `epoch`, and explicit `storage`. For example, native SOL uses `assets: {"native": 9}` and `budget: {"asset:native": "10000000"}`. Each configured asset needs an explicit budget; there are no defaults, top-ups, resets or automatic refunds. The chain must exactly match the configured Solana network or an installed, active EIP-7702 EVM network; chain aliases and implicit mainnet/testnet substitution are refused. EVM ERC-20 addresses and decimals must match the installed token registry. Account setup is a separate human action.

For replicated storage, supply the closed object below as the configuration's `storage` field. The actual cluster ID must come from the operator's independently verified cluster, not this illustrative value. `tokenEnvironment` names a local environment variable containing the short-lived etcd credential; a named but missing or empty credential is an error. Inline tokens, unknown fields, automatic pins and fallback stores are refused.

```json
{
  "kind": "etcd",
  "endpoint": "https://private-state.example",
  "namespace": "payment-authority",
  "clusterId": "123456789",
  "tokenEnvironment": "SOULPASS_STATE_TOKEN"
}
```

`tokenEnvironment` may be omitted for a locally isolated test cluster. The remote deployment must restrict access to the configured namespace and authenticate its clients. The namespace and cluster pin are trusted local inputs; no ACE sender can select them. Provisioning still refuses existing authority state. A network failure never switches to `local`. A restored cluster with a different identity stops execution rather than repinning itself. See document 10 for quorum trust, capacity, recovery and rollback limitations.

Send the document-10 `urn:ace:execute:1` extension with `{intent, grants}`. Its `intent.details` uses the eight fields above. The resource is scoped to the account, so token amounts and fees share one atomic budget authority. Costs are derived from the signed details: sum amount and worst-case fee for the same asset, or reserve both dimensions for different assets. The leaf subject must equal the authenticated sender, and audience must equal the configured executor. The installed registry fixes asset decimals; fee assets with a nonzero ceiling must also be explicitly installed and budgeted. The actual mint or token contract and chain are checked again when constructing the transaction.

The service consumes the authenticated ACE receive log and stream. It reserves the budget once, durably writes an unresolved payment record, constructs one validated sponsored transfer, and permanently consumes the authority's release immediately before exposing the signed authorization to the simulator or sponsor. A permanent account nonce binding prevents different operation IDs from authorizing or claiming the same chain nonce. The second check rejects expiry, revocation or an epoch change during preparation. Absolute expiry is checked again after authority persistence and after the nonce/evidence journal returns; a slow quorum cannot turn an expired request into permission to disclose a signature. A binding that survived a crash is never reassigned. It does not deploy accounts, use user-paid fallback, accept raw transactions, execute Token-2022 hooks, fetch a schema implementation or run sender-provided code.

For EVM, the CLI uses the captured wallet device’s derived ECDSA owner key and requires that owner to be registered on-chain with threshold one. The SDK also accepts an explicitly installed P-256 signer. Delegation, initialization, owner set, nonce and owner-policy epoch are read at a pinned block; an unsupported or foreign account fails closed. The payload contains exactly one native or ERC-20 transfer, plus at most the bounded relay fee. The signature binds chain, account, owner-policy epoch, nonce, full calls and deadline. A relay acknowledgement produces only a submitted receipt; confirmation requires finalized chain evidence for the exact calls and deadline. There is no deployment, owner enrollment, allowance approval, self-paid fallback or automatic retry in this path.

**Two authority layers, one direction.** The account's on-chain owner set and session policies (machine-wallet `mandate_hash` and cash caps; MachineAccount session owners) are the hard outer bound of what the executor key can sign at all; the chain enforces them with or without ACE. The ACE grant and the `ExecutionAuthority` reservation are the per-operation exact-intent authorization inside that bound: they decide whether this executor will sign at all, never what the chain accepts. The ACE intent digest is not written on-chain and the chain does not read ACE state, so the two ledgers are independent by design and are reconciled only by the executor's read-only chain reconciliation of its own operations. An operator who wants on-chain evidence that a session was opened for this profile binds the session's mandate hash to the SHA-256 of the installed `AgentPaymentProfile` descriptor; that binding is an application deployment choice, not part of this profile.

A durable reservation without a payment row, any interrupted preparation, a lost acknowledgement and every uncertain submission are unresolved. Repeating the same operation never calls the executor again. The same ID with a changed intent or sender is rejected. Reconciliation may promote an existing authorization to confirmed using chain history and its exact signed digest, including after the grant expires or is revoked. It does not resign or refund. A relay's claimed refusal is not proof that its copy of the signature cannot execute. Returned receipts use the same private payment receipt schema; their `requestId` and `operationId` both identify the stable execution operation. The server's outbox binds each exact receipt body to a stable local send key.

All agents/devices for this resource address the same executor identity and authority state. They receive evidence, never a reusable permission to pay on another device. Explicit `storage: {"kind":"local"}` uses the protected wallet FileStore on one host; copying, rolling back or deleting those files is unsupported. Local backups cannot safely resume signing from an older state. The optional replicated backend below keeps budgets, releases, account nonce bindings and payment recovery evidence in the same private quorum namespace. Signing identity enrollment and device takeover remain separate operator responsibilities; shared storage does not distribute signing keys. The received-message display log is bounded and may rotate; senders must retransmit an unacknowledged proposal with the same operation ID. Payment and authority operation bindings themselves never expire or rotate. Deployment and independent security review remain release work.

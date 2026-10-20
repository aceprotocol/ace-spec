# ACE interop matrix

A live cross-SDK check of the wire objects agents exchange: packets carrying text, receipts
(`ace:receipt:1`) and contact requests (`ace:contact:1`), and card records
([04 § Card record](../04-descriptor.md#card-record)). No relay is involved: each SDK is driven
through a small command-line **driver**, artifacts are exchanged as JSON files, every directed
pair of SDKs (same-SDK pairs included) is run, and every SDK verifies every SDK's card records.

```
bash ace-spec/interop/run.sh                       # TypeScript and Python
ACE_INTEROP_SWIFT=/path/to/ACEInterop bash run.sh  # adds Swift (see § Swift)
INTEROP_LANGS=py,swift SKIP_BUILD=1 WORK=/tmp/x bash run.sh
```

`run.sh` builds `sdk-ts` (`dist/`, skipped with `SKIP_BUILD=1`), then runs `matrix.py` with
`sdk-py/.venv/bin/python` (override with `PYTHON`). The TS driver runs with Node's type stripping
(Node >= 22.18) and imports `sdk-ts/dist`; the Python driver runs with `PYTHONPATH=sdk-py`.
Environment: `INTEROP_LANGS` (default: every available driver), `ACE_INTEROP_NOW` (the fixed clock,
default `1760140800`), `WORK` (artifact directory, recreated on each run).

## Driver contract

A driver is one executable. It takes a subcommand, a driver directory it owns and `--now <unix
seconds>` (every operation uses that clock and nothing else, so runs are reproducible). It exits 0
on success and non-zero only on an internal failure (bad arguments, an unexpected exception); a
protocol rejection while opening is a successful run whose result is `{"error": <code>}`.

### `gen-identity <dir> [--handle H] --now N`

Generate a software identity (ML-DSA root, next root, signing key) and one X-Wing prekey dated
`N`, persisting whatever the driver needs to sign and decrypt later inside `<dir>` (format private
to the driver). Write two files:

- `<dir>/agent.json`: the PublishedAgent `{kel, descriptor}` issued at `N` (lifetime 86400),
  `relays: ["https://relay.interop.test"]`, `profiles` listing exactly `ace:text:1` with its
  profile digest;
- `<dir>/card.json`: the CardBundle `{kel, card}` whose card record is issued at `N` with
  `home: "https://relay.interop.test"`, `card: {}`, `contact: "open"`, `listed: false`, no `pay`,
  and `handle: H` exactly when `--handle` is given (the matrix gives `<sdk>-a`, e.g. `ts-a`, to each
  SDK's identity `a` and no handle to `b` and `c`).

### `verify-card <card.json> --now N`

Verify the CardBundle in the file at `N` (04 § Card record steps 1-3; no pin) and print one JSON
line to stdout: `{"ok": true, "aceId", "handle"?, "contact", "listed"}`, or `{"error": <code>}` for
a protocol rejection.

### `create-packet <dir> --to-agent F --kind K --out P [options] --now N`

Verify the recipient PublishedAgent `F` at `N`, build the private content for `K`, encrypt to the
recipient's descriptor prekey (or to the prekey of `--prekey-agent F2` when given), sign with
`timestamp = N` (and `messageId` from `--message-id` when given, else a fresh UUIDv4). Write the
packet to `P` and the exact private content `{type, schemaDigest, threadId?, body}` to
`P.content.json`.

| `--kind` | Content |
|---|---|
| `text` | `ace:text:1` `{message: --message}` |
| `receipt-delivered` | `ace:receipt:1` `{messageId: --ref-message-id, outcome: "delivered"}` |
| `receipt-rejected` | `ace:receipt:1` `{messageId: --ref-message-id, outcome: "rejected", code: --code, permit}`, `permit` a fresh delivery permit from the sender to the recipient (a renewal) |
| `receipt-unknown-prekey` | `ace:receipt:1` `{messageId: --ref-message-id, outcome: "rejected", code: "unknown_prekey", prekey: --ref-prekey}` |
| `contact-request`, `contact-accepted` | `ace:contact:1` `{kind, profile: "ace:text:1", note: --note, source: <own agent.json>, permit}`, `permit` issued by the sender to the recipient |
| `contact-rejected` | `ace:contact:1` `{kind: "rejected", profile: "ace:text:1", note: "", source}` (no permit) |

### `open-packet <dir> --from-agent F --packet P --out R --now N`

Open the packet as the identity in `<dir>`, in this order, the first failure deciding:

1. decode the closed packet (`unsupported_version` for any `ace` other than `"1"`, else
   `invalid_packet`); `to` is this identity (`wrong_recipient`);
2. verify the sender's KEL `F.kel` at `N`, standing for the receiver's pin (the descriptor of `F` is
   not consulted, so it may have expired); its ACE ID must equal `from` (`invalid_signature`
   otherwise);
3. the packet signature as an operational signature of that KEL, usable at `N`
   (`stale_peer_binding`, `invalid_signature`);
4. the time window `N - 604800 <= timestamp <= N + 300` (`stale_timestamp`);
5. decrypt with the referenced prekey (`unknown_prekey`, `decryption_failed`), parse the private
   content (`invalid_body`);
6. `(type, schemaDigest)` installed (core + text) and the body schema (`unsupported_schema`,
   `invalid_body`);
7. core rules: a contact packet has no freshness bound beyond step 4; its `source` verifies at `N`
   and names `from` (`invalid_authorization`), the packet signature verifies under `source.kel`, the
   note is at most 512 UTF-8 bytes (`invalid_body`), `permit` is present exactly unless
   `rejected` and verifies with `issuer = from`, `subject = <me>`; a receipt carries `code`
   exactly when `rejected` and `prekey` exactly when `code` is `unknown_prekey` (`invalid_body`),
   and any `permit` verifies against the sender's KEL with `subject = <me>`.

Write `R`: `{"ok": true, "from", "messageId", "type", "schemaDigest", "threadId"?, "body"}`, or
`{"error": "<ACE error code>"}`. This is the receive pipeline of [06](../06-delivery.md#receive-pipeline)
minus admission, pinning and deduplication (which are local state, not wire interop).

### Swift

The Swift driver is the `ACEInterop` executable of `sdk-swift` (`Examples/Interop`); it keeps its identity export
and a `FileStore` prekey vault in its directory:

```
(cd sdk-swift && swift build -c release --product ACEInterop)
ACE_INTEROP_SWIFT="$(cd sdk-swift && swift build -c release --show-bin-path)/ACEInterop" bash ace-spec/interop/run.sh
```

`matrix.py` invokes it exactly like the other drivers (`<exe> <subcommand> <dir> ... --now N`).

## Card cases (per verifier)

Each SDK runs `verify-card` over the card records of identities `a` (with a handle) and `b` (without)
of every SDK, and over tampered copies of each:

| Case | Expectation |
|---|---|
| `valid` | `{ok: true, aceId, handle?, contact: "open", listed: false}`, `aceId` that of the identity's `agent.json` and `handle` present exactly for `a` (the matrix also checks the generated record against the `gen-identity` contract) |
| `tamper-signature` (a flipped byte of `signature.value`), `tamper-listed`, `tamper-contact` | the signature covers every claim: `invalid_authorization` |
| `tamper-unknown-member` (`x` added) | the record is closed: `invalid_authorization` |
| `tamper-seq` | `signature.seq` names an unknown delegation: `stale_peer_binding` |

## Packet cases (per directed pair)

| Case | Expectation |
|---|---|
| `text` (non-ASCII), `receipt-delivered`, `receipt-rejected` (code + renewal permit), `receipt-unknown-prekey` (`prekey` member), `contact-request`, `contact-accepted`, `contact-rejected` | opened; content equals the sender's `P.content.json` |
| `text-old-but-in-window` | the text packet opened 3600 s later |
| `contact-old-but-in-window` | the contact request opened 3 hours later: opened (contacts share the offline window) |
| `unknown-prekey` | validly signed packet encrypted to a prekey the receiver never held: `unknown_prekey` |
| `future` | signed at `now + 301`: `stale_timestamp` |
| `stale-contact` | the contact request opened `OFFLINE_WINDOW_SECONDS + 1` (604801 s) later: `stale_timestamp` |
| `tamper-payload`, `tamper-kem`, `tamper-prekey-id`, `tamper-timestamp`, `tamper-message-id` | the signature commits to every field and is verified before decryption: `invalid_signature` |
| `tamper-seq` | `signature.seq` names an unknown delegation: `stale_peer_binding` |
| `tamper-from` | `from` rewritten to a bystander (its agent supplied): `invalid_signature` |
| `tamper-to` | `wrong_recipient` |
| `tamper-version` (`ace: "2"`) | `unsupported_version` (any value other than `"1"`) |
| `tamper-unknown-member` | `invalid_packet` |
| `tamper-short-kem` (1119 bytes) | `invalid_packet` |

Deterministic byte-level checks (headers, HKDF keys, payloads, X-Wing known answers) live in
`../test-vectors.json`; this matrix checks that independently generated randomized artifacts
interoperate.

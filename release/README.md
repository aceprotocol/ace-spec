# Reproducible pre-release bundles

These scripts package and smoke-test the reviewed source combination. They do not publish packages, push Git refs or deploy services. Registry names and version numbers identify the intended distributions; publication is a separate operation.

Every package is pure source: there is no native or WASM engine to build. Cryptography comes from each language's libraries (`@noble/post-quantum` / `@noble/hashes` in TypeScript, `cryptography` (ML-DSA, ML-KEM-768, X25519) in Python, with X-Wing composed in `ace/_xwing.py`, CryptoKit in Swift).

| Repository | Distribution | Entry point |
|---|---|---|
| `sdk-ts` | npm `@ace-protocol/sdk` | single export `.` (`src/index.ts`) |
| `sdk-py` | PyPI `ace-sdk` (pure wheel) | `ace` (`ace/__init__.py`) |
| `sdk-swift` | SwiftPM package `ace-sdk-swift` | product `ACE` (one target, no dependencies) |
| `relay` | npm `@ace-protocol/relay`, container image | `dist/src/server.js` |
| `ace-cli` | npm `@ace-protocol/cli` | `ace` binary |
| `ace-mcp` | npm `@ace-protocol/mcp`, container image | hosted MCP server |

Use Node 24, Python 3.10+ and Swift 6.2+ on macOS 26+. The release manifest records full source commits. Fetch those commits before building; do not substitute floating branches. Publish the source commits before running remote workflows that check them out.

## Node packages

From the directory containing all repositories:

```sh
for p in sdk-ts relay ace-cli ace-mcp; do npm --prefix $p ci && npm --prefix $p run build; done
node ace-spec/release/package-node.mjs /tmp/ace-release-candidate/node
```

`package-node.mjs` refuses a checkout with uncommitted changes, stages each distribution (`dist`, plus `resources`, `openapi.yaml`, `LICENSE`, `README.md` where present), replaces sibling `file:` dependencies with the exact release versions and emits tarballs plus `manifest.json` (repository, commit, package, version, SHA-256). The source checkouts keep their development workspace dependencies. Install all four tarballs together into an empty consumer directory; this resolves the unpublished exact dependencies locally:

```sh
mkdir -p /tmp/ace-consumer && cd /tmp/ace-consumer && npm init -y
npm install /tmp/ace-release-candidate/node/*.tgz
cp <workspace>/ace-spec/release/standalone-smoke.mjs . && node standalone-smoke.mjs
```

The smoke test needs a disposable Redis (`ACE_SMOKE_REDIS`, default `redis://127.0.0.1:16379`) and uses **only databases 14 and 15** (`ACE_SMOKE_DBS=a,b`), which it flushes. It creates an identity with the installed `ace` CLI in a throwaway `ACE_HOME`, starts two installed relays on loopback, and runs the SDK `NetworkClient` through publication (registering on demand), contact request, automatic acceptance, message and delivery receipt across the two relays, with the receiver restarted from its `FileStore` while the message is queued. It removes its temporary files afterwards. Remove the consumer directory to uninstall.

## Python wheel

```sh
sdk-py/.venv/bin/pip wheel --no-deps -w /tmp/ace-release-candidate/python ./sdk-py
python3 -m venv /tmp/ace-python-consumer
/tmp/ace-python-consumer/bin/pip install /tmp/ace-release-candidate/python/*.whl
cd /tmp && /tmp/ace-python-consumer/bin/python -I <workspace>/ace-spec/release/standalone-python.py
```

The wheel is `py3-none-any`. The smoke test refuses to run against a checkout, exchanges a text packet and its signed receipt between two identities in memory, and reopens the receiver from its `FileStore` and 0600 prekey file before the packet arrives.

## Swift package

The Swift SDK is consumed from source: tag the reviewed commit of `sdk-swift` and depend on it with `.package(url: ..., exact: "<version>")` (or `.package(path:)` for a local checkout), product `ACE`. Verify with:

```sh
swift build --package-path sdk-swift
swift test --package-path sdk-swift
```

The automated suite runs on macOS arm64; iOS builds of the same target are not exercised on a device here.

## Validation and source pins

Run each repository's suite on its declared runtime (relay/MCP/CLI document their Redis database assignments in their test helpers). Then, from `ace-spec/`:

```sh
python3 scripts/check-sdk-artifacts.py --sdk-ts ../sdk-ts --sdk-py ../sdk-py --sdk-swift ../sdk-swift
bash interop/run.sh            # TS/Py packet, receipt, contact and card record matrix; ACE_INTEROP_SWIFT adds Swift
```

and the website generator in `--check` mode. Relay and MCP workflows pin full spec/SDK commits (`SDK_TS_SHA`, `ACE_SPEC_SHA`) and vendor the SDK tarball into the image build (`scripts/vendor-local-deps.sh`). Checksums detect artifact mismatch; they are not signatures or a security audit. A locally passing release candidate implies no published deployment.

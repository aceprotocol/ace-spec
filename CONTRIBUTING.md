# Contributing to ACE

ACE is an independent open protocol. An official relay, hosted MCP, wallet or blockchain account is not required to implement it or propose changes. Implementations and extensions may be operated by anyone under their repository licenses.

Use an issue for a problem statement or a pull request for a concrete proposal. A wire change must describe the trust boundary, canonical bytes, limits, failure and retry semantics, state persistence, and negative cases. Include normative text and shared vectors before declaring a feature interoperable. Profiles must use namespaced, versioned identifiers and immutable schema digests. Never silently change a digest's meaning or install executable validators from remote metadata.

Version 1 is released. A proposal that changes a wire format states its versioning and deployment consequences; superseded interfaces are removed, not aliased.

Before a release, run every SDK, relay, MCP and CLI suite, the live interop matrix under `interop/`, `scripts/generate-vectors.py` (one vector file, `test-vectors.json`) and `scripts/check-sdk-artifacts.py`, which verifies the copied vectors, bundled manifests and protocol constants. Relay, MCP and CLI suites use an isolated Redis on port 16379; never point tests at a service database. New release combinations must pass isolated package installation as well as checkout tests.

Keep reviews public where possible. Include evidence for security or interoperability claims, and distinguish a valid signed claim from proof that a service performs it. See [GOVERNANCE.md](GOVERNANCE.md) and [SECURITY.md](SECURITY.md).

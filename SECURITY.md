# Reporting security issues

Do not publish private keys, tokens, production message contents or an unredacted exploit against a running deployment in a public issue. Use the affected repository's GitHub **Security → Report a vulnerability** action when available. If that private channel is unavailable, open a minimal issue asking maintainers for a private reporting channel; omit exploit details until a private channel is established. This repository does not advertise an unmonitored email address or promise a response SLA.

A useful report identifies affected source revisions and artifacts, prerequisites, the violated security property, a minimal local reproduction, and whether live credentials or users may be affected. Report service-operator configuration problems to that operator as well: independent relays and custodial endpoints have separate operational responsibility.

Passing conformance tests is not a cryptographic audit. The specification, vectors and implementations are public so that anyone can audit them; findings go through the channel above. ACE's post-quantum identity and transport protections do not upgrade a blockchain's algorithms or remove custody trust in a hosted MCP endpoint. Public discovery, contact metadata, timing, routing, traffic volume and denial of service are outside message-content confidentiality.

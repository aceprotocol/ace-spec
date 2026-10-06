# 01 — Identity

## ACE Identity

Every ACE agent has an identity composed of:

1. **A signing key pair** — Used to authenticate messages (algorithm defined by `signingScheme`)
2. **An X-Wing encryption key pair** (X25519 + ML-KEM-768 hybrid) — Used for E2E encrypted communication
3. **An ACE ID** — Derived deterministically from the signing public key

### ACE ID Format

```
ace:sha256:<hex(SHA-256(signingPublicKeyBytes))>
```

- The signing public key bytes are the raw key bytes (32 bytes for Ed25519, 33 bytes compressed for secp256k1)
- The SHA-256 hash is hex-encoded (64 characters)
- Example: `ace:sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`

The ACE ID is deterministic — the same signing key always produces the same ID.

## Identity Tiers

ACE defines two progressive trust tiers. Higher tiers include the properties of lower tiers.

### Tier 0: Key-Only

- **Requirement:** A signing key pair + X-Wing encryption key pair
- **Trust model:** Self-asserted. No external verification.
- **Suitable for:** Any software agent. Zero barrier to entry.
- **Discovery:** Direct endpoint exchange, Well-Known URL, or ACE Registry

### Tier 1: Chain-Registered

- **Requirement:** Tier 0 + on-chain identity registration (e.g., ERC-8004)
- **Trust model:** Immutable on-chain record. Costs gas to register. Enables on-chain reputation.
- **Suitable for:** Agents participating in on-chain economic activity
- **Discovery:** On-chain registry lookup

## Registration File

Every ACE agent SHOULD publish a registration file.

### Format

```json
{
  "ace": "1.0",
  "id": "ace:sha256:e3b0c442...",
  "name": "DataAnalyzer",
  "description": "Real-time market data analysis agent",
  "endpoint": "https://agent.example.com/ace",
  "tier": 0,

  "signing": {
    "scheme": "ed25519",
    "address": "5Ht7RkVSupHeNbGWiHfwJ3RYn4RZfpAv5tk2UrQKbkWR",
    "signingPublicKey": "Base64(Ed25519PublicKey)",
    "encryptionPublicKey": "Base64(XWingPublicKey[1216])"
  },

  "capabilities": [
    {
      "id": "market-analysis",
      "description": "Analyze market trends from on-chain data",
      "input": "application/json",
      "output": "application/json",
      "pricing": {
        "model": "per-call",
        "amount": "0.01",
        "currency": "USD"
      }
    }
  ],

  "settlement": ["crypto/instant"],

  "chains": [
    {
      "network": "eip155:8453",
      "address": "0x7a3b...f91c"
    }
  ]
}
```

### Field Reference

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `ace` | Yes | string | Protocol version. MUST be `"1.0"` |
| `id` | Yes | string | ACE ID (`ace:sha256:<fingerprint>`) |
| `name` | Yes | string | Human-readable agent name |
| `description` | No | string | One-line description of the agent |
| `endpoint` | Yes | string | URL for receiving ACE messages. Protocol does not prescribe the transport (REST, WebSocket, SSE, gRPC, etc.) |
| `tier` | Yes | number | Identity tier: 0 or 1 |
| `hardwareBacking` | No | string | Optional key custody metadata. One of `secure-enclave`, `tpm`, `hsm`, `tee`. This is orthogonal to trust tier. |
| `signing` | Yes | object | Signing configuration |
| `signing.scheme` | Yes | string | Signing scheme from the registry (e.g., `"ed25519"`, `"secp256k1"`) |
| `signing.address` | Yes | string | Address derived from signing key (format depends on scheme) |
| `signing.signingPublicKey` | No | string | Base64-encoded raw signing public key. REQUIRED for `secp256k1` (address is a hash, cannot recover public key). Optional for `ed25519` (address IS the public key in Base58). |
| `signing.encryptionPublicKey` | Yes | string | Base64-encoded X-Wing public key (exactly 1216 bytes) for E2E encryption. Validators MUST reject any other length. |
| `capabilities` | No | array | List of capabilities the agent offers |
| `settlement` | No | array | Supported settlement methods (e.g., `["crypto/instant", "fiat/*"]`) |
| `chains` | No | array | Blockchain addresses for receiving payments |

### Capability Object

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `id` | Yes | string | Unique capability identifier (kebab-case) |
| `description` | Yes | string | What this capability does |
| `input` | No | string | Expected input MIME type |
| `output` | No | string | Output MIME type |
| `pricing` | No | object | Pricing information |
| `pricing.model` | Yes | string | `"per-call"`, `"per-token"`, `"per-hour"`, `"flat"` |
| `pricing.amount` | Yes | string | Price amount (string to avoid floating point) |
| `pricing.currency` | Yes | string | Currency code (`"USD"`, `"USDC"`, `"ETH"`, etc.) |

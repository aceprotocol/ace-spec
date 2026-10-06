#!/usr/bin/env python3
"""Generate the canonical cross-language test vectors for all ACE SDKs.

Uses deterministic seed keys so all three SDKs (TypeScript, Python, Swift) can
independently verify identity derivation, X-Wing (draft-connolly-cfrg-xwing-kem-11)
key generation / decapsulation, conversationId, signData, signatures and a full
encrypted message.

Output: ace-spec/test-vectors.json.

Install the current Python SDK in your environment, then run this script.
"""

import base64
import hashlib
import json
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
import ace.messages as _messages_mod  # noqa: E402
from ace import create_registration_request, build_registration_payload, AgentProfile, ProfilePricing
from ace import xwing  # noqa: E402
from ace.encryption import compute_conversation_id, get_ace_kem_salt  # noqa: E402
from ace.identity import SoftwareIdentity  # noqa: E402
from ace.messages import create_message, parse_message  # noqa: E402
from ace.security import ReplayDetector  # noqa: E402
from ace.signing import build_sign_data, encode_payload, encode_signature  # noqa: E402
from ace.state_machine import ThreadStateMachine  # noqa: E402


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def deterministic_seed(label: str) -> bytes:
    """Derive a deterministic 32-byte seed from a label."""
    return hashlib.sha256(f"ace-test-vector-v1:{label}".encode()).digest()


# === X-Wing draft-11 test vector 1 (Appendix) ===
# The published vectors file is the single source of this block: it is carried
# over verbatim from the existing file on every regeneration.
out_path = os.path.normpath(os.path.join(_HERE, "..", "test-vectors.json"))
try:
    with open(out_path) as f:
        _xw = json.load(f)["xwing"]
except (OSError, KeyError, ValueError) as exc:
    sys.exit(
        f"error: cannot read the X-Wing draft-11 vector 1 block from {out_path}: {exc}\n"
        "The 'xwing' block {seed, publicKey, ciphertext, sharedSecret} (hex) must already "
        "exist in ace-spec/test-vectors.json; restore it from git before regenerating."
    )
XWING_VECTOR_1 = {
    "seed": _xw["seed"],
    "publicKey": _xw["publicKey"],
    "ciphertext": _xw["ciphertext"],
    "sharedSecret": _xw["sharedSecret"],
}
_xw_seed = bytes.fromhex(XWING_VECTOR_1["seed"])
assert len(_xw_seed) == 32
assert len(bytes.fromhex(XWING_VECTOR_1["publicKey"])) == 1216
assert len(bytes.fromhex(XWING_VECTOR_1["ciphertext"])) == 1120
assert len(bytes.fromhex(XWING_VECTOR_1["sharedSecret"])) == 32
# The SDK must reproduce the draft vector before we publish anything derived from it.
assert xwing.public_key_from_seed(_xw_seed).hex() == XWING_VECTOR_1["publicKey"]
assert (
    xwing.decapsulate(bytes.fromhex(XWING_VECTOR_1["ciphertext"]), _xw_seed).hex()
    == XWING_VECTOR_1["sharedSecret"]
)

# === Alice (ed25519) ===
alice_signing_seed = deterministic_seed("alice-signing")
alice_encryption_seed = deterministic_seed("alice-encryption")  # X-Wing seed
alice = SoftwareIdentity("ed25519", alice_signing_seed, alice_encryption_seed)

# === Bob (secp256k1) ===
bob_signing_seed = deterministic_seed("bob-signing")
bob_encryption_seed = deterministic_seed("bob-encryption")  # X-Wing seed
bob = SoftwareIdentity("secp256k1", bob_signing_seed, bob_encryption_seed)

assert len(alice.get_encryption_public_key()) == 1216
assert len(bob.get_encryption_public_key()) == 1216

# === Derived values ===
conversation_id = compute_conversation_id(
    alice.get_encryption_public_key(),
    bob.get_encryption_public_key(),
)

# Fixed test values for signData computation
TIMESTAMP = 1741000000
MESSAGE_ID = "550e8400-e29b-41d4-a716-446655440000"
THREAD_ID = "interop-test"
KEM_CIPHERTEXT = b"\xaa" * 1120  # fixed, not a real encapsulation
CIPHERTEXT = b"fake-ciphertext-for-testing-only"

message_payload = encode_payload(
    "rfq",
    bob.get_ace_id(),
    conversation_id,
    MESSAGE_ID,
    THREAD_ID,
    KEM_CIPHERTEXT,
    CIPHERTEXT,
)

sign_data = build_sign_data("message", alice.get_ace_id(), TIMESTAMP, message_payload)

# Alice signs (ed25519 is deterministic)
signature, scheme = alice.sign(sign_data)
assert scheme == "ed25519"

# === Full encrypted message alice -> bob (real X-Wing encapsulation; random per run) ===
EXPECTED_BODY = {"message": "hello from python"}
encrypted_message = create_message(
    sender=alice,
    recipient_pub_key=bob.get_encryption_public_key(),
    recipient_ace_id=bob.get_ace_id(),
    type_="text",
    body=EXPECTED_BODY,
    state_machine=ThreadStateMachine(),
    timestamp=TIMESTAMP,
)
envelope = encrypted_message.to_dict()  # exact JSON object that goes on the wire
assert envelope["conversationId"] == conversation_id
assert len(base64.b64decode(envelope["encryption"]["kemCiphertext"])) == 1120

# Self-check: bob must parse + decrypt it (freshness check bypassed for the fixed timestamp).
_orig_fresh = _messages_mod.check_timestamp_freshness
_messages_mod.check_timestamp_freshness = lambda _ts, _floor=None: None
try:
    _parsed = parse_message(
        type(encrypted_message).from_dict(json.loads(json.dumps(envelope))),
        bob,
        alice.get_signing_public_key(),
        ThreadStateMachine(),
        ReplayDetector.from_export({"horizon": TIMESTAMP - 1, "senderHorizons": {}, "entries": []}),
        sender_encryption_pub_key=alice.get_encryption_public_key(),
    )
finally:
    _messages_mod.check_timestamp_freshness = _orig_fresh
assert _parsed.body == EXPECTED_BODY

registration_vectors = []
for name, identity in [("alice", alice), ("bob", bob)]:
    for mode in ["keep", "remove", "replace"]:
        profile = AgentProfile(name="Agent α", description="中文 / quote \"", image="https://example.com/a.png",
                               tags=["data", "defi"], capabilities=["translate"], chains=["eip155:8453"],
                               endpoint="https://example.com/ace", pricing=ProfilePricing(currency="USDC", max_amount="12.50"))
        opts = {} if mode == "keep" else {"profile": None if mode == "remove" else profile}
        request = create_registration_request(identity, timestamp=TIMESTAMP, **opts)
        payload = build_registration_payload(request["encryptionPublicKey"], request["signingPublicKey"], request["scheme"], **opts)
        registration_vectors.append({"agent": name, "mode": mode, "request": request,
                                     "signDataHex": build_sign_data("register-request", request["aceId"], TIMESTAMP, payload).hex()})

vectors = {
    "version": "1.0",
    "agents": {
        "alice": {
            "scheme": "ed25519",
            "signingPrivateKey": b64(alice_signing_seed),
            "encryptionPrivateKey": b64(alice_encryption_seed),
            "signingPublicKey": b64(alice.get_signing_public_key()),
            "encryptionPublicKey": b64(alice.get_encryption_public_key()),
            "address": alice.get_address(),
            "aceId": alice.get_ace_id(),
        },
        "bob": {
            "scheme": "secp256k1",
            "signingPrivateKey": b64(bob_signing_seed),
            "encryptionPrivateKey": b64(bob_encryption_seed),
            "signingPublicKey": b64(bob.get_signing_public_key()),
            "encryptionPublicKey": b64(bob.get_encryption_public_key()),
            "address": bob.get_address(),
            "aceId": bob.get_ace_id(),
        },
    },
    "xwing": XWING_VECTOR_1,
    "vectors": {
        "registrations": registration_vectors,
        "aceKemSalt": get_ace_kem_salt().hex(),
        "conversationId": conversation_id,
        "signData": {
            "action": "message",
            "aceId": alice.get_ace_id(),
            "timestamp": TIMESTAMP,
            "messagePayload": {
                "type": "rfq",
                "to": bob.get_ace_id(),
                "conversationId": conversation_id,
                "messageId": MESSAGE_ID,
                "threadId": THREAD_ID,
                "kemCiphertext": b64(KEM_CIPHERTEXT),
                "ciphertext": b64(CIPHERTEXT),
            },
            "signDataHex": sign_data.hex(),
        },
        "signature": {
            "scheme": "ed25519",
            "signDataHex": sign_data.hex(),
            "signatureValue": encode_signature(signature, "ed25519"),
        },
        "encryptedMessage": {
            "from": "alice",
            "to": "bob",
            "envelope": envelope,
            "expectedBody": EXPECTED_BODY,
        },
    },
}

with open(out_path, "w") as f:
    json.dump(vectors, f, indent=2)
    f.write("\n")

print(f"Generated {out_path}")
print(f"  Alice ACE ID:    {alice.get_ace_id()}")
print(f"  Bob ACE ID:      {bob.get_ace_id()}")
print(f"  Conversation ID: {conversation_id}")
print(f"  SignData hex:    {sign_data.hex()[:40]}...")
print(f"  Encrypted msgId: {envelope['messageId']}")

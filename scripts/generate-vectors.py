#!/usr/bin/env python3
"""Generate ``ace-spec/test-vectors.json``: the one shared conformance vector file.

Run with the Python SDK's interpreter from ``ace-spec/``::

    ../sdk-py/.venv/bin/python scripts/generate-vectors.py

Every expectation is written out from the specification (chapters 01-08, profiles/delegation.md,
profiles/commerce.md) and
asserted against the Python SDK while generating, so a generator run is also a conformance check of
sdk-py. Each section carries a ``rules`` string telling consumers exactly what to call.

Deterministic: identities (seeds derived from labels), prekeys, X-Wing encapsulations (the draft's
own vectors), nonces, message IDs and every byte string that does not contain an ML-DSA signature.
Hedged ML-DSA signatures (KEL ``sig`` values, operational signatures, auth headers) change on every
run: consumers verify them and never compare them; so do the encapsulations to peer prekeys (packets
encrypted to a key from ``peerSeeds``), which have no draft vector. Relay-side checks (auth headers, registration)
are self-checked by the small reference verifiers below, written from 07; sdk-py ships none.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import os
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ace import (
    ACEError, CORE, COMMERCE, DELEGATION, DELEGATION_TYPE, TEXT, Inbox, Outbox, PeerStore, PrekeyVault, PrivateMessage, ProfileManifest, Profiles, ReplayDetector,
    SoftwareIdentity, SoftwareKey, canonical_state_bytes, check_receipt_body, check_stranger_source, conversation_key, create_auth_headers,
    create_permit, create_registration_request, create_packet, decode_content, decode_packet, decrypt_packet, extend_kel, is_usable,
    key_digest, signing_message, verify_erc8004_registration, verify_kel, verify_operational_signature,
    verify_packet, verify_permit, verify_published_agent, verify_signature, create_card_record, verify_card_bundle,
    create_delegation_credential, delegation_rules, validate_delegation_ext, verify_delegation_credential,
)
from ace import _xwing
from ace._encoding import (
    CAIP10_RE, CAIP19_RE, check_json_value, from_base64, is_ace_id, is_handle, is_https_url, is_message_id,
    is_namespaced_id, is_sha256_hex, is_stream_id, is_thread_id, loads_json, wire_int,
)
from ace._net import is_blocked_address
from ace._relay_url import is_canonical_relay_url, normalize_relay_url
from ace._signing import encode_payload
from ace.commerce import ThreadStore, commerce_rules, validate_commerce_ext
from ace.card_record import validate_erc8004
from ace.identity import sign_claims
from ace.kel import create_inception, create_rotation, create_signing_delegation, event_bytes
from ace.packet import aead_key, check_window, packet_header, packet_sign_payload
from ace.prekeys import _entry, _Peer, _State
from ace.relay import map_relay_response
from ace.rules import MessageEvent
from ace.store import MemoryStore

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.dirname(HERE)
ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
ap.add_argument("--out", default=os.path.join(SPEC, "test-vectors.json"))
OUT = ap.parse_args().out

NOW = 1760140800
T0 = NOW - 86400  # every agent's log is dated T0 (bob's rotation T0 + 10)
RELAY = "https://relay.example"


def seed(label: str) -> bytes:
    return hashlib.sha256(f"ace-vectors-v8:{label}".encode()).digest()


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode()


def mid(n: int) -> str:
    """A deterministic lowercase UUIDv4."""
    h = hashlib.sha256(f"mid-{n}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{'89ab'[int(h[16], 16) % 4]}{h[17:20]}-{h[20:32]}"


def outcome(fn) -> str | None:
    """None on success, else the ACEError code; any other exception is reported as ``error``."""
    try:
        fn()
    except ACEError as exc:
        return exc.code
    except Exception:  # noqa: BLE001 - the spec only says "rejected" for some inputs
        return "error"
    return None


def expect(name: str, fn, code: str | None):
    got = outcome(fn)
    assert got == code, f"{name}: expected {code}, sdk-py gave {got}"


# =============================================================================== agents

class Agent:
    def __init__(self, name, root, nxt, signing, kel, *, extra_signing=None):
        self.name, self.root, self.next, self.signing, self.kel = name, root, nxt, signing, kel
        self.extra_signing = extra_signing or {}
        self.identity = SoftwareIdentity(root, nxt, signing, kel, NOW)
        self.id = self.identity.get_ace_id()
        self.state = verify_kel(kel, NOW)
        self.seq = self.state.signing.seq

    def export(self) -> dict:
        out = {"rootSeed": b64(self.root.seed), "signingSeed": b64(self.signing.seed), "kel": copy.deepcopy(self.kel)}
        if self.next is not None:
            out["nextRootSeed"] = b64(self.next.seed)
        return out

    def raw_sign(self, action: str, signed_at: int, payload: bytes, seq: int | None = None) -> dict:
        """An operational signature without the signer-side usability check (for negative vectors)."""
        seq = self.seq if seq is None else seq
        key = self.signing if seq == self.seq else self.extra_signing[seq]
        return {"scheme": "ml-dsa-65", "seq": seq, "value": b64(key.sign(signing_message(self.id, signed_at, seq, payload), action))}


def key(label):
    return SoftwareKey(seed(label))


def simple_agent(name, not_after=None) -> Agent:
    root, nxt, sgn = key(f"{name}-root"), key(f"{name}-next"), key(f"{name}-signing")
    icp = create_inception(root, key_digest(nxt.scheme, nxt.public_key()), T0)
    dlg = create_signing_delegation(verify_kel([icp], T0), root, sgn.public_key(), T0, not_after)
    return Agent(name, root, nxt, sgn, [icp, dlg])


alice = simple_agent("alice")
carol = simple_agent("carol", not_after=NOW + 100)  # signing delegation expires at NOW + 100
dave = simple_agent("dave")  # an ace:delegation:1 credential issuer


def make_bob() -> Agent:
    """Rotated once: icp, dlg(seq 1), rot(seq 2), dlg(seq 3)."""
    r1, r2, r3 = key("bob-root"), key("bob-next"), key("bob-next-2")
    s1, s2 = key("bob-signing-1"), key("bob-signing-2")
    icp = create_inception(r1, key_digest(r2.scheme, r2.public_key()), T0)
    d1 = create_signing_delegation(verify_kel([icp], T0), r1, s1.public_key(), T0)
    rot = create_rotation(verify_kel([icp, d1], T0), r2, key_digest(r3.scheme, r3.public_key()), T0 + 10)
    d3 = create_signing_delegation(verify_kel([icp, d1, rot], T0 + 10), r2, s2.public_key(), T0 + 10)
    return Agent("bob", r2, r3, s2, [icp, d1, rot, d3], extra_signing={1: s1})


bob = make_bob()
AGENTS = {a.name: a for a in (alice, bob, carol, dave)}

# =============================================================================== X-Wing (draft-11 Appendix C)

# The draft's own known-answer vectors 1-3 (Appendix C), transcribed verbatim in xwing-draft-11.json.
with open(os.path.join(HERE, "xwing-draft-11.json"), encoding="utf-8") as f:
    XWING = json.load(f)
for v in XWING:
    dk = _xwing.DecapsulationKey(bytes.fromhex(v["seed"]))
    assert dk.public_key.hex() == v["publicKey"]
    assert dk.decapsulate(bytes.fromhex(v["ciphertext"])).hex() == v["sharedSecret"]
    assert set(v) == {"seed", "publicKey", "ciphertext", "sharedSecret", "eseed"}


def prekey_of(seed_hex: str) -> dict:
    pk = _xwing.DecapsulationKey(bytes.fromhex(seed_hex)).public_key
    return {"id": hashlib.sha256(pk).hexdigest(), "publicKey": b64(pk)}


BOB_PREKEY_SEED = XWING[0]["seed"]  # bob's current prekey is the draft's first key
BOB_PREKEY = prekey_of(BOB_PREKEY_SEED)
OTHER_PREKEY = prekey_of(XWING[1]["seed"])  # a prekey bob does not hold
ALICE_PREKEY = prekey_of(seed("alice-prekey").hex())
# Peer prekeys (04 § Peer prekeys): X_OFFER_Y is the key X's vault offered Y (Y encrypts to it).
ALICE_OFFER_BOB_SEED = seed("alice-offer-bob").hex()
ALICE_OFFER_BOB = prekey_of(ALICE_OFFER_BOB_SEED)  # the prekey alice's contents carry to bob
BOB_OFFER_ALICE_SEED = seed("bob-offer-alice").hex()
BOB_OFFER_ALICE = prekey_of(BOB_OFFER_ALICE_SEED)  # bob's vault offered it to alice
BOB_OFFER_CAROL_SEED = seed("bob-offer-carol").hex()
BOB_OFFER_CAROL = prekey_of(BOB_OFFER_CAROL_SEED)  # bob's vault offered it to carol
CAROL_OFFER_BOB = prekey_of(seed("carol-offer-bob").hex())  # the prekey carol's contents carry to bob

# =============================================================================== encoding

B64 = [
    ("", True), ("QQ==", True), ("QR==", False), ("QUI=", True), ("QUJ=", False), ("QUJD", True),
    ("+/8=", True), ("-_8=", False), ("QQ", False), ("QQ=", False), ("QUJD====", False), ("QUJD\n", False),
    (" QUJD", False), ("QU JD", False), ("QUJDRA==", True), ("QUJDRB==", False), ("QUJDRA=", False), ("=QUJD", False),
]
base64_cases = []
for text, valid in B64:
    got = outcome(lambda: from_base64(text)) is None
    assert got == valid, text
    base64_cases.append({"text": text, "valid": valid, **({"hex": from_base64(text).hex()} if valid else {})})

CANONICAL = [
    ("key order", '{"b":1,"a":2,"c":{"z":null,"y":[true,false]}}', '{"a":2,"b":1,"c":{"y":[true,false],"z":null}}'),
    ("proper prefix sorts first", '{"ab":1,"a":2,"":3}', '{"":3,"a":2,"ab":1}'),
    ("code-point order, not UTF-16", '{"\\ud83d\\ude00":1,"\\ue000":2,"z":3}', '{"z":3,"":2,"\U0001F600":1}'),
    ("non-ASCII keys", '{"é":1,"e":2,"f":3}', '{"e":2,"f":3,"é":1}'),
    ("escapes exactly", '"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\\"\\\\\\/\\u007f\\u00e9\\ud83d\\ude00"',
     '"\\u0000\\u0001\\b\\t\\n\\u000b\\f\\r\\u001f\\"\\\\/\x7fé\U0001F600"'),
    ("integers", "[0,-0,1,1.0,1e3,9007199254740991,-5]", "[0,0,1,1,1000,9007199254740991,-5]"),
    ("ECMAScript number forms", "[0.1,1.5,-2.25,1e21,1e-7,123456789.125,1e300]", "[0.1,1.5,-2.25,1e+21,1e-7,123456789.125,1e+300]"),
    ("whitespace removed", ' { "a" : [ 1 , 2 ] } ', '{"a":[1,2]}'),
]
CANONICAL_ERRORS = [
    ("unpaired high surrogate", '"\\ud800"'),
    ("unpaired low surrogate in a key", '{"\\udc00":1}'),
    ("overflowing number literal", "[1e400]"),
]
canonical_cases = []
for name, text, want in CANONICAL:
    got = canonical_state_bytes(loads_json(text)).decode("utf-8")
    assert got == want, (name, got, want)
    canonical_cases.append({"name": name, "input": text, "canonical": want})


def _canonical_rejects(text):
    v = loads_json(text)
    check_json_value(v, "invalid_argument")
    canonical_state_bytes(v)


for name, text in CANONICAL_ERRORS:
    assert outcome(lambda: _canonical_rejects(text)) is not None, name
    canonical_cases.append({"name": name, "input": text, "error": True})

WIRE_INTS = [("0", 0), ("1000", 1000), ("1000.0", 1000), ("1e3", 1000), ("-0", 0), ("9007199254740991", 9007199254740991),
             ("9007199254740992", None), ("-1", None), ("1.5", None), ("true", None), ('"1"', None), ("null", None),
             ("[1]", None)]
wire_cases = []
for text, value in WIRE_INTS:
    assert wire_int(loads_json(text)) == value, text
    wire_cases.append({"json": text, "value": value})

IDENTIFIERS = {
    "aceId": (is_ace_id, [("ace:sha256:" + "0" * 64, True), ("ace:sha256:" + "A" * 64, False), ("ace:sha256:" + "0" * 63, False),
                          ("ace:sha512:" + "0" * 64, False), ("ace:sha256:" + "0" * 64 + "\n", False)]),
    "messageId": (is_message_id, [("550e8400-e29b-41d4-a716-446655440000", True), ("550E8400-E29B-41D4-A716-446655440000", False),
                                  ("550e8400-e29b-11d4-a716-446655440000", False), ("550e8400-e29b-41d4-c716-446655440000", False),
                                  ("550e8400e29b41d4a716446655440000", False)]),
    "hexDigest": (is_sha256_hex, [("a" * 64, True), ("A" * 64, False), ("a" * 63, False), ("g" * 64, False)]),
    "namespacedId": (is_namespaced_id, [("ace:text:1", True), ("urn:example:translate:v1", True), ("x-y.z+w:A/b?c#d", True),
                                        ("ace", False), ("Ace:text:1", False), ("1ace:x", False), (":x", False), ("ace:", False),
                                        ("ace:a b", False), ("ace:é", False), ("x:" + "a" * 254, True), ("x:" + "a" * 255, False)]),
    "threadId": (is_thread_id, [("t", True), ("thread-1 é😀", True), ("", False), ("a\x00b", False), ("a\x7fb", False),
                                ("😀" * 256, True), ("😀" * 257, False)]),
    "handle": (is_handle, [("abc", True), ("a-b9-c", True), ("a9b", True), ("a-9", True), ("ab", False), ("Abc", False),
                           ("9abc", False), ("a_b", False), ("a--b", False), ("abc-", False), ("-abc", False), ("a.b", False),
                           ("a" * 32, True), ("a" * 31 + "-", False), ("a" * 33, False), ("a-" * 15 + "ab", True),
                           ("a-" * 16 + "a", False)]),
    "streamId": (is_stream_id, [("1741000000000-0", True), ("0-0", True), ("1-", False), ("a-1", False), ("1" * 21 + "-0", False)]),
    "outcomeCode": (lambda v: isinstance(v, str) and re.fullmatch(r"[a-z0-9_]{1,64}", v) is not None,
                    [("unknown_prekey", True), ("a" * 64, True), ("a" * 65, False), ("Bad", False), ("", False), ("a-b", False)]),
    "caip10": (lambda v: CAIP10_RE.fullmatch(v) is not None,
               [("eip155:8453:0xabc", True), ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX", True), ("eip155:8453", False), ("EIP155:1:0x1", False)]),
    "caip19": (lambda v: CAIP19_RE.fullmatch(v) is not None,
               [("eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", True),
                ("solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp/token:EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", True),
                ("eip155:8453/erc721:0xabc/1", False), ("eip155:8453:0xabc", False)]),
}
identifier_cases = {}
for kind, (pred, cases) in IDENTIFIERS.items():
    for value, valid in cases:
        assert bool(pred(value)) == valid, (kind, value)
    identifier_cases[kind] = [{"value": v, "valid": ok} for v, ok in cases]

URLS = [
    ("https://example.com", True), ("https://example.com/", True), ("https://a.b-c.example.com:8443/p/a?q=1&r=%20#frag", True),
    ("https://1.2.3.4/x", True), ("https://example.com:65535", True), ("https://example.com:1", True),
    ("https://" + "a" * 63 + ".com", True), ("https://" + "a" * 64 + ".com", False),
    ("HTTPS://example.com", False), ("http://example.com", False), ("https://user@example.com", False),
    ("https://[::1]/", False), ("https://example.com:0", False), ("https://example.com:65536", False),
    ("https://example.com:", False), ("https://exa mple.com", False), ("https://example.com.", False),
    ("https://-example.com", False), ("https://a..b", False), ("https://a-.example", False), ("https://", False), ("https://exämple.com", False), ("https://example.com/\n", False),
    ("https://example.com\\path", False), ("https://example.com/\"q\"", False),
    ("https://" + ".".join(["a" * 63] * 3 + ["a" * 61]), True), ("https://" + ".".join(["a" * 63] * 4) + "/", False),
    ("https://example.com/" + "a" * (2048 - 20), True), ("https://example.com/" + "a" * (2049 - 20), False),
]
for u, ok in URLS:
    assert is_https_url(u) == ok, u
https_cases = [{"url": u, "valid": ok} for u, ok in URLS]

RELAY_URLS = [
    ("https://relay.aceprotocol.org", "https://relay.aceprotocol.org"), ("https://relay.aceprotocol.org//", "https://relay.aceprotocol.org"),
    ("HTTPS://Relay.AceProtocol.ORG/", "https://relay.aceprotocol.org"), ("https://relay.aceprotocol.org:443/", "https://relay.aceprotocol.org"),
    ("http://relay.example.com:80", "http://relay.example.com"), ("https://relay.example.com:80", "https://relay.example.com:80"),
    ("https://relay.example.com/Ace/V1/", "https://relay.example.com/Ace/V1"), ("http://127.0.0.1:3000/", "http://127.0.0.1:3000"),
    ("http://[::1]:3000/", "http://[::1]:3000"), ("http://[FE80::1]:8080/", "http://[fe80::1]:8080"),
    ("ftp://relay.example.com", None), ("relay.example.com", None), ("", None), ("https://user@relay.example.com", None),
    ("https://relay.example.com?x=1", None), ("https://relay.example.com/#", None), ("https://relay.example.com:65536", None),
    (" https://relay.example.com", None), ("https://relay.example.com/a\tb", None), ("https://relay.example.com:", None),
    ("https://relay.example.com:0", None), ("https://relay.example.com:0443", None), ("https://rélay.example.com", None),
    ("https://relay_1.example.com", None), ("http://[::g]", None), ("http://[fe80::1%25en0]/", None),
]
# 02 step 3 admits these hosts, so they normalize; they are not canonical relay URLs (the ACE HTTPS URL grammar's host
# has no IP literal, empty label, edge hyphen or trailing dot), so descriptor relays and card home reject them (SP11).
NON_CANONICAL_HOSTS = ["https://[::1]", "https://a..b", "https://-a.example", "https://a-.example", "https://example.com."]
RELAY_URLS += [(u, u) for u in NON_CANONICAL_HOSTS]
for u in NON_CANONICAL_HOSTS:
    assert not is_canonical_relay_url(u, allow_loopback=True), u
relay_url_cases = []
for u, norm in RELAY_URLS:
    if norm is None:
        assert outcome(lambda: normalize_relay_url(u)) == "invalid_argument", u
        relay_url_cases.append({"input": u, "error": "invalid_argument"})
    else:
        assert normalize_relay_url(u) == norm, u
        relay_url_cases.append({"input": u, "normalized": norm})

BLOCKED = [
    ("1.1.1.1", False), ("0.0.0.0", True), ("10.255.255.255", True), ("11.0.0.0", False), ("100.64.0.0", True),
    ("100.128.0.0", False), ("127.0.0.1", True), ("169.254.169.254", True), ("172.16.0.0", True), ("172.32.0.0", False),
    ("192.0.0.1", True), ("192.0.2.1", True), ("192.168.0.1", True), ("198.18.0.0", True), ("198.51.100.7", True),
    ("203.0.113.7", True), ("224.0.0.1", True), ("240.0.0.1", True), ("255.255.255.255", True),
    ("::", True), ("::1", True), ("2606:4700:4700::1111", False), ("100::1", True), ("2001:db8::1", True), ("fc00::1", True),
    ("fe80::1", True), ("ff02::1", True), ("::ffff:127.0.0.1", True), ("::ffff:8.8.8.8", False), ("64:ff9b::7f00:1", True),
    ("64:ff9b::808:808", False), ("2002:808:808::1", True), ("2001:0:4136:e378:8000:63bf:3fff:fdd2", True),
    ("2001:2::1", True), ("2001:200::1", False), ("3fff::1", True), ("5f00::1", True), ("fec0::1", True),
    ("::808:808", True), ("64:ff9b:1:808:8:800::", True), ("::ffff:0:808:808", True),
    ("example.com", True), ("", True), ("1.2.3", True), ("256.0.0.1", True), ("8.8.8.8%x", True), ("[::1]", True),
    ("fe80::1%en0", True), ("2606:4700:4700::1111%eth0", False),
]
for a, blocked in BLOCKED:
    assert is_blocked_address(a) == blocked, a
blocked_cases = [{"address": a, "blocked": b} for a, b in BLOCKED]

encoding = {
    "rules": (
        "base64: decode 'text' as canonical Base64 (valid => bytes == hex). canonicalJson: parse 'input' with the SDK's "
        "strict JSON reader and serialize with canonicalStateBytes; the UTF-8 result equals 'canonical', or (error: true) "
        "reading, the JSON-value check or serializing fails. wireInts: parse 'json'; the wire-integer reading is 'value' "
        "(null = rejected). identifiers: each predicate (02 § Identifiers; caip10/caip19 per 04 and profiles/commerce.md). "
        "httpsUrls: the ACE HTTPS URL grammar. relayUrls: normalizeRelayUrl. blockedAddresses: isBlockedAddress. "
        "conversationKey: both argument orders give 'key'."
    ),
    "base64": base64_cases,
    "canonicalJson": canonical_cases,
    "wireInts": wire_cases,
    "identifiers": identifier_cases,
    "httpsUrls": https_cases,
    "relayUrls": relay_url_cases,
    "blockedAddresses": blocked_cases,
    "conversationKey": {"a": alice.id, "b": bob.id, "key": conversation_key(alice.id, bob.id)},
}
assert conversation_key(bob.id, alice.id) == encoding["conversationKey"]["key"]

# =============================================================================== signing

def ep_case(fields):
    raw = [f.encode() if isinstance(f, str) else f for f in fields]
    return {"fields": [{"text": f} if isinstance(f, str) else {"hex": f.hex()} for f in fields], "hex": encode_payload(*raw).hex()}


M_CASES = [(alice.id, 0, None, b""), (alice.id, NOW, alice.seq, b"\x00\x01payload"), ("ace:sha256:" + "f" * 64, 9007199254740991, 9007199254740991, b"x" * 70)]
sig_message = signing_message(alice.id, NOW, alice.seq, b"vector")
sig_value = alice.signing.sign(sig_message, "packet")
assert verify_signature(sig_message, "packet", sig_value, alice.signing.public_key())
assert not verify_signature(sig_message, "agent-descriptor", sig_value, alice.signing.public_key())
# 02 § Signing actions: a delivery permit and an ace:delegation:1 credential (a profile's own signed object, signed with
# the profile ID as its action) have claims of the same shape ({issuer, subject, issuedAt, expiresAt}); only the context
# tells them apart.
SAME_SHAPE = {"issuer": dave.id, "subject": alice.id, "issuedAt": NOW - 100, "expiresAt": NOW + 3600}
same_message = signing_message(dave.id, NOW - 100, dave.seq, canonical_state_bytes(SAME_SHAPE))
same_value = dave.signing.sign(same_message, DELEGATION_TYPE)
assert verify_signature(same_message, DELEGATION_TYPE, same_value, dave.signing.public_key())
assert not verify_signature(same_message, "delivery-permit", same_value, dave.signing.public_key())
signing = {
    "rules": (
        "encodePayload(fields) == hex. message: M = encodePayload('ace.v1', aceId, decimal(timestamp), seqOrEmpty, payload) "
        "== messageHex, with seqOrEmpty empty when seq is null (a KEL event signature) and decimal(seq) otherwise. "
        "actionSeparation: ML-DSA-65 verify of 'signature' over messageHex under agents[signer]'s signing key with ctx = "
        "each listed action gives its boolean. The second entry signs credential-shaped claims (the same shape as a "
        "delivery permit's) with ctx 'ace:delegation:1' (the profile ID, profiles/delegation.md): only the context "
        "distinguishes the two objects."
    ),
    "encodePayload": [ep_case([]), ep_case([""]), ep_case(["ace", b"\x00\xff"]), ep_case(["é", "", b""])],
    "message": [{"aceId": a, "timestamp": t, "seq": q, "payloadHex": p.hex(), "messageHex": signing_message(a, t, q, p).hex()}
                for a, t, q, p in M_CASES],
    "actionSeparation": [
        {"signer": "alice", "messageHex": sig_message.hex(), "signature": b64(sig_value),
         "actions": {"packet": True, "agent-descriptor": False, "delivery-permit": False}},
        {"signer": "dave", "claims": SAME_SHAPE, "messageHex": same_message.hex(), "signature": b64(same_value),
         "actions": {DELEGATION_TYPE: True, "delivery-permit": False}},
    ],
}

# =============================================================================== KEL

def resign(ev, signer, ace_id):
    """Re-sign a KEL event under ``ace_id``; ``None`` for an inception, which signs under its own identifier."""
    ev = copy.deepcopy(ev)
    ev.pop("sig", None)
    eb = event_bytes(ev)
    if ace_id is None:
        ace_id = "ace:sha256:" + hashlib.sha256(eb).hexdigest()
    ev["sig"] = {"scheme": signer.scheme, "value": b64(signer.sign(signing_message(ace_id, ev["ts"], None, eb), "kel"))}
    return ev


A_KEL = alice.kel
a_root = alice.root
kel_invalid = []


def bad_kel(name, events, code, now=NOW):
    expect(f"kel {name}", lambda: verify_kel(events, now), code)
    kel_invalid.append({"name": name, "kel": events, "now": now, "error": code})


bad_kel("empty", [], "invalid_kel")
bad_kel("first event is not icp", [A_KEL[1]], "invalid_kel")
bad_kel("missing sig", [A_KEL[0], {k: v for k, v in A_KEL[1].items() if k != "sig"}], "invalid_kel")
bad_kel("unknown member", [A_KEL[0], {**A_KEL[1], "x": 1}], "invalid_kel")
_role = copy.deepcopy(A_KEL[1])
_role["role"] = "signing"
bad_kel("dlg role member (removed in this revision)", [A_KEL[0], _role], "invalid_kel")
bad_kel("seq gap", [A_KEL[0], resign({**A_KEL[1], "seq": 2}, a_root, alice.id)], "invalid_kel")
bad_kel("ts decreasing", [A_KEL[0], resign({**A_KEL[1], "ts": T0 - 1}, a_root, alice.id)], "invalid_kel")
bad_kel("ts beyond now + 300", A_KEL, "invalid_kel", now=T0 - 301)
bad_kel("prev mismatch", [A_KEL[0], resign({**A_KEL[1], "prev": "0" * 64}, a_root, alice.id)], "invalid_kel")
bad_kel("icp after seq 0", [A_KEL[0], {**A_KEL[0], "seq": 1}], "invalid_kel")
bad_kel("non-canonical base64 key", [{**A_KEL[0], "root": {"scheme": "ml-dsa-65", "publicKey": A_KEL[0]["root"]["publicKey"][:-4] + "AAB="}}], "invalid_kel")
_small = resign({**A_KEL[0], "root": {"scheme": "ml-dsa-65", "publicKey": b64(bytes(1951))}}, a_root, None)
bad_kel("root key of the wrong size", [_small], "invalid_kel")
bad_kel("root scheme not ml-dsa-65", [{**A_KEL[0], "root": {"scheme": "ml-dsa-44", "publicKey": A_KEL[0]["root"]["publicKey"]}}], "invalid_kel")
_icp_badsig = copy.deepcopy(A_KEL[0])
_icp_badsig["sig"]["value"] = b64(bytes(3309))
bad_kel("icp signature does not verify", [_icp_badsig], "invalid_signature")
bad_kel("dlg signed by a key other than the root", [A_KEL[0], resign(A_KEL[1], alice.next, alice.id)], "invalid_signature")
_x = copy.deepcopy(A_KEL[1])
_x["key"] = {"scheme": "x-wing", "publicKey": ALICE_PREKEY["publicKey"]}
bad_kel("dlg key is not ml-dsa-65", [A_KEL[0], resign(_x, a_root, alice.id)], "invalid_kel")
bad_kel("dlg notAfter not after ts", [A_KEL[0], resign({**A_KEL[1], "notAfter": T0}, a_root, alice.id)], "invalid_kel")
bad_kel("dlg notAfter beyond ts + MAX_SIGNING_KEY_LIFETIME", [A_KEL[0], resign({**A_KEL[1], "notAfter": T0 + 31622401}, a_root, alice.id)], "invalid_kel")
_rot_wrong = {"t": "rot", "seq": 2, "ts": T0 + 1, "prev": hashlib.sha256(event_bytes(A_KEL[1])).hexdigest(),
              "root": {"scheme": "ml-dsa-65", "publicKey": b64(dave.root.public_key())}, "next": "ab" * 32}
bad_kel("rot reveals a key that is not the committed next", A_KEL + [resign(_rot_wrong, dave.root, alice.id)], "invalid_kel")
_rot_old = {**_rot_wrong, "root": {"scheme": "ml-dsa-65", "publicKey": b64(alice.next.public_key())}}
bad_kel("rot signed by the old root", A_KEL + [resign(_rot_old, a_root, alice.id)], "invalid_signature")
_rot_scheme = resign(_rot_old, alice.next, alice.id)
_rot_scheme["sig"]["scheme"] = "ml-dsa-44"
bad_kel("sig scheme differs from the signing root", A_KEL + [_rot_scheme], "invalid_kel")
_prec = [_icp_badsig, A_KEL[1], resign({**A_KEL[1], "seq": 2, "prev": "0" * 64}, a_root, alice.id)]
bad_kel("structure before any signature (bad icp sig and a bad prev later)", _prec, "invalid_kel")

kel_valid = []
for a in AGENTS.values():
    st = a.state
    kel_valid.append({"agent": a.name, "now": NOW, "aceId": a.id, "seq": st.seq, "lastHash": st.last_hash, "rootScheme": st.root_scheme,
                      "next": st.next, "signing": {"seq": st.signing.seq, "notAfter": st.signing.not_after}, "usable": True})
kel_valid.append({"agent": "carol", "now": NOW + 100, "aceId": carol.id, "seq": 1, "lastHash": carol.state.last_hash, "rootScheme": "ml-dsa-65",
                  "next": carol.state.next, "signing": {"seq": 1, "notAfter": NOW + 100}, "usable": False})
_b2, _b3 = verify_kel(bob.kel[:2], NOW), verify_kel(bob.kel[:3], NOW)
kel_valid.append({"agent": "bob", "events": 2, "now": NOW, "aceId": bob.id, "seq": 1, "lastHash": _b2.last_hash,
                  "rootScheme": "ml-dsa-65", "next": _b2.next, "signing": {"seq": 1, "notAfter": None}, "usable": True})
kel_valid.append({"agent": "bob", "events": 3, "now": NOW, "aceId": bob.id, "seq": 2, "lastHash": _b3.last_hash,
                  "rootScheme": "ml-dsa-65", "next": _b3.next, "signing": None, "usable": False})
for c in kel_valid:
    st = verify_kel(AGENTS[c["agent"]].kel[: c.get("events")], c["now"])
    assert st.ace_id == c["aceId"] and st.seq == c["seq"] and st.last_hash == c["lastHash"]
    assert is_usable(st, c["now"]) == c["usable"]

event_bytes_cases = [{"event": ev, "hex": event_bytes(ev).hex()} for ev in bob.kel + [carol.kel[1]]]

# forks: frank, a fresh identity with several branches
f_root, f_next, f_next2 = key("frank-root"), key("frank-next"), key("frank-next-2")
f_icp = create_inception(f_root, key_digest("ml-dsa-65", f_next.public_key()), T0)
f_s = verify_kel([f_icp], T0)
f_d1 = create_signing_delegation(f_s, f_root, key("frank-s1").public_key(), T0)
f_d1b = create_signing_delegation(f_s, f_root, key("frank-s1b").public_key(), T0 + 1)
f_d2 = create_signing_delegation(verify_kel([f_icp, f_d1], T0), f_root, key("frank-s2").public_key(), T0 + 2)
f_rot = create_rotation(f_s, f_next, key_digest("ml-dsa-65", f_next2.public_key()), T0 + 3)
f_rot_d = create_signing_delegation(verify_kel([f_icp, f_rot], T0 + 3), f_next, key("frank-s3").public_key(), T0 + 3)
f_rot2 = create_rotation(f_s, f_next, key_digest("ml-dsa-65", key("frank-next-3").public_key()), T0 + 4)
f_rot2_d = create_signing_delegation(verify_kel([f_icp, f_rot2], T0 + 4), f_next, key("frank-s4").public_key(), T0 + 4)
FORKS = [
    ("no pin: adopted", None, [f_icp, f_d1], "adopted", 1),
    ("equal: unchanged", [f_icp, f_d1], [f_icp, f_d1], "unchanged", 1),
    ("prefix: unchanged (the pin is kept)", [f_icp, f_d1, f_d2], [f_icp, f_d1], "unchanged", 2),
    ("extension: extended", [f_icp, f_d1], [f_icp, f_d1, f_d2], "extended", 2),
    ("rot at the fork point, no rot pinned after it: recovered", [f_icp, f_d1, f_d2], [f_icp, f_rot, f_rot_d], "recovered", 2),
    ("dlg fork: kel_conflict", [f_icp, f_d1], [f_icp, f_d1b], "kel_conflict", None),
    ("rot fork against a pinned rot: kel_conflict", [f_icp, f_rot, f_rot_d], [f_icp, f_rot2, f_rot2_d], "kel_conflict", None),
    ("different identity: kel_conflict", [f_icp, f_d1], alice.kel, "kel_conflict", None),
]
fork_cases = []
for name, pinned, cand, want, seq in FORKS:
    pin_state = None if pinned is None else verify_kel(pinned, NOW)
    if want == "kel_conflict":
        expect(name, lambda: extend_kel(pin_state, cand, NOW), "kel_conflict")
        fork_cases.append({"name": name, "pinned": pinned, "candidate": cand, "now": NOW, "error": "kel_conflict"})
    else:
        st, got = extend_kel(pin_state, cand, NOW)
        assert got == want and st.seq == seq, (name, got)
        fork_cases.append({"name": name, "pinned": pinned, "candidate": cand, "now": NOW, "outcome": want, "seq": seq})

# operational signatures (01 § Operational signatures)
OP_PAYLOAD = b"operational-vector"
op_cases = []


def op_case(name, signer, signed_at, sig, now, code, action="packet"):
    st = verify_kel(signer.kel, now)
    expect(name, lambda: verify_operational_signature(st, sig, OP_PAYLOAD, action, signed_at, now), code)
    op_cases.append({"name": name, "signer": signer.name, "action": action, "timestamp": signed_at, "payloadHex": OP_PAYLOAD.hex(),
                     "signature": sig, "now": now, "error": code})


op_case("valid (bob, seq 3)", bob, NOW, bob.raw_sign("packet", NOW, OP_PAYLOAD), NOW, None)
op_case("signed at the delegating dlg's ts (bob, seq 3)", bob, T0 + 10, bob.raw_sign("packet", T0 + 10, OP_PAYLOAD), NOW, None)
op_case("signed one second before the delegating dlg: stale_peer_binding", bob, T0 + 9, bob.raw_sign("packet", T0 + 9, OP_PAYLOAD), NOW,
        "stale_peer_binding")
op_case("superseded delegation seq: stale_peer_binding", bob, NOW, bob.raw_sign("packet", NOW, OP_PAYLOAD, seq=1), NOW, "stale_peer_binding")
op_case("signed before notAfter (carol)", carol, NOW + 99, carol.raw_sign("packet", NOW + 99, OP_PAYLOAD), NOW, None)
op_case("signed at notAfter: stale_peer_binding", carol, NOW + 100, carol.raw_sign("packet", NOW + 100, OP_PAYLOAD), NOW, "stale_peer_binding")
op_case("back-dated: signed before notAfter, verified at or after it (rule 5): stale_peer_binding", carol, NOW + 50,
        carol.raw_sign("packet", NOW + 50, OP_PAYLOAD), NOW + 100, "stale_peer_binding")
op_case("another action's signature: invalid_signature", alice, NOW, alice.raw_sign("delivery-permit", NOW, OP_PAYLOAD), NOW, "invalid_signature")
_s44 = alice.raw_sign("packet", NOW, OP_PAYLOAD)
op_case("scheme ml-dsa-44: invalid_signature", alice, NOW, {**_s44, "scheme": "ml-dsa-44"}, NOW, "invalid_signature")
op_case("signature of the wrong size: invalid_signature", alice, NOW, {**_s44, "value": b64(bytes(3308))}, NOW, "invalid_signature")

kel = {
    "rules": (
        "valid: verifyKel(agents[agent].kel[0:events or all], now) gives aceId, seq, lastHash, rootScheme, next, the "
        "signing delegation {seq, notAfter} (null when none) and isUsable(state, now). invalid: verifyKel(kel, now) fails "
        "with 'error' (rule 1 structure is checked for the whole log before any signature). eventBytes: canonical bytes of "
        "each event. forks: extendKel(pinned ? verifyKel(pinned, now) : null, candidate, now) gives 'outcome' and the "
        "resulting state's seq, or fails with 'error'. operational: 01 § Operational signatures rules 1-5 (rule 3: the "
        "timestamp is at or after the ts of the delegating dlg and before its notAfter) for "
        "'signature' over M(agents[signer].aceId, timestamp, signature.seq, payload) with ctx 'action' against "
        "verifyKel(agents[signer].kel, now), the signer usable at 'now' (rule 5): error null = valid."
    ),
    "valid": kel_valid,
    "invalid": kel_invalid,
    "eventBytes": event_bytes_cases,
    "forks": fork_cases,
    "operational": op_cases,
}

# =============================================================================== packet

SALT = b""  # 03 § Encryption: HKDF salt is the empty string
PKT_MID = "550e8400-e29b-41d4-a716-446655440000"
PKT_NONCE = bytes(range(12))
TEXT_DIGEST = TEXT.messages["ace:text:1"].digest
CONTENT = {"type": "ace:text:1", "schemaDigest": TEXT_DIGEST, "threadId": "thread-1", "body": {"message": "hello, bob"},
           "prekey": ALICE_OFFER_BOB["publicKey"]}
PLAINTEXT = canonical_state_bytes(CONTENT)
KEM = bytes.fromhex(XWING[0]["ciphertext"])
SS = bytes.fromhex(XWING[0]["sharedSecret"])
header = packet_header(alice.id, bob.id, PKT_MID, NOW, BOB_PREKEY["id"], KEM)
AEAD_KEY = HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=header).derive(SS)
assert AEAD_KEY == aead_key(SS, header)
payload = PKT_NONCE + AESGCM(AEAD_KEY).encrypt(PKT_NONCE, PLAINTEXT, header)

det_packet = create_packet(alice.identity, bob.id, BOB_PREKEY, PLAINTEXT, timestamp=NOW, message_id=PKT_MID, _kem=(SS, KEM), _nonce=PKT_NONCE)
assert det_packet["encryption"] == {"prekey": BOB_PREKEY["id"], "kemCiphertext": b64(KEM), "payload": b64(payload)}
sign_payload = packet_sign_payload(bob.id, PKT_MID, BOB_PREKEY["id"], KEM, payload)
packet_message = signing_message(alice.id, NOW, alice.seq, sign_payload)
assert verify_signature(packet_message, "packet", base64.b64decode(det_packet["signature"]["value"]), alice.signing.public_key())


def bob_vault(peer_seeds=None):
    """bob's vault: his published current prekey, and for each ``peer_seeds`` entry (aceId -> seed hex) the
    peer prekey offered to that peer, offeredAt NOW (test-only injection)."""
    v = PrekeyVault()
    peers = {pid: _Peer(offered=_entry(bytes.fromhex(sd), NOW)) for pid, sd in (peer_seeds or {}).items()}
    v._state = _State(_entry(bytes.fromhex(BOB_PREKEY_SEED), T0), [], peers)
    return v


def open_pkt(pkt, recipient, sender: Agent, now, peer_seeds=None):
    """06 steps 1, 4, 5, 6 and the private-content parse of 7."""
    p = decode_packet(pkt)
    if p.to_id != recipient:
        raise ACEError("wrong_recipient", "")
    verify_packet(p, verify_kel(sender.kel, now), now)
    check_window(p, now)
    return PrivateMessage.of(p, decode_content(decrypt_packet(p, bob_vault(peer_seeds), now)))


msg = open_pkt(det_packet, bob.id, alice, NOW)
assert msg.body == CONTENT["body"] and msg.thread_id == "thread-1"


def mutate(base, path, value):
    out = copy.deepcopy(base)
    cur = out
    for k in path[:-1]:
        cur = cur[k]
    if value is DELETE:
        del cur[path[-1]]
    else:
        cur[path[-1]] = value
    return out


DELETE = object()
decode_cases = []


def dec_case(name, pkt=None, code=None, json_text=None):
    value = loads_json(json_text) if json_text is not None else pkt
    expect(f"decode {name}", lambda: decode_packet(value), code)
    decode_cases.append({"name": name, **({"json": json_text} if json_text is not None else {"packet": pkt}), "error": code})


P = det_packet
dec_case("valid", P, None)
dec_case("timestamp written as 1.7601408e9 (a wire integer)", code=None,
         json_text=json.dumps(P, separators=(",", ":")).replace(f'"timestamp":{NOW}', '"timestamp":1.7601408e9'))
dec_case("seq written as 1.0", code=None, json_text=json.dumps(P, separators=(",", ":")).replace('"seq":1', '"seq":1.0'))
dec_case("ace 2: unsupported_version", mutate(P, ["ace"], "2"), "unsupported_version")
dec_case("ace 1 as a number", mutate(P, ["ace"], 1), "invalid_packet")
dec_case("ace missing", mutate(P, ["ace"], DELETE), "invalid_packet")
dec_case("unknown member", {**P, "conversationId": "ab" * 32}, "invalid_packet")
dec_case("unknown encryption member", mutate(P, ["encryption", "x"], 1), "invalid_packet")
dec_case("unknown signature member", mutate(P, ["signature", "x"], 1), "invalid_packet")
dec_case("uppercase messageId", mutate(P, ["messageId"], PKT_MID.upper()), "invalid_packet")
dec_case("from equals to", mutate(P, ["to"], alice.id), "invalid_packet")
dec_case("negative timestamp", mutate(P, ["timestamp"], -1), "invalid_packet")
dec_case("string timestamp", mutate(P, ["timestamp"], str(NOW)), "invalid_packet")
dec_case("fractional timestamp", mutate(P, ["timestamp"], NOW + 0.5), "invalid_packet")
dec_case("uppercase prekey id", mutate(P, ["encryption", "prekey"], BOB_PREKEY["id"].upper()), "invalid_packet")
dec_case("kemCiphertext of 1119 bytes", mutate(P, ["encryption", "kemCiphertext"], b64(KEM[:-1])), "invalid_packet")
dec_case("non-canonical payload Base64", mutate(P, ["encryption", "payload"], b64(bytes(29)).rstrip("=")), "invalid_packet")
dec_case("payload of 27 bytes", mutate(P, ["encryption", "payload"], b64(bytes(27))), "invalid_packet")
dec_case("signature scheme ml-dsa-44", mutate(P, ["signature", "scheme"], "ml-dsa-44"), "invalid_packet")
dec_case("signature seq as a string", mutate(P, ["signature", "seq"], "1"), "invalid_packet")
dec_case("signature of 3308 bytes", mutate(P, ["signature", "value"], b64(bytes(3308))), "invalid_packet")
dec_case("not an object", [P], "invalid_packet")

# open cases: decode -> recipient -> signature -> window -> decrypt -> private content
open_cases = []


def open_case(name, pkt, sender, now, code, recipient=None, peer_seeds=None):
    recipient = bob.id if recipient is None else recipient
    expect(f"open {name}", lambda: open_pkt(pkt, recipient, AGENTS[sender] if isinstance(sender, str) else sender, now, peer_seeds), code)
    rname = next(n for n, a in AGENTS.items() if a.id == recipient)
    open_cases.append({"name": name, "packet": pkt, "sender": sender if isinstance(sender, str) else sender.name, "recipient": rname,
                       "now": now, **({"peerSeeds": peer_seeds} if peer_seeds else {}), "error": code})


def flip_b64(text, index):
    raw = bytearray(base64.b64decode(text))
    raw[index] ^= 1
    return b64(bytes(raw))


def manual_packet(sender: Agent, to, prekey, content, ts, *, seq=None, kem=KEM, ss=SS, mid_=PKT_MID, nonce=PKT_NONCE):
    """``content``: a dict (canonical JSON) or raw plaintext bytes. ``kem=None``: a fresh encapsulation to ``prekey``."""
    if kem is None:
        ss, kem = _xwing.encapsulate(base64.b64decode(prekey["publicKey"]))
    pt = canonical_state_bytes(content) if isinstance(content, dict) else content
    hdr = packet_header(sender.id, to, mid_, ts, prekey["id"], kem)
    k = HKDF(algorithm=hashes.SHA256(), length=32, salt=SALT, info=hdr).derive(ss)
    pl = nonce + AESGCM(k).encrypt(nonce, pt, hdr)
    sig = sender.raw_sign("packet", ts, encode_payload(to, mid_, prekey["id"], kem, pl), seq=seq)
    return {"ace": "1", "messageId": mid_, "from": sender.id, "to": to, "timestamp": ts,
            "encryption": {"prekey": prekey["id"], "kemCiphertext": b64(kem), "payload": b64(pl)}, "signature": sig}


open_case("valid", P, "alice", NOW, None)
open_case("valid at the end of the offline window", P, "alice", NOW + 604800, None)
open_case("older than the offline window: stale_timestamp", P, "alice", NOW + 604801, "stale_timestamp")
open_case("more than 300 s in the future: stale_timestamp", P, "alice", NOW - 301, "stale_timestamp")
open_case("addressed to someone else: wrong_recipient", P, "alice", NOW, "wrong_recipient", recipient=carol.id)
open_case("kemCiphertext tampered: invalid_signature (signature before decryption)",
          mutate(P, ["encryption", "kemCiphertext"], flip_b64(P["encryption"]["kemCiphertext"], 5)), "alice", NOW, "invalid_signature")
open_case("payload tampered: invalid_signature", mutate(P, ["encryption", "payload"], flip_b64(P["encryption"]["payload"], 20)), "alice", NOW, "invalid_signature")
open_case("timestamp changed: invalid_signature", mutate(P, ["timestamp"], NOW + 1), "alice", NOW, "invalid_signature")
open_case("superseded seq: stale_peer_binding", mutate(P, ["signature", "seq"], 0), "alice", NOW, "stale_peer_binding")
# carol re-encrypts nothing: the same ciphertext, re-signed under her identity
resigned = {**P, "from": carol.id, "signature": carol.raw_sign("packet", NOW, encode_payload(bob.id, PKT_MID, BOB_PREKEY["id"], KEM, base64.b64decode(P["encryption"]["payload"])))}
open_case("stripped and re-signed by another identity: decryption_failed (header binds from)", resigned, "carol", NOW, "decryption_failed")
open_case("prekey the receiver does not hold: unknown_prekey",
          manual_packet(alice, bob.id, OTHER_PREKEY, CONTENT, NOW, kem=bytes.fromhex(XWING[1]["ciphertext"]), ss=bytes.fromhex(XWING[1]["sharedSecret"])),
          "alice", NOW, "unknown_prekey")
open_case("signed at the delegation's notAfter: stale_peer_binding", manual_packet(carol, bob.id, BOB_PREKEY, CONTENT, NOW + 100), "carol", NOW, "stale_peer_binding")
open_case("back-dated: signed before the delegation's notAfter, opened after it (06 step 4): stale_peer_binding",
          manual_packet(carol, bob.id, BOB_PREKEY, CONTENT, NOW + 50), "carol", NOW + 150, "stale_peer_binding")
open_case("timestamp before the sender's dlg ts: stale_peer_binding", manual_packet(alice, bob.id, BOB_PREKEY, CONTENT, T0 - 1), "alice",
          NOW, "stale_peer_binding")
open_case("plaintext is not private content: invalid_body",
          manual_packet(alice, bob.id, BOB_PREKEY, b'{"type":"ace:text:1","body":{}}', NOW), "alice", NOW, "invalid_body")
open_case("AEAD key from the wrong shared secret: decryption_failed",
          manual_packet(alice, bob.id, BOB_PREKEY, CONTENT, NOW, ss=bytes(32)), "alice", NOW, "decryption_failed")
# peer prekeys (04 § Peer prekeys): a key bob's vault offered a peer opens only that peer's packets
open_case("opened under a peer prekey", manual_packet(alice, bob.id, BOB_OFFER_ALICE, CONTENT, NOW, kem=None), "alice", NOW, None,
          peer_seeds={alice.id: BOB_OFFER_ALICE_SEED})
open_case("peer prekey of another peer: unknown_prekey", manual_packet(alice, bob.id, BOB_OFFER_CAROL, CONTENT, NOW, kem=None),
          "alice", NOW, "unknown_prekey", peer_seeds={carol.id: BOB_OFFER_CAROL_SEED})
open_case("content missing prekey: invalid_body",
          manual_packet(alice, bob.id, BOB_PREKEY, {k: v for k, v in CONTENT.items() if k != "prekey"}, NOW), "alice", NOW, "invalid_body")

packet = {
    "rules": (
        "deterministic: header = encodePayload('ace.v1.packet', from, to, messageId, decimal(timestamp), prekeyId, "
        "kemCiphertext) == headerHex; key = HKDF-SHA256(ikm = ss, salt = saltHex (empty), info = header, L = 32) == keyHex; "
        "payload = nonce || AES-256-GCM(key, nonce, plaintext, aad = header) == payloadHex; createPacket with the injected "
        "(sharedSecret, kemCiphertext, nonce) reproduces packet.encryption exactly; signPayloadHex = encodePayload(to, "
        "messageId, prekeyId, kemCiphertext, payload) and messageHex = M(from, timestamp, seq, signPayload), over which "
        "packet.signature verifies against agents.alice with ctx 'packet'. plaintextHex is the canonical JSON of "
        "'content'; 'content.prekey' is the peer prekey alice offers bob (04 § Peer prekeys). The receiver vault holds "
        "prekeySeed (agents.bob's current prekey). decode: decodePacket on 'packet' (or on the parse of 'json') fails with "
        "'error' or succeeds (null). open: decode -> to must be agents[recipient] (wrong_recipient) -> "
        "operational signature against verifyKel(agents[sender].kel, now), the sender usable at now -> window "
        "now-604800 <= ts <= now+300 -> decrypt with the vault, passing the sender (unknown_prekey, decryption_failed) -> "
        "private content (invalid_body); 'error' null means it opens. An optional 'peerSeeds' "
        "{aceId: seedHex} means the receiver vault also holds, for each aceId, that seed as the peer prekey it offered "
        "that peer (peers[aceId].offered = {seed, offeredAt: the vectors' top-level now}, inUse and held null): it opens a "
        "packet from that aceId naming its ID (sha256 of its public key), and is unknown_prekey for any other sender."
    ),
    "deterministic": {
        "sender": "alice", "recipient": "bob", "prekeySeed": BOB_PREKEY_SEED, "prekey": BOB_PREKEY, "messageId": PKT_MID,
        "timestamp": NOW, "content": CONTENT, "plaintextHex": PLAINTEXT.hex(), "sharedSecret": SS.hex(), "kemCiphertext": KEM.hex(),
        "nonce": PKT_NONCE.hex(), "saltHex": SALT.hex(), "headerHex": header.hex(), "keyHex": AEAD_KEY.hex(),
        "payloadHex": payload.hex(), "signPayloadHex": sign_payload.hex(), "messageHex": packet_message.hex(),
        "packet": det_packet,
    },
    "decode": decode_cases,
    "open": open_cases,
}

# =============================================================================== private content

pc_cases = []


def pc(name, raw: bytes, code):
    expect(f"content {name}", lambda: decode_content(raw), code)
    pc_cases.append({"name": name, **({"text": raw.decode()} if _utf8(raw) else {"hex": raw.hex()}), "error": code})


def _utf8(raw):
    try:
        raw.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def cj(o):
    return canonical_state_bytes(o)


def nested(depth_body):
    """A body whose deepest container sits at content depth ``depth_body + 1``."""
    v: object = []
    for _ in range(depth_body - 1):
        v = [v]
    return {"x": v} if depth_body > 0 else {}


pc("valid with threadId", cj(CONTENT), None)
pc("valid without threadId", cj({k: v for k, v in CONTENT.items() if k != "threadId"}), None)
pc("threadId null", cj({**CONTENT, "threadId": None}), "invalid_body")
pc("unknown member", cj({**CONTENT, "extra": 1}), "invalid_body")
pc("missing body", cj({k: v for k, v in CONTENT.items() if k != "body"}), "invalid_body")
pc("type not namespaced", cj({**CONTENT, "type": "text"}), "invalid_body")
pc("schemaDigest uppercase", cj({**CONTENT, "schemaDigest": TEXT_DIGEST.upper()}), "invalid_body")
pc("body is an array", cj({**CONTENT, "body": []}), "invalid_body")
pc("threadId of 257 code points", cj({**CONTENT, "threadId": "😀" * 257}), "invalid_body")
pc("threadId with a control character", cj({**CONTENT, "threadId": "a\tb"}), "invalid_body")
pc("nesting depth 32 (body at depth 1)", cj({**CONTENT, "body": nested(31)}), None)
pc("nesting depth 33", cj({**CONTENT, "body": nested(32)}), "invalid_body")
pc("invalid UTF-8", b'{"type":"ace:text:1","schemaDigest":"' + TEXT_DIGEST.encode() + b'","body":{"message":"\xff"}}', "invalid_body")
pc("not an object", b"[]", "invalid_body")
pc("NaN literal", b'{"type":"ace:text:1","schemaDigest":"' + TEXT_DIGEST.encode() + b'","body":{"n":NaN}}', "invalid_body")
pc("overflowing number", b'{"type":"ace:text:1","schemaDigest":"' + TEXT_DIGEST.encode() + b'","body":{"n":1e400}}', "invalid_body")
_ADM = {"proof": {"issuer": "x"}, "permit": {"issuer": "y"}, "source": {"kel": []}}  # decoding checks the shape only (03); 05 checks the permits
pc("valid with admission", cj({**CONTENT, "admission": _ADM}), None)
pc("admission null", cj({**CONTENT, "admission": None}), "invalid_body")
pc("admission without source", cj({**CONTENT, "admission": {"proof": _ADM["proof"], "permit": _ADM["permit"]}}), "invalid_body")
pc("admission with an unknown member", cj({**CONTENT, "admission": {**_ADM, "extra": {}}}), "invalid_body")
pc("admission proof not an object", cj({**CONTENT, "admission": {**_ADM, "proof": "permit"}}), "invalid_body")
_RECEIPT = {"type": "ace:receipt:1", "schemaDigest": CORE.messages["ace:receipt:1"].digest, "body": {"messageId": "550e8400-e29b-41d4-a716-446655440000", "outcome": "delivered"},
            "prekey": ALICE_OFFER_BOB["publicKey"]}
pc("receipt with admission", cj({**_RECEIPT, "admission": _ADM}), "invalid_body")
pc("valid receipt", cj(_RECEIPT), None)
pc("missing prekey", cj({k: v for k, v in CONTENT.items() if k != "prekey"}), "invalid_body")
pc("prekey of 1215 bytes", cj({**CONTENT, "prekey": b64(base64.b64decode(CONTENT["prekey"])[:-1])}), "invalid_body")
pc("prekey non-canonical base64", cj({**CONTENT, "prekey": CONTENT["prekey"].rstrip("=")}), "invalid_body")
pc("prekey null", cj({**CONTENT, "prekey": None}), "invalid_body")
private_content = {
    "rules": ("decodePrivateContent(UTF-8 'text' or hex-decoded 'hex') fails with 'error' (always invalid_body) or "
              "succeeds (null). Content is the closed object {type, schemaDigest, threadId?, body, prekey, admission?}: "
              "'prekey' is required on every packet (receipts and contacts too) and is the canonical Base64 of exactly 1216 "
              "bytes, an X-Wing public key (04 § Peer prekeys)."),
    "cases": pc_cases,
}

# =============================================================================== descriptor, permit

COMMERCE_EXT = {"settlement": [{"method": "stablecoin", "asset": "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913"}, {"method": "stripe-link"}]}
# dave's ace:delegation:1 credential for alice (profiles/delegation.md), issued at NOW - 100 for the full 7 days
DLG_CRED = create_delegation_credential(dave.identity, alice.id, now=NOW - 100)
assert DLG_CRED["issuedAt"] == NOW - 100 and DLG_CRED["expiresAt"] == NOW - 100 + 604800
BASE = {
    "aceId": alice.id, "issuedAt": NOW - 100, "expiresAt": NOW + 3600, "relays": [RELAY],
    "prekey": ALICE_PREKEY, "profiles": [TEXT.descriptor(), COMMERCE.descriptor()],
    "ext": {"ace:commerce:1": COMMERCE_EXT},
}


def signed(action, claims, signer: Agent, seq=None):
    """``claims`` signed under ``action`` (without signer-side checks when they would refuse, or under a forced ``seq``)."""
    c = {k: v for k, v in claims.items() if k != "signature"}
    if seq is None:
        try:
            return sign_claims(signer.identity, action, c)
        except ACEError:
            pass
    return {**c, "signature": signer.raw_sign(action, c["issuedAt"], canonical_state_bytes(c), seq=seq)}


def with_changes(base, changes):
    out = copy.deepcopy(base)
    for k, v in changes.items():
        if v is DELETE:
            out.pop(k, None)
        else:
            out[k] = v
    return out


def published(claims, signer: Agent = alice, kel=None, resign_=True, seq=None):
    d = signed("agent-descriptor", claims, signer, seq) if resign_ or seq is not None else claims
    return {"kel": signer.kel if kel is None else kel, "descriptor": d}


desc_valid, desc_invalid = [], []
BASE_PA = published(BASE)
desc_valid.append({"name": "full descriptor", "publishedAgent": BASE_PA, "now": NOW})
_min = {k: v for k, v in BASE.items() if k != "ext"}
_min = {**_min, "profiles": []}
desc_valid.append({"name": "minimal descriptor", "publishedAgent": published(_min), "now": NOW})
desc_valid.append({"name": "lifetime of 604800 (7 days)", "publishedAgent": published({**_min, "expiresAt": NOW - 100 + 604800}),
                   "now": NOW})
# ace:delegation:1 ext: shape only (no signature, no expiry), the subject is the descriptor's aceId
DLG_PROFILES = [TEXT.descriptor(), DELEGATION.descriptor(), COMMERCE.descriptor()]
DLG_EXT = {"ace:commerce:1": COMMERCE_EXT, "ace:delegation:1": {"credentials": [DLG_CRED]}}
desc_valid.append({"name": "ace:delegation:1 ext with dave's credential", "now": NOW,
                   "publishedAgent": published({**BASE, "profiles": DLG_PROFILES, "ext": DLG_EXT})})
_exp_cred = create_delegation_credential(dave.identity, alice.id, now=NOW - 700000)
desc_valid.append({"name": "ace:delegation:1 ext with an expired credential (expiry is not checked)", "now": NOW,
                   "publishedAgent": published({**BASE, "profiles": DLG_PROFILES,
                                                "ext": {"ace:delegation:1": {"credentials": [_exp_cred]}}})})
_pa = published({**BASE, "relays": ["https://relay.example/ace", "https://r2.example:8443"]})
desc_valid.append({"name": "relay with path and port", "publishedAgent": _pa, "now": NOW})
_pa = copy.deepcopy(BASE_PA)
_pa["descriptor"]["issuedAt"] = 1.7601407e9  # == NOW - 100: same canonical claims, same signature
desc_valid.append({"name": "issuedAt written as 1.7601407e9 (a wire integer)", "publishedAgent": _pa, "now": NOW})
desc_valid.append({"name": "valid at expiresAt - 1", "publishedAgent": BASE_PA, "now": NOW + 3599})
_big = {"x:big:1": {"pad": "a" * (32768 - 22)}}  # {"x:big:1":{"pad":"…"}}: 32768 canonical bytes
assert len(canonical_state_bytes(_big)) == 32768
desc_valid.append({"name": "ext of exactly 32768 canonical bytes", "now": NOW, "publishedAgent": published(
    {**BASE, "profiles": [TEXT.descriptor(), {"id": "x:big:1", "digest": "b" * 64}], "ext": _big})})
for c in desc_valid:
    verify_published_agent(c["publishedAgent"], now=c["now"])


def bad_desc(name, pa, code, now=NOW):
    expect(f"descriptor {name}", lambda: verify_published_agent(pa, now=now), code)
    desc_invalid.append({"name": name, "publishedAgent": pa, "now": now, "error": code})


def field(name, code="invalid_authorization", **changes):
    bad_desc(name, published(with_changes(BASE, changes)), code)


IA = "invalid_authorization"
field("a version member (unknown in the closed object)", version=1)
field("aceId of another identity", aceId=bob.id)
field("issuedAt beyond now + 300", issuedAt=NOW + 301, expiresAt=NOW + 3600)
field("expiresAt not after issuedAt", expiresAt=NOW - 100)
field("lifetime above 604800", issuedAt=NOW - 100, expiresAt=NOW - 100 + 604801)
bad_desc("expired (now == expiresAt)", BASE_PA, IA, now=NOW + 3600)
field("no relays", relays=[])
field("five relays", relays=[f"https://r{i}.example" for i in range(5)])
field("duplicate relays", relays=[RELAY, RELAY])
field("relay with a trailing slash", relays=[RELAY + "/"])
field("relay with an uppercase host", relays=["https://Relay.example"])
field("relay over http", relays=["http://relay.example"])
field("loopback http relay (development only)", relays=["http://127.0.0.1:8080"])
field("relay with a query", relays=[RELAY + "?a=1"])
for _u in NON_CANONICAL_HOSTS:
    field(f"relay {_u} (normalized but not a canonical relay URL host)", relays=[_u])
field("prekey id is not SHA-256 of the key", prekey={**ALICE_PREKEY, "id": "0" * 64})
field("prekey of 1215 bytes", prekey={"id": hashlib.sha256(bytes(1215)).hexdigest(), "publicKey": b64(bytes(1215))})
field("prekey with an extra member", prekey={**ALICE_PREKEY, "x": 1})
field("core profile listed", profiles=[CORE.descriptor()])
field("duplicate profile id", profiles=[TEXT.descriptor(), TEXT.descriptor()])
field("33 profiles", profiles=[{"id": f"x:p{i}", "digest": "a" * 64} for i in range(33)], ext=DELETE)
field("profile digest uppercase", profiles=[{"id": "ace:text:1", "digest": "A" * 64}], ext=DELETE)
field("profile entry with an extra member", profiles=[{**TEXT.descriptor(), "x": 1}], ext=DELETE)
field("handle member (moved to the card record)", handle="alice")
field("card member (moved to the card record)", card={"name": "Alice"})
field("ext key not a listed profile", ext={"x:other:1": {}})
field("ext value not an object", ext={"ace:commerce:1": []})
field("ext for an official profile that defines none", ext={"ace:text:1": {}})
field("commerce ext with a bad asset", ext={"ace:commerce:1": {"settlement": [{"method": "stablecoin", "asset": "usdc"}]}})
field("commerce ext with 11 entries", ext={"ace:commerce:1": {"settlement": [{"method": "stablecoin", "asset": f"eip155:{i + 1}/erc20:0xabc"} for i in range(11)]}})
field("commerce ext with duplicate entries", ext={"ace:commerce:1": {"settlement": [{"method": "stripe-link"}, {"method": "stripe-link"}]}})
field("commerce ext with an unknown member", ext={"ace:commerce:1": {"settlement": [{"method": "stripe-link"}], "x": 1}})
field("ext above 32768 canonical bytes", profiles=[TEXT.descriptor(), {"id": "x:big:1", "digest": "b" * 64}],
      ext={"x:big:1": {"pad": "a" * (32768 - 21)}})
field("ace:delegation:1 ext naming another subject", profiles=DLG_PROFILES,
      ext={"ace:delegation:1": {"credentials": [create_delegation_credential(dave.identity, bob.id, now=NOW - 100)]}})
field("ace:delegation:1 ext without the profile announced", ext={"ace:delegation:1": {"credentials": [DLG_CRED]}})
field("empty ext", ext={})
field("unknown descriptor member", contact={"relay": RELAY})
_tampered = published(BASE)
_tampered["descriptor"]["expiresAt"] -= 1
bad_desc("claims changed after signing", _tampered, IA)
bad_desc("descriptor signed with a superseded delegation seq", published({**BASE, "aceId": bob.id}, signer=bob, seq=1), "stale_peer_binding")
bad_desc("descriptor kel not usable at now (carol, now >= notAfter)", published({**BASE, "aceId": carol.id}, signer=carol), "invalid_kel", now=NOW + 100)
_badkel = copy.deepcopy(alice.kel)
_badkel[1]["sig"]["value"] = b64(bytes(3309))
bad_desc("descriptor kel does not verify", published(BASE, kel=_badkel), "invalid_signature")
bad_desc("published agent with an extra member", {**BASE_PA, "x": 1}, IA)
bad_desc("published agent without kel", {"descriptor": BASE_PA["descriptor"]}, IA)

# Verification against a pin (01 § Pinning; prekey substitution by a superseded signing key).
BOB_FORK = [bob.kel[0], create_signing_delegation(verify_kel(bob.kel[:1], NOW), key("bob-root"), key("bob-x").public_key(), T0 + 5)]
_bob_claims = {**BASE, "aceId": bob.id, "prekey": OTHER_PREKEY}
_c = {k: v for k, v in _bob_claims.items() if k != "signature"}
_old_sig = {**_c, "signature": bob.raw_sign("agent-descriptor", _c["issuedAt"], canonical_state_bytes(_c), seq=1)}
_new_sig = {**_c, "signature": bob.raw_sign("agent-descriptor", _c["issuedAt"], canonical_state_bytes(_c))}
desc_pinned = []
for name, pa, code in [
    ("older KEL prefix signed by the superseded delegation (seq 1): stale_peer_binding", {"kel": bob.kel[:2], "descriptor": _old_sig}, "stale_peer_binding"),
    ("older KEL prefix signed by the pinned current delegation (seq 3): valid", {"kel": bob.kel[:2], "descriptor": _new_sig}, None),
    ("full KEL, current delegation: valid", {"kel": bob.kel, "descriptor": _new_sig}, None),
    ("forked KEL: kel_conflict", {"kel": BOB_FORK, "descriptor": _old_sig}, "kel_conflict"),
]:
    expect(f"pinned {name}", lambda: verify_published_agent(pa, now=NOW, pinned=bob.state), code)
    desc_pinned.append({"name": name, "publishedAgent": pa, "pinned": "bob", "now": NOW, "error": code})
# the attack only works without the pin:
assert outcome(lambda: verify_published_agent(desc_pinned[0]["publishedAgent"], now=NOW)) is None

# 01 § Operational signatures rule 3: signed while live requires the signed timestamp (issuedAt) to be at or after the ts of
# the dlg its signature seq names.
# Fork recovery that re-delegates the same key at the same seq: the superseded branch FORK_OLD = icp, dlg(seq 1), dlg(seq 2,
# key K, T0 + 5); the holder of the next root recovers with FORK_NEW = icp, rot(seq 1, T0 + 20), dlg(seq 2, key K, T0 + 20),
# which supersedes FORK_OLD (01 rule 6). A document signed with K at seq 2 on the old branch (issuedAt T0 + 10) carries a
# signature that also verifies under FORK_NEW's seq 2: only the issuedAt bound rejects its replay.
def make_fork():
    r1, r2, r3 = key("fork-root"), key("fork-next"), key("fork-next-2")
    s1, k = key("fork-signing-1"), key("fork-signing")
    icp = create_inception(r1, key_digest(r2.scheme, r2.public_key()), T0)
    d1 = create_signing_delegation(verify_kel([icp], T0), r1, s1.public_key(), T0)
    d2 = create_signing_delegation(verify_kel([icp, d1], T0 + 5), r1, k.public_key(), T0 + 5)
    rot = create_rotation(verify_kel([icp], T0 + 20), r2, key_digest(r3.scheme, r3.public_key()), T0 + 20)
    d2b = create_signing_delegation(verify_kel([icp, rot], T0 + 20), r2, k.public_key(), T0 + 20)
    old, new = Agent("fork-old", r1, r2, k, [icp, d1, d2]), Agent("fork-new", r2, r3, k, [icp, rot, d2b])
    assert old.id == new.id and old.seq == new.seq == 2
    assert extend_kel(old.state, new.kel, NOW)[1] == "recovered"  # 01 rule 6
    return old, new


FORK_OLD, FORK_NEW = make_fork()
BOB_DLG_TS = bob.kel[3]["ts"]  # bob's current dlg (seq 3), T0 + 10
assert BOB_DLG_TS == T0 + 10
_bob_min = {**_min, "aceId": bob.id}
_fork_min = {**_min, "aceId": FORK_NEW.id}
_fork_replayed = signed("agent-descriptor", {**_fork_min, "issuedAt": T0 + 10}, FORK_OLD)
_issued_valid = [
    ("issuedAt equal to the ts of the delegating dlg (bob, seq 3)", published({**_bob_min, "issuedAt": BOB_DLG_TS}, signer=bob)),
    ("fork recovery: issuedAt equal to the ts of the re-delegating dlg", published({**_fork_min, "issuedAt": T0 + 20}, signer=FORK_NEW)),
    ("fork recovery: the old branch's document under the old branch's own KEL (no pin: still valid)",
     {"kel": FORK_OLD.kel, "descriptor": _fork_replayed}),
]
for name, pa in _issued_valid:
    verify_published_agent(pa, now=NOW)
    desc_valid.append({"name": name, "publishedAgent": pa, "now": NOW})
bad_desc("issuedAt one second before the ts of the delegating dlg (bob, seq 3): stale_peer_binding",
         published({**_bob_min, "issuedAt": BOB_DLG_TS - 1}, signer=bob), "stale_peer_binding")
bad_desc("fork recovery: the superseded branch's document (same seq, same key, issuedAt before the re-delegating dlg) replayed "
         "under the recovered KEL: stale_peer_binding", {"kel": FORK_NEW.kel, "descriptor": _fork_replayed}, "stale_peer_binding")

descriptor = {
    "rules": (
        "verifyPublishedAgent(publishedAgent, now) with production settings (no loopback relays). valid: succeeds. "
        "invalid: fails with 'error'. An official profile's ext value is checked by that profile's validator: "
        "ext['ace:delegation:1'] by validateDelegationExt(value, descriptor.aceId, now) (shape only, no signature, no "
        "expiry). pinned: verify with the "
        "verifier's pin verifyKel(agents[pinned].kel, now): the carried KEL is reconciled with the pin (fork rules) and "
        "the signature must verify under the resulting newest state ('error' null = valid). A PeerStore/importAgent "
        "adopting these must behave the same."
    ),
    "valid": desc_valid,
    "invalid": desc_invalid,
    "pinned": desc_pinned,
}

permit_cases = []


def permit_doc(issuer: Agent, subject, issued, expires, *, seq=None, extra=None):
    c = {"issuer": issuer.id, "subject": subject, "issuedAt": issued, "expiresAt": expires, **(extra or {})}
    return {**c, "signature": issuer.raw_sign("delivery-permit", issued, canonical_state_bytes(c), seq=seq)}


def permit_case(name, permit, issuer: Agent, subject, now, code):
    expect(f"permit {name}", lambda: verify_permit(permit, verify_kel(issuer.kel, now), subject, now=now), code)
    permit_cases.append({"name": name, "permit": permit, "issuer": issuer.name, "subject": subject, "now": now, "error": code})


GOOD_PERMIT = permit_doc(bob, alice.id, NOW - 10, NOW - 10 + 2592000)
permit_case("valid (30 days)", GOOD_PERMIT, bob, alice.id, NOW, None)
permit_case("expired at expiresAt", GOOD_PERMIT, bob, alice.id, NOW - 10 + 2592000, IA)
permit_case("lifetime above 30 days", permit_doc(bob, alice.id, NOW, NOW + 2592001), bob, alice.id, NOW, IA)
permit_case("issuedAt beyond now + 300", permit_doc(bob, alice.id, NOW + 301, NOW + 1000), bob, alice.id, NOW, IA)
permit_case("subject is someone else", GOOD_PERMIT, bob, carol.id, NOW, IA)
permit_case("issuer equals subject", permit_doc(bob, bob.id, NOW, NOW + 10), bob, bob.id, NOW, IA)
permit_case("extra member", permit_doc(bob, alice.id, NOW, NOW + 10, extra={"scope": "all"}), bob, alice.id, NOW, IA)
permit_case("an id member (unknown in the closed object)", permit_doc(bob, alice.id, NOW, NOW + 10, extra={"id": "6f9619ff-8b86-4011-b42d-00c04fc964ff"}), bob, alice.id, NOW, IA)
permit_case("changed after signing", {**GOOD_PERMIT, "expiresAt": GOOD_PERMIT["expiresAt"] - 1}, bob, alice.id, NOW, IA)
permit_case("verified against another issuer", GOOD_PERMIT, carol, alice.id, NOW, IA)
permit_case("signed under a superseded delegation", permit_doc(bob, alice.id, NOW, NOW + 10, seq=1), bob, alice.id, NOW, "stale_peer_binding")
permit_case("signed at the issuer's notAfter", permit_doc(carol, alice.id, NOW + 100, NOW + 200), carol, alice.id, NOW, "stale_peer_binding")
permit_case("signed before the issuer's notAfter, verified after it (01 rule 5): stale_peer_binding",
            permit_doc(carol, alice.id, NOW + 50, NOW + 500), carol, alice.id, NOW + 150, "stale_peer_binding")
permit_case("issuedAt before the issuer's dlg ts: stale_peer_binding",
            permit_doc(bob, alice.id, BOB_DLG_TS - 1, BOB_DLG_TS - 1 + 2592000), bob, alice.id, NOW, "stale_peer_binding")
permit = {
    "rules": ("verifyPermit(permit, verifyKel(agents[issuer].kel, now), subject, now) succeeds (error null) or fails with "
              "'error'; the issuer must be usable at now (01 rule 5). A relay checking the same permit on POST /v1/send "
              "(07 step 4: issuer = to, subject = from, against the issuer's registered KEL) refuses every failing case "
              "with not_permitted."),
    "cases": permit_cases,
}

# =============================================================================== ace:delegation:1 (profiles/delegation.md)

def cred_doc(issuer: Agent, subject, issued, expires, *, seq=None, extra=None):
    """A credential signed with the profile ID as its action, without signer-side checks."""
    c = {"issuer": issuer.id, "subject": subject, "issuedAt": issued, "expiresAt": expires, **(extra or {})}
    return {**c, "signature": issuer.raw_sign(DELEGATION_TYPE, issued, canonical_state_bytes(c), seq=seq)}


cred_cases, dext_cases, dmsg_cases = [], [], []


def cred_case(name, cred, issuer: Agent, now, code):
    expect(f"credential {name}", lambda: verify_delegation_credential(cred, verify_kel(issuer.kel, now), now), code)
    cred_cases.append({"name": name, "credential": cred, "issuer": issuer.name, "now": now, "error": code})


assert verify_signature(signing_message(dave.id, NOW - 100, dave.seq, canonical_state_bytes({k: v for k, v in DLG_CRED.items() if k != "signature"})),
                        DELEGATION_TYPE, from_base64(DLG_CRED["signature"]["value"]), dave.signing.public_key())
cred_case("valid (dave for alice, 7 days)", DLG_CRED, dave, NOW, None)
cred_case("valid at expiresAt - 1", DLG_CRED, dave, NOW - 100 + 604799, None)
cred_case("expired (now == expiresAt)", DLG_CRED, dave, NOW - 100 + 604800, IA)
cred_case("issuer equals subject", cred_doc(dave, dave.id, NOW - 100, NOW + 3600), dave, NOW, IA)
cred_case("lifetime of 604801", cred_doc(dave, alice.id, NOW - 100, NOW - 100 + 604801), dave, NOW, IA)
cred_case("issuedAt beyond now + 300", cred_doc(dave, alice.id, NOW + 301, NOW + 3600), dave, NOW, IA)
cred_case("expiresAt not after issuedAt", cred_doc(dave, alice.id, NOW - 100, NOW - 100), dave, NOW, IA)
cred_case("subject is not an ACE ID", cred_doc(dave, "alice", NOW - 100, NOW + 3600), dave, NOW, IA)
cred_case("extra member", cred_doc(dave, alice.id, NOW - 100, NOW + 3600, extra={"scope": "all"}), dave, NOW, IA)
cred_case("changed after signing", {**DLG_CRED, "expiresAt": DLG_CRED["expiresAt"] - 1}, dave, NOW, IA)
cred_case("signed with ctx 'delivery-permit'", {**DLG_CRED, "signature": dave.raw_sign("delivery-permit", NOW - 100,
          canonical_state_bytes({k: v for k, v in DLG_CRED.items() if k != "signature"}))}, dave, NOW, IA)
cred_case("verified against another issuer", DLG_CRED, carol, NOW, IA)
cred_case("signed under a superseded delegation (bob, seq 1): stale_peer_binding",
          cred_doc(bob, alice.id, NOW - 100, NOW + 3600, seq=1), bob, NOW, "stale_peer_binding")
cred_case("issuedAt before the issuer's dlg ts: stale_peer_binding",
          cred_doc(bob, alice.id, BOB_DLG_TS - 1, BOB_DLG_TS - 1 + 3600 * 24), bob, T0 + 3600, "stale_peer_binding")
cred_case("issuer not usable at now (carol, now >= notAfter): stale_peer_binding",
          cred_doc(carol, alice.id, NOW - 100, NOW + 3600), carol, NOW + 100, "stale_peer_binding")


def dext_case(name, value, subject, now, code):
    expect(f"delegation ext {name}", lambda: validate_delegation_ext(value, subject, now), code)
    dext_cases.append({"name": name, "value": value, "subject": subject, "now": now, "error": code})


_four = [create_delegation_credential(i.identity, carol.id, now=NOW - 100) for i in (alice, bob, dave)]
_four.append(cred_doc(simple_agent("erin"), carol.id, NOW - 100, NOW + 3600))
_fifth = cred_doc(simple_agent("frank"), carol.id, NOW - 100, NOW + 3600)
dext_case("one credential", {"credentials": [DLG_CRED]}, alice.id, NOW, None)
dext_case("four credentials accepted", {"credentials": _four}, carol.id, NOW, None)
dext_case("a fifth credential: invalid_authorization", {"credentials": _four + [_fifth]}, carol.id, NOW, IA)
dext_case("expired credential (expiry is not checked)", {"credentials": [cred_doc(dave, alice.id, NOW - 700000, NOW - 100000)]},
          alice.id, NOW, None)
dext_case("signature not verified (changed after signing)", {"credentials": [{**DLG_CRED, "expiresAt": NOW + 1}]}, alice.id, NOW, None)
dext_case("wrong subject (not the descriptor's aceId)", {"credentials": [DLG_CRED]}, bob.id, NOW, IA)
dext_case("issuer equals subject", {"credentials": [cred_doc(alice, alice.id, NOW - 100, NOW + 3600)]}, alice.id, NOW, IA)
dext_case("duplicate issuers", {"credentials": [DLG_CRED, create_delegation_credential(dave.identity, alice.id, now=NOW - 50)]},
          alice.id, NOW, IA)
dext_case("no credentials", {"credentials": []}, alice.id, NOW, IA)
dext_case("unknown member", {"credentials": [DLG_CRED], "x": 1}, alice.id, NOW, IA)
dext_case("credentials not an array", {"credentials": DLG_CRED}, alice.id, NOW, IA)
dext_case("lifetime of 604801", {"credentials": [cred_doc(dave, alice.id, NOW - 100, NOW - 100 + 604801)]}, alice.id, NOW, IA)
dext_case("issuedAt beyond now + 300", {"credentials": [cred_doc(dave, alice.id, NOW + 301, NOW + 3600)]}, alice.id, NOW, IA)
dext_case("credential with an extra member", {"credentials": [{**DLG_CRED, "x": 1}]}, alice.id, NOW, IA)
dext_case("signature not a delegated signature's shape", {"credentials": [{**DLG_CRED, "signature": {**DLG_CRED["signature"],
          "value": "AAAA"}}]}, alice.id, NOW, IA)

# the hand-over message: dave (issuer) sends alice (subject) her credential; alice's rule runs at receive step 10


def dmsg_case(name, direction, from_: Agent, to: Agent, body, code, now=NOW, pinned=True):
    peers = PeerStore(MemoryStore(), clock=lambda: now)
    if pinned and direction == "receive":
        peers.pin(from_.kel, now)
    rules = delegation_rules(peers)
    event = MessageEvent(direction, mid(900 + len(dmsg_cases)), from_.id, to.id, now, DELEGATION_TYPE, None)
    expect(f"delegation message {name}", lambda: rules.check(event, body), code)
    dmsg_cases.append({"name": name, "direction": direction, "from": from_.name, "to": to.name, "body": body, "now": now,
                       "senderPinned": pinned and direction == "receive", "error": code})


dmsg_case("receive: dave hands alice her credential", "receive", dave, alice, {"credential": DLG_CRED}, None)
dmsg_case("send: dave hands alice her credential", "send", dave, alice, {"credential": DLG_CRED}, None)
dmsg_case("receive: issuer != from: invalid_body", "receive", bob, alice, {"credential": DLG_CRED}, "invalid_body")
dmsg_case("send: issuer != from: invalid_body", "send", bob, alice, {"credential": DLG_CRED}, "invalid_body")
dmsg_case("receive: subject != to: invalid_body", "receive", dave, carol, {"credential": DLG_CRED}, "invalid_body")
dmsg_case("receive: expired credential: invalid_body", "receive", dave, alice, {"credential": DLG_CRED}, "invalid_body",
          now=NOW - 100 + 604800)
dmsg_case("receive: signature does not verify under the sender's pin: invalid_body", "receive", dave, alice,
          {"credential": {**DLG_CRED, "expiresAt": DLG_CRED["expiresAt"] - 1}}, "invalid_body")
dmsg_case("receive: sender not pinned: invalid_body", "receive", dave, alice, {"credential": DLG_CRED}, "invalid_body", pinned=False)
dmsg_case("receive: credential with an extra member: invalid_body", "receive", dave, alice, {"credential": {**DLG_CRED, "x": 1}},
          "invalid_body")

delegation = {
    "rules": (
        "profiles/delegation.md. credentials: verifyDelegationCredential(credential, verifyKel(agents[issuer].kel, now), "
        "now) succeeds (error null) or fails with 'error': the closed {issuer, subject, issuedAt, expiresAt, signature} "
        "with issuer != subject, issuedAt <= now + 300, issuedAt < expiresAt <= issuedAt + 604800, now < expiresAt, "
        "issuer == the state's aceId, and 'signature' an operational signature of the issuer over "
        "canonicalStateBytes(claims) at timestamp = issuedAt with ctx 'ace:delegation:1' (stale_peer_binding from that "
        "check passes through, every other failure is invalid_authorization). ext: validateDelegationExt(value, "
        "subject, now) succeeds or fails with 'error' (invalid_authorization): the closed {credentials} of 1-4 "
        "credentials with distinct issuers, each closed, subject == 'subject', issuer != subject, the issuedAt / "
        "expiresAt grammar above and a signature of the delegated-signature shape; no expiry, no signature check. "
        "messages: delegationRules(peers).check({direction, from: agents[from].aceId, to: agents[to].aceId, "
        "type: 'ace:delegation:1', ...}, body) at clock 'now', where peers holds verifyKel(agents[from].kel, now) as the "
        "pin for 'from' iff senderPinned, succeeds (error null) or fails with invalid_body: credential.issuer == from, "
        "credential.subject == to, the credential's grammar and now < expiresAt, and on receive its signature verifies "
        "under the sender's pin (no pin is a failure)."
    ),
    "credentials": cred_cases,
    "ext": dext_cases,
    "messages": dmsg_cases,
}

# =============================================================================== ERC-8004 (04 § Card record)

ERC_SHAPES = [({"agentRegistry": "eip155:8453:0xabc", "agentId": "0"}, True), ({"agentRegistry": "eip155:8453:0xabc", "agentId": "9" * 78}, True),
              ({"agentRegistry": "eip155:8453:0xabc", "agentId": "007"}, False), ({"agentRegistry": "eip155:8453", "agentId": "1"}, False),
              ({"agentRegistry": "eip155:8453:0xabc", "agentId": "1", "chain": "base"}, False), ({"agentRegistry": "eip155:8453:0xabc"}, False),
              # chain-native identifiers outside eip155 (04 § Card record)
              ({"agentRegistry": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX", "agentId": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"}, True),
              ({"agentRegistry": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX", "agentId": "007"}, True),
              ({"agentRegistry": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX", "agentId": "a" * 128}, True),
              ({"agentRegistry": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX", "agentId": "a" * 129}, False),
              ({"agentRegistry": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX", "agentId": "7xKX-1"}, False),
              ({"agentRegistry": "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKX", "agentId": ""}, False),
              ({"agentRegistry": "eip155:8453:0xabc", "agentId": "7xKX"}, False),
              ({"agentRegistry": "eip1555:1:0xabc", "agentId": "7xKX"}, True)]
for e, ok in ERC_SHAPES:
    assert (outcome(lambda: validate_erc8004(e)) is None) == ok, e
ERC_REG = [
    ({"services": [{"name": "ACE", "endpoint": alice.id}]}, True),
    ({"services": [{"name": "web", "endpoint": "https://x"}, {"name": "ACE", "endpoint": alice.id, "version": "1"}]}, True),
    ({"endpoints": [{"name": "ACE", "endpoint": alice.id}]}, False),
    ({"services": [{"name": "ace", "endpoint": alice.id}]}, False),
    ({"services": [{"name": "ACE", "endpoint": bob.id}]}, False),
    ({"services": {"name": "ACE", "endpoint": alice.id}}, False),
    ([{"name": "ACE", "endpoint": alice.id}], False),
    ('{"services":[{"name":"ACE","endpoint":"' + alice.id + '"}]}', True),
    ("not json", False),
]
for r, ok in ERC_REG:
    assert verify_erc8004_registration(r, alice.id) == ok, r
erc8004 = {
    "rules": ("shapes: one card record erc8004 entry (04 § Card record); validateErc8004 / validateErc8004Binding / "
              "validateErc8004Entry accepts it iff 'valid' (invalid_authorization otherwise). registrations: "
              "verifyErc8004Registration(registration, aceId) == result (a string is JSON text)."),
    "shapes": [{"entry": e, "valid": ok} for e, ok in ERC_SHAPES],
    "registrations": [{"registration": r, "aceId": alice.id, "result": ok} for r, ok in ERC_REG],
}

# =============================================================================== card record (04 § Card record)

CARD_HOME = "https://relay.interop.test"
SOL = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"
CARD_BASE = {
    "aceId": alice.id, "issuedAt": NOW - 100, "home": CARD_HOME, "handle": "alice",
    "card": {"description": "translation agent", "image": "https://example.com/a.png", "tags": ["nlp", "hosted"]},
    "pay": [SOL], "erc8004": [{"agentRegistry": "eip155:8453:0x8004a169fb4a3325136eb29fa0ceb6d2e539a432", "agentId": "42"}],
    "contact": "open", "listed": False,
}


def card_bundle(claims, signer: Agent = alice, kel=None, seq=None):
    return {"kel": signer.kel if kel is None else kel, "card": signed("card-record", claims, signer, seq)}


def card_summary(v) -> dict:
    r = v.record
    assert v.erc8004 == r.get("erc8004")
    return {"aceId": v.ace_id, "home": r["home"], "handle": r.get("handle"), "pay": r.get("pay"), "erc8004": r.get("erc8004"),
            "contact": r["contact"], "listed": r["listed"]}


BASE_CARD = card_bundle(CARD_BASE)
# the SDK's own constructor produces the same claims
_made = create_card_record(alice.identity, home=CARD_HOME, handle="alice", card=CARD_BASE["card"], pay=[SOL],
                           erc8004=CARD_BASE["erc8004"], contact="open", listed=False, now=NOW - 100)
assert {k: v for k, v in _made["card"].items() if k != "signature"} == CARD_BASE
card_valid, card_invalid = [], []


def good_card(name, bundle, now=NOW):
    card_valid.append({"name": name, "bundle": bundle, "now": now, "expect": card_summary(verify_card_bundle(bundle, now))})


def bad_card(name, bundle, code, now=NOW):
    expect(f"card record {name}", lambda: verify_card_bundle(bundle, now), code)
    card_invalid.append({"name": name, "bundle": bundle, "now": now, "error": code})


def card_field(name, code=IA, **changes):
    bad_card(name, card_bundle(with_changes(CARD_BASE, changes)), code)


good_card("alice: handle, home, pay, erc8004, open, unlisted", BASE_CARD)
good_card("minimal: no handle, no pay, empty card, closed", card_bundle(
    {"aceId": alice.id, "issuedAt": NOW - 100, "home": CARD_HOME, "card": {}, "contact": "closed", "listed": True}))
good_card("no expiry: verifies a year later", BASE_CARD, now=NOW + 365 * 86400)
good_card("issuedAt at now + 300", card_bundle({**CARD_BASE, "issuedAt": NOW + 300}))
good_card("4 erc8004 entries, eip155 and chain-native", card_bundle({**CARD_BASE, "erc8004": [
    {"agentRegistry": "eip155:1:0xabc", "agentId": "0"}, {"agentRegistry": "eip155:1:0xabc", "agentId": "9" * 78},
    {"agentRegistry": SOL, "agentId": "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU"}, {"agentRegistry": SOL, "agentId": "007"}]}))
good_card("8 pay accounts", card_bundle({**CARD_BASE, "pay": [f"eip155:1:0x{i:040x}" for i in range(8)]}))
good_card("home with a path and port, no handle", card_bundle(
    {k: v for k, v in CARD_BASE.items() if k != "handle"} | {"home": "https://relay.example:8443/ace"}))
bad_card("tampered signature value", mutate(BASE_CARD, ["card", "signature", "value"], flip_b64(BASE_CARD["card"]["signature"]["value"], 0)), IA)
bad_card("claims changed after signing", mutate(BASE_CARD, ["card", "listed"], True), IA)
card_field("a version member (unknown in the closed object)", version=1)
card_field("aceId of another identity", aceId=bob.id)
card_field("no contact", contact=DELETE)
card_field("no card", card=DELETE)
card_field("no home", home=DELETE)
card_field("no listed", listed=DELETE)
card_field("issuedAt beyond now + 300", issuedAt=NOW + 301)
bad_card("issuedAt not an integer", mutate(BASE_CARD, ["card", "issuedAt"], NOW - 100.5), IA)
card_field("contact 'public'", contact="public")
card_field("listed as a string", listed="false")
card_field("home with a trailing slash", home=CARD_HOME + "/")
card_field("home with an uppercase host", home="https://Relay.interop.test")
card_field("home over http", home="http://relay.interop.test")
card_field("loopback http home (development only)", home="http://127.0.0.1:8080")
card_field("handle with a home that has a path", home="https://relay.example:8443/ace")
for _u in NON_CANONICAL_HOSTS:
    card_field(f"home {_u} (normalized but not a canonical relay URL host)", home=_u)
card_field("handle grammar", handle="Al")
card_field("handle with an underscore", handle="al_ice")
card_field("handle with a doubled hyphen", handle="al--ice")
card_field("handle of 33 characters", handle="a" * 33)
card_field("9 pay accounts", pay=[f"eip155:1:0x{i:040x}" for i in range(9)])
card_field("empty pay", pay=[])
card_field("duplicate pay", pay=[SOL, SOL])
card_field("pay entry not CAIP-10", pay=["solana:7xKX"])
card_field("pay entry not a string", pay=[1])
card_field("erc8004 registry is not CAIP-10", erc8004=[{"agentRegistry": "0x8004", "agentId": "1"}])
card_field("erc8004 eip155 agentId with a leading zero", erc8004=[{"agentRegistry": "eip155:1:0xabc", "agentId": "01"}])
card_field("erc8004 eip155 agentId of 79 digits", erc8004=[{"agentRegistry": "eip155:1:0xabc", "agentId": "1" * 79}])
card_field("erc8004 eip155 agentId not decimal", erc8004=[{"agentRegistry": "eip155:1:0xabc", "agentId": "7xKX"}])
card_field("erc8004 chain-native agentId with a hyphen", erc8004=[{"agentRegistry": SOL, "agentId": "7xKX-1"}])
card_field("erc8004 chain-native agentId of 129 characters", erc8004=[{"agentRegistry": SOL, "agentId": "a" * 129}])
card_field("erc8004 agentId as a number", erc8004=[{"agentRegistry": "eip155:1:0xabc", "agentId": 1}])
card_field("erc8004 entry with an extra member", erc8004=[{"agentRegistry": "eip155:1:0xabc", "agentId": "1", "chain": "base"}])
card_field("erc8004 duplicate entries", erc8004=[{"agentRegistry": "eip155:1:0xabc", "agentId": "1"}] * 2)
card_field("erc8004 five entries", erc8004=[{"agentRegistry": "eip155:1:0xabc", "agentId": str(i)} for i in range(5)])
card_field("erc8004 empty", erc8004=[])
card_field("card unknown member", card={"url": "https://x.example"})
card_field("card name (a display name is application data)", card={"name": "Alice"})
card_field("card description of 257 characters", card={"description": "a" * 257})
card_field("card image over http", card={"image": "http://example.com/a.png"})
card_field("card tag uppercase", card={"tags": ["NLP"]})
card_field("card 11 tags", card={"tags": [f"t{i}" for i in range(11)]})
card_field("card duplicate tags", card={"tags": ["a", "a"]})
card_field("record above 16384 canonical bytes", card={"description": "x" * 16384})
bad_card("bundle with an extra member", {**BASE_CARD, "x": 1}, IA)
bad_card("bundle without kel", {"card": BASE_CARD["card"]}, IA)
bad_card("signed with a superseded delegation seq", card_bundle({**CARD_BASE, "aceId": bob.id}, signer=bob, seq=1), "stale_peer_binding")
bad_card("kel not usable at now (carol, now >= notAfter)", card_bundle({**CARD_BASE, "aceId": carol.id}, signer=carol), "invalid_kel",
         now=NOW + 100)
bad_card("kel does not verify", card_bundle(CARD_BASE, kel=_badkel), "invalid_signature")
# 01 § Operational signatures rule 3 (via 04 § Card record step 3): issuedAt at or after the ts of the delegating dlg.
_card_nh = {k: v for k, v in CARD_BASE.items() if k != "handle"}
good_card("issuedAt equal to the ts of the delegating dlg (bob, seq 3)",
          card_bundle({**_card_nh, "aceId": bob.id, "issuedAt": BOB_DLG_TS}, signer=bob))
good_card("fork recovery: issuedAt equal to the ts of the re-delegating dlg",
          card_bundle({**_card_nh, "aceId": FORK_NEW.id, "issuedAt": T0 + 20}, signer=FORK_NEW))
_fork_card = signed("card-record", {**_card_nh, "aceId": FORK_NEW.id, "issuedAt": T0 + 10}, FORK_OLD)
good_card("fork recovery: the old branch's record under the old branch's own KEL (no pin: still valid)",
          {"kel": FORK_OLD.kel, "card": _fork_card})
bad_card("issuedAt one second before the ts of the delegating dlg (bob, seq 3): stale_peer_binding",
         card_bundle({**_card_nh, "aceId": bob.id, "issuedAt": BOB_DLG_TS - 1}, signer=bob), "stale_peer_binding")
bad_card("fork recovery: the superseded branch's record (same seq, same key, issuedAt before the re-delegating dlg) replayed "
         "under the recovered KEL: stale_peer_binding", {"kel": FORK_NEW.kel, "card": _fork_card}, "stale_peer_binding")
card_records = {
    "rules": (
        "verifyCardBundle(bundle, now) with production settings (no loopback relays). valid: succeeds and the record's "
        "aceId, home, handle, pay, erc8004 (each null when absent), contact and listed equal 'expect'. invalid: fails with 'error'. "
        "A card record has no expiry."
    ),
    "valid": card_valid,
    "invalid": card_invalid,
}

# =============================================================================== manifests

official = []
for m, file in ((CORE, "core.json"), (TEXT, "text.json"), (DELEGATION, "delegation.json"), (COMMERCE, "commerce.json")):
    with open(os.path.join(SPEC, "profiles", file), encoding="utf-8") as f:
        spec_m = json.load(f)
    assert canonical_state_bytes(spec_m) == canonical_state_bytes(m.to_dict()), file
    official.append({"file": file, "id": m.id, "digest": m.digest, "messages": {t: s.digest for t, s in m.messages.items()}})
with open(os.path.join(SPEC, "08-profiles.md"), encoding="utf-8") as f:
    ch8 = f.read()
for o in official:
    assert o["digest"] in ch8 and all(d in ch8 for d in o["messages"].values()), (o["file"], o["digest"], o["messages"])

OBJ = {"type": "object", "properties": {"q": {"type": "string", "maxLength": 8}}, "required": ["q"], "additionalProperties": False}


def man(mid_="x:translate:1", msgs=None, **extra):
    return {"id": mid_, "messages": msgs if msgs is not None else [{"type": "x:translate:request:1", "schema": OBJ}], **extra}


def deep_schema(depth):
    s = {"type": "string"}
    for _ in range(depth):
        s = {"type": "array", "items": s}
    return {"type": "object", "properties": {"a": s}, "required": [], "additionalProperties": False}


THIRD_PARTY = [
    ("valid", man(), True),
    ("every keyword", man(msgs=[{"type": "x:t:1", "schema": {"type": "object", "properties": {
        "s": {"type": "string", "maxLength": 3, "enum": ["a", "b"]}, "i": {"type": "integer", "minimum": -5, "maximum": 5},
        "b": {"type": "boolean"}, "n": {"type": "null"}, "a": {"type": "array", "items": {"type": "integer"}, "maxItems": 2},
        "o": {"type": "object", "properties": {}, "required": [], "additionalProperties": True}},
        "required": ["s"], "additionalProperties": False}}]), True),
    ("nesting 8 edges below the root", man(msgs=[{"type": "x:t:1", "schema": deep_schema(7)}]), True),
    ("nesting 9 edges below the root", man(msgs=[{"type": "x:t:1", "schema": deep_schema(8)}]), False),
    ("reserved ace: id", man(mid_="ace:translate:1"), False),
    ("reserved ace: message type", man(msgs=[{"type": "ace:t:1", "schema": OBJ}]), False),
    ("urn:ace: is not reserved", man(mid_="urn:ace:translate:1"), True),
    ("a version member", {**man(), "version": 1}, False),
    ("extra top-level member", man(extra=1), False),
    ("no messages", man(msgs=[]), False),
    ("33 messages", man(msgs=[{"type": f"x:t{i}:1", "schema": OBJ} for i in range(33)]), False),
    ("duplicate message types", man(msgs=[{"type": "x:t:1", "schema": OBJ}] * 2), False),
    ("message schema is not an object", man(msgs=[{"type": "x:t:1", "schema": {"type": "string"}}]), False),
    ("$ref", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "$ref": "#"}}]), False),
    ("unknown keyword pattern", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "string", "pattern": "a"}}}}]), False),
    ("inapplicable keyword maxLength on integer", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "integer", "maxLength": 1}}}}]), False),
    ("object without additionalProperties", man(msgs=[{"type": "x:t:1", "schema": {"type": "object", "properties": {}, "required": []}}]), False),
    ("required name not in properties", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "required": ["z"]}}]), False),
    ("minimum above maximum", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "integer", "minimum": 2, "maximum": 1}}}}]), False),
    ("enum value not matching its node", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "string", "enum": [1]}}}}]), False),
    ("empty enum", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "string", "enum": []}}}}]), False),
    ("bound above 2^53-1", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "integer", "maximum": 2 ** 53}}}}]), False),
    ("type 'number' is not in the dialect", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "number"}}}}]), False),
    ("canonical size above 65536", man(msgs=[{"type": "x:t:1", "schema": {**OBJ, "properties": {"q": {"type": "string", "enum": ["a" * 1100] * 60}}}}]), False),
]
tp_cases = []
for name, mf, ok in THIRD_PARTY:
    got = outcome(lambda: ProfileManifest(mf))
    assert (got is None) == ok and (ok or got == "invalid_argument"), (name, got)
    entry = {"name": name, "manifest": mf, "valid": ok}
    if ok:
        pm = ProfileManifest(mf)
        entry["digest"] = pm.digest
        entry["messages"] = {t: s.digest for t, s in pm.messages.items()}
    tp_cases.append(entry)

prof = Profiles([TEXT, COMMERCE])
D = {t: s.digest for m in (CORE, TEXT, COMMERCE) for t, s in m.messages.items()}
BODIES = [
    ("text", "ace:text:1", {"message": "hi"}, None),
    ("text without message", "ace:text:1", {}, "invalid_body"),
    ("text extra member", "ace:text:1", {"message": "hi", "x": 1}, "invalid_body"),
    ("text message null", "ace:text:1", {"message": None}, "invalid_body"),
    ("text with the commerce rfq digest", "ace:text:1", {"message": "hi"}, "unsupported_schema", D["ace:commerce:rfq:1"]),
    ("uninstalled digest", "ace:text:1", {"message": "hi"}, "unsupported_schema", "0" * 64),
    ("uninstalled type", "x:other:1", {}, "unsupported_schema", "0" * 64),
    ("receipt delivered", "ace:receipt:1", {"messageId": PKT_MID, "outcome": "delivered"}, None),
    ("receipt rejected with code and permit", "ace:receipt:1", {"messageId": PKT_MID, "outcome": "rejected", "code": "invalid_body", "permit": GOOD_PERMIT}, None),
    ("receipt unknown outcome", "ace:receipt:1", {"messageId": PKT_MID, "outcome": "busy"}, "invalid_body"),
    ("receipt unknown_prekey with the prekey", "ace:receipt:1", {"messageId": PKT_MID, "outcome": "rejected", "code": "unknown_prekey", "prekey": BOB_PREKEY["id"]}, None),
    ("receipt prekey of 65 characters", "ace:receipt:1", {"messageId": PKT_MID, "outcome": "rejected", "code": "unknown_prekey", "prekey": "a" * 65}, "invalid_body"),
    ("contact request", "ace:contact:1", {"kind": "request", "profile": "ace:text:1", "note": "hi", "source": BASE_PA, "permit": GOOD_PERMIT}, None),
    ("contact note of 513 characters", "ace:contact:1", {"kind": "request", "profile": "ace:text:1", "note": "a" * 513, "source": BASE_PA}, "invalid_body"),
    ("rfq", "ace:commerce:rfq:1", {"need": "translate", "maxPrice": "10", "currency": "USDC", "expiresAt": NOW + 3600}, None),
    ("rfq expiresAt 0", "ace:commerce:rfq:1", {"need": "x", "expiresAt": 0}, None),
    ("rfq expiresAt negative", "ace:commerce:rfq:1", {"need": "x", "expiresAt": -1}, "invalid_body"),
    ("rfq expiresAt written as 1.7601444e9", "ace:commerce:rfq:1", {"need": "x", "expiresAt": 1.7601444e9}, None),
    ("rfq expiresAt 1.5", "ace:commerce:rfq:1", {"need": "x", "expiresAt": 1.5}, "invalid_body"),
    ("rfq expiresAt as a string", "ace:commerce:rfq:1", {"need": "x", "expiresAt": "1760144400"}, "invalid_body"),
    ("rfq relative ttl (not in the schema)", "ace:commerce:rfq:1", {"need": "x", "ttl": 3600}, "invalid_body"),
    ("offer expiresAt", "ace:commerce:offer:1", {"price": "8", "currency": "USDC", "expiresAt": NOW + 600}, None),
    ("offer price as a number", "ace:commerce:offer:1", {"price": 10, "currency": "USDC"}, "invalid_body"),
    ("offer currency of 16 code points (emoji)", "ace:commerce:offer:1", {"price": "1", "currency": "😀" * 16}, None),
    ("offer currency of 17 code points", "ace:commerce:offer:1", {"price": "1", "currency": "😀" * 17}, "invalid_body"),
    ("invoice settlement method outside the enum", "ace:commerce:invoice:1", {"offerId": PKT_MID, "amount": "1", "currency": "USDC", "settlement": {"method": "paypal"}}, "invalid_body"),
    ("deliver metadata is open", "ace:commerce:deliver:1", {"type": "reference", "uri": "https://x.example/f", "metadata": {"checksum": "sha256:ab", "n": [1]}}, None),
]
body_cases = []
for b in BODIES:
    name, type_, body, code = b[:4]
    digest = b[4] if len(b) > 4 else D[type_]
    expect(f"body {name}", lambda: prof.validate(type_, digest, body), code)
    body_cases.append({"name": name, "type": type_, "schemaDigest": digest, "body": body, "error": code})

manifests = {
    "rules": (
        "official: each bundled manifest has profile digest 'digest' and message digests 'messages' (08 § Digests). "
        "thirdParty: validating 'manifest' as a third-party manifest succeeds iff 'valid' (invalid_argument), and then its "
        "digests are 'digest'/'messages'. bodies: with core, text and commerce installed, validate(type, schemaDigest, "
        "body) fails with 'error' or succeeds (null)."
    ),
    "official": official,
    "thirdParty": tp_cases,
    "bodies": body_cases,
}

# =============================================================================== core rules

RCPT = [
    ("delivered", {"messageId": PKT_MID, "outcome": "delivered"}, None),
    ("rejected with code", {"messageId": PKT_MID, "outcome": "rejected", "code": "invalid_body"}, None),
    ("rejected without code", {"messageId": PKT_MID, "outcome": "rejected"}, "invalid_body"),
    ("delivered with code", {"messageId": PKT_MID, "outcome": "delivered", "code": "invalid_body"}, "invalid_body"),
    ("code outside the grammar", {"messageId": PKT_MID, "outcome": "rejected", "code": "Bad-Code"}, "invalid_body"),
    ("messageId not a UUIDv4", {"messageId": "x", "outcome": "delivered"}, "invalid_body"),
    ("unknown_prekey with the prekey", {"messageId": PKT_MID, "outcome": "rejected", "code": "unknown_prekey", "prekey": BOB_PREKEY["id"]}, None),
    ("unknown_prekey without the prekey", {"messageId": PKT_MID, "outcome": "rejected", "code": "unknown_prekey"}, "invalid_body"),
    ("prekey with another code", {"messageId": PKT_MID, "outcome": "rejected", "code": "invalid_body", "prekey": BOB_PREKEY["id"]}, "invalid_body"),
    ("prekey with delivered", {"messageId": PKT_MID, "outcome": "delivered", "prekey": BOB_PREKEY["id"]}, "invalid_body"),
    ("prekey in uppercase hex", {"messageId": PKT_MID, "outcome": "rejected", "code": "unknown_prekey", "prekey": BOB_PREKEY["id"].upper()}, "invalid_body"),
    ("permit not an object", {"messageId": PKT_MID, "outcome": "delivered", "permit": []}, "invalid_body"),
]
rcpt_cases = []
for name, body, code in RCPT:
    expect(f"receipt rule {name}", lambda: check_receipt_body(body), code)
    rcpt_cases.append({"name": name, "body": body, "error": code})

_kel33 = [BASE_PA["kel"][0]] * 33
_kel32 = [BASE_PA["kel"][0]] * 32
STRANGER = [
    ("ordinary source", BASE_PA, None),
    ("kel of 32 events (count only)", {**BASE_PA, "kel": _kel32}, None),
    ("kel of 33 events", {**BASE_PA, "kel": _kel33}, "not_permitted"),
    ("ext with four credentials from unknown issuers", published({**BASE, "profiles": DLG_PROFILES,
     "ext": {"ace:delegation:1": {"credentials": [create_delegation_credential(i.identity, alice.id, now=NOW - 100) for i in
                                                  (bob, carol, dave)] + [cred_doc(simple_agent("erin"), alice.id, NOW - 100, NOW + 3600)]}}}),
     None),
]
stranger_cases = []
for name, src, code in STRANGER:
    expect(f"stranger source {name}", lambda: check_stranger_source(src), code)
    stranger_cases.append({"name": name, "source": src, "error": code})

core_rules = {
    "rules": (
        "receipts: the core receipt rules beyond the schema (06 § Receipts; checkReceiptBody) fail with 'error' "
        "(invalid_body) or accept (null). strangerSources: the structural bounds on a stranger's contact source (05 § "
        "Receiver admission: the source's own kel <= MAX_STRANGER_KEL_EVENTS events; nothing else in it is fetched or "
        "counted), checked before and independently of any signature, fail with 'error' (not_permitted) or pass."
    ),
    "receipts": rcpt_cases,
    "strangerSources": stranger_cases,
}

# =============================================================================== replay / dedupe

SA, SB, SC = "ace:sha256:" + "a" * 64, "ace:sha256:" + "b" * 64, "ace:sha256:" + "c" * 64


def sender(n):
    return f"ace:sha256:{n:064x}"


def classify(det, m, s, ts):
    if det.seen(m, s):
        return "duplicate"
    if det.covered(s, ts):
        return "replay_horizon"
    return "new"


def replay_case(name, capacity, horizon, ops, initial=None, check=None):
    det = ReplayDetector.from_state(initial, capacity=capacity) if initial else ReplayDetector(capacity=capacity, horizon=horizon)
    out = []
    for op in ops:
        kind, m, s, ts, *rest = op
        if kind == "commit":
            floor, want = rest
            assert det.commit(m, s, ts, floor) == want, (name, op)
            out.append({"op": "commit", "messageId": m, "sender": s, "timestamp": ts, "floor": floor, "expect": want})
        else:
            (want,) = rest
            assert classify(det, m, s, ts) == want, (name, op, classify(det, m, s, ts))
            out.append({"op": "classify", "messageId": m, "sender": s, "timestamp": ts, "expect": want})
    state = det.export_state()
    if check:
        assert check(state), (name, state)
    entry = {"name": name, "capacity": capacity, "horizon": horizon, **({"initialState": initial} if initial else {}), "ops": out,
             "finalState": state}
    return entry


replay_cases = [
    replay_case("duplicate, horizon and new", 100, 1000, [
        ("classify", mid(1), SA, 1000, "replay_horizon"), ("classify", mid(1), SA, 1001, "new"),
        ("commit", mid(1), SA, 1001, 900, True), ("classify", mid(1), SA, 1001, "duplicate"),
        ("classify", mid(1), SA, 5000, "duplicate"), ("commit", mid(1), SA, 1001, 900, False), ("classify", mid(2), SB, 1001, "new")]),
    replay_case("floor eviction raises H; an evicted entry is then beyond the horizon", 100, 1000, [
        ("commit", mid(1), SA, 1010, 1000, True), ("commit", mid(2), SA, 1020, 1000, True), ("commit", mid(3), SB, 1030, 1015, True),
        ("classify", mid(1), SA, 1010, "replay_horizon"), ("classify", mid(4), SA, 1011, "new"),
        ("commit", mid(1), SA, 1010, 1015, False), ("classify", mid(2), SA, 1020, "duplicate")],
        check=lambda s: s["horizon"] == 1010),
    replay_case("sender quota (capacity 48, Q = 3) raises only that sender's horizon", 48, 1000, [
        ("commit", mid(1), SB, 1100, 1000, True), *[("commit", mid(10 + k), SA, 2000 + k, 1000, True) for k in range(10)],
        ("classify", mid(1), SB, 1100, "duplicate"), ("classify", mid(2), SB, 1050, "new"),
        ("classify", mid(30), SA, 2006, "replay_horizon"), ("classify", mid(31), SA, 2010, "new"), ("classify", mid(19), SA, 2009, "duplicate")],
        check=lambda s: s["senderHorizons"] == {SA: 2006} and s["horizon"] == 1000),
    replay_case("capacity eviction raises only the victim's horizon", 32, 1000, [
        ("commit", mid(1), sender(0), 1005, 1000, True), ("commit", mid(2), sender(0), 1005, 1000, True),
        *[("commit", mid(100 + 2 * n + k), sender(n), 1100 + n, 1000, True) for n in range(1, 16) for k in range(2)],
        ("commit", mid(200), sender(16), 1200, 1000, True),
        ("classify", mid(3), sender(0), 1005, "replay_horizon"), ("classify", mid(3), sender(0), 1006, "new"), ("classify", mid(3), sender(17), 1001, "new")],
        check=lambda s: s["senderHorizons"] == {sender(0): 1005} and len(s["entries"]) == 31),
    replay_case("sender-horizon compaction folds into H", 2, 1000, [
        ("commit", mid(1), SA, 1010, 1000, True), ("commit", mid(2), SA, 1011, 1000, True), ("commit", mid(3), SB, 1020, 1000, True),
        ("commit", mid(4), SB, 1021, 1000, True), ("commit", mid(5), SC, 1030, 1000, True), ("commit", mid(6), SC, 1031, 1000, True),
        ("classify", mid(7), SA, 1015, "replay_horizon"), ("classify", mid(7), SA, 1021, "new"), ("classify", mid(7), SC, 1030, "replay_horizon")],
        check=lambda s: s["horizon"] == 1020 and s["senderHorizons"] == {SC: 1030}),
    replay_case("loading a state normalizes it", 48, None, [
        ("classify", mid(1), SA, 1002, "replay_horizon"), ("classify", mid(20), SC, 1500, "new"), ("classify", mid(6), SB, 1003, "duplicate")],
        initial={"version": 1, "horizon": 1000, "senderHorizons": {SC: 900, SB: 1001},
                 "entries": [[mid(5), SA, 1005], [mid(1), SA, 1001], [mid(3), SA, 1003], [mid(2), SA, 1002], [mid(4), SA, 1004], [mid(6), SB, 1003]]},
        check=lambda s: s["senderHorizons"] == {SA: 1002, SB: 1001} and len(s["entries"]) == 4),
]
replay = {
    "rules": (
        "06 § Deduplication. Start from ReplayDetector(capacity, horizon) or fromState(initialState, capacity). classify: "
        "'duplicate' if (sender, messageId) is held, else 'replay_horizon' if timestamp <= H or <= H[sender], else 'new'. "
        "commit(messageId, sender, timestamp, floor) returns 'expect'. Afterwards exportState() equals finalState "
        "(canonical JSON)."
    ),
    "cases": replay_cases,
}

# =============================================================================== commerce

RFQ_BODY = {"need": "translate 300 words EN->FR", "maxPrice": "10", "currency": "USDC"}
OFFER_BODY = {"price": "8", "currency": "USDC"}
SETTLE_INV = {"method": "stablecoin", "asset": "eip155:8453/erc20:0x833589fcd6edb6e08f4c7c32d4f71b54bda02913", "recipient": "0xabc"}
STRIPE_INV = {"method": "stripe-link", "url": "https://buy.stripe.com/test_123"}
REC_STABLE = {"method": "stablecoin", "proof": {"txHash": "0xdeadbeef"}}
REC_STRIPE = {"method": "stripe-link", "proof": {"paymentId": "pi_123"}}
DELIVER_BODY = {"type": "inline", "content": "Bonjour", "contentType": "text/plain"}


def run_commerce(local_role, steps, thread="t1"):
    """steps: (type, sender role, body or callable(ids) -> body, expected state or error code)."""
    store = MemoryStore()
    ids = {"buyer": alice.id, "seller": bob.id, "third": carol.id}
    local = ids[local_role]
    ts = ThreadStore(store, local)
    out, history = [], []
    for i, st in enumerate(steps):
        type_, role, body, want = st[:4]
        to_role = st[4] if len(st) > 4 else ("seller" if role == "buyer" else "buyer")
        b = body(history) if callable(body) else body
        e = MessageEvent("receive" if ids[role] != local else "send", mid(500 + i), ids[role], ids[to_role], NOW + i,
                         f"ace:commerce:{type_}:1", thread if not (len(st) > 5 and st[5] is None) else None)
        try:
            ts.decide(e, b)
            got = ts.apply(e, b)
            history.append(e.message_id)
        except ACEError as exc:
            got = exc.code
        assert got == want, (local_role, steps, i, got, want)
        out.append({"type": e.type, "from": role, "to": to_role, "messageId": e.message_id, "timestamp": e.timestamp,
                    **({"threadId": e.thread_id} if e.thread_id else {}), "body": b, "expect": want})
    return out


H = lambda k: (lambda h: {**k[1], k[0]: h[k[2]]})  # noqa: E731  (field, base body, history index)
comm_cases = []
for local in ("buyer", "seller"):
    comm_cases.append({"name": f"stablecoin path, invoiced first (local {local})", "local": local, "steps": run_commerce(local, [
        ("rfq", "buyer", RFQ_BODY, "requested"), ("offer", "seller", OFFER_BODY, "offered"),
        ("offer", "seller", {"price": "7", "currency": "USDC"}, "offered"),
        ("accept", "buyer", H(("offerId", {}, -1)), "accepted"),
        ("invoice", "seller", H(("offerId", {"amount": "7", "currency": "USDC", "settlement": SETTLE_INV}, -2)), "invoiced"),
        ("payment", "buyer", H(("referenceId", {"amount": "7", "currency": "USDC", "settlement": REC_STABLE}, -1)), "paid"),
        ("deliver", "seller", DELIVER_BODY, "delivered"), ("confirm", "buyer", H(("deliverId", {"message": "thanks"}, -1)), "confirmed"),
        ("rfq", "buyer", RFQ_BODY, "transition_not_allowed")])})
comm_cases.append({"name": "pre-paid with Stripe Link, then deliver", "local": "seller", "steps": run_commerce("seller", [
    ("rfq", "buyer", RFQ_BODY, "requested"), ("offer", "seller", OFFER_BODY, "offered"), ("accept", "buyer", H(("offerId", {}, -1)), "accepted"),
    ("payment", "buyer", H(("referenceId", {"amount": "8", "currency": "USDC", "settlement": REC_STRIPE}, -1)), "paid"),
    ("deliver", "seller", {"type": "reference", "uri": "https://files.example/out.txt"}, "delivered")])})
comm_cases.append({"name": "deliver first", "local": "buyer", "steps": run_commerce("buyer", [
    ("rfq", "buyer", RFQ_BODY, "requested"), ("offer", "seller", OFFER_BODY, "offered"), ("accept", "buyer", H(("offerId", {}, -1)), "accepted"),
    ("deliver", "seller", DELIVER_BODY, "delivered"), ("invoice", "seller", H(("offerId", {"amount": "8", "currency": "USDC", "settlement": STRIPE_INV}, -2)), "transition_not_allowed")])})
comm_cases.append({"name": "seller rejects the rfq; terminal", "local": "buyer", "steps": run_commerce("buyer", [
    ("rfq", "buyer", RFQ_BODY, "requested"), ("reject", "seller", {"reason": "busy"}, "rejected"), ("offer", "seller", OFFER_BODY, "transition_not_allowed")])})
comm_cases.append({"name": "check order and codes", "local": "seller", "steps": run_commerce("seller", [
    ("rfq", "buyer", RFQ_BODY, "invalid_body", "seller", None),
    ("offer", "seller", OFFER_BODY, "transition_not_allowed"),
    ("rfq", "buyer", RFQ_BODY, "requested"),
    ("rfq", "buyer", RFQ_BODY, "transition_not_allowed"),
    ("offer", "buyer", OFFER_BODY, "wrong_role", "seller"),
    ("offer", "third", OFFER_BODY, "wrong_party", "buyer"),
    ("offer", "seller", OFFER_BODY, "offered"),
    ("accept", "buyer", {"offerId": mid(999)}, "bad_reference"),
    ("accept", "seller", H(("offerId", {}, -1)), "wrong_role", "buyer"),
    ("accept", "buyer", H(("offerId", {}, -1)), "accepted"),
    ("invoice", "seller", H(("offerId", {"amount": "8", "currency": "USDC", "settlement": {**SETTLE_INV, "asset": "usdc"}}, -2)), "invalid_body"),
    ("invoice", "seller", H(("offerId", {"amount": "8", "currency": "USDC", "settlement": {**STRIPE_INV, "url": "http://x.example"}}, -2)), "invalid_body"),
    ("invoice", "seller", H(("offerId", {"amount": "8", "currency": "USDC", "settlement": {**SETTLE_INV, "url": "https://x.example"}}, -2)), "invalid_body"),
    ("invoice", "seller", H(("offerId", {"amount": "8", "currency": "USDC", "settlement": SETTLE_INV}, -1)), "bad_reference"),
    ("invoice", "seller", H(("offerId", {"amount": "8", "currency": "USDC", "settlement": {**SETTLE_INV, "memo": "order 7"}}, -2)), "invoiced"),
    ("payment", "buyer", H(("referenceId", {"amount": "8", "currency": "USDC", "settlement": {"method": "stablecoin", "proof": {"paymentId": "pi"}}}, -1)), "invalid_body"),
    ("payment", "buyer", H(("referenceId", {"amount": "8", "currency": "USDC", "settlement": {"method": "stablecoin", "proof": {"txHash": ""}}}, -1)), "invalid_body"),
    ("payment", "buyer", H(("referenceId", {"amount": "8", "currency": "USDC", "settlement": REC_STABLE}, -1)), "paid"),
    ("deliver", "seller", {"type": "inline"}, "invalid_body"),
    ("deliver", "seller", {"type": "reference", "content": "x"}, "invalid_body"),
])})

# Sender state and busy threads (08 § Sender state and busy threads), local party alice (buyer), peer bob.
def run_sender(steps):
    """steps: (op, args, expect); op is send | receipt | receive | abandon. Returns the case steps."""
    clock = {"t": NOW}
    store = MemoryStore()
    rules = commerce_rules(store, alice.id)
    ob = Outbox(alice.identity, store, Profiles([TEXT, COMMERCE]), vault=PrekeyVault(), rules=[rules], clock=lambda: clock["t"])
    conv = conversation_key(alice.id, bob.id)
    out = []
    for i, (op, a, want) in enumerate(steps):
        clock["t"] = NOW + i
        typ = f"ace:commerce:{a['type']}:1" if "type" in a else None
        try:
            if op == "send":
                ob.enqueue(bob.id, typ, a["body"], thread_id=a.get("threadId", "t1"), message_id=a["messageId"])
            elif op == "receipt":
                ob.settle(a["messageId"], a["outcome"], a.get("code"), sender=bob.id)
            elif op == "abandon":
                ob.abandon(a["messageId"])
            elif op == "receive":
                e = MessageEvent("receive", a["messageId"], bob.id, alice.id, NOW + i, typ, a.get("threadId", "t1"))
                if ob.busy(bob.id, e.thread_id) is not None:
                    raise ACEError("thread_busy", "busy")
                rules.check(e, a["body"])
                rules.commit(e, a["body"])
            got = "ok"
        except ACEError as exc:
            got = exc.code
        snap = rules.threads.get(conv, "t1")
        step = {"op": op, **{k: v for k, v in a.items() if k != "type"}, **({"type": typ} if typ else {}),
                "expect": got, "state": None if snap is None else snap.state, "busy": ob.busy(bob.id, "t1") is not None}
        assert got == want, (i, step, want)
        out.append(step)
    return out


SM = [mid(700 + i) for i in range(12)]
sender_cases = [{"name": "commit on delivered; busy thread; rejected and crossing change nothing; a late receipt settles an abandoned message", "steps": run_sender([
    ("send", {"type": "rfq", "messageId": SM[0], "body": RFQ_BODY}, "ok"),
    ("send", {"type": "rfq", "messageId": SM[1], "body": RFQ_BODY}, "thread_busy"),
    ("send", {"type": "rfq", "messageId": SM[1], "threadId": "t2", "body": RFQ_BODY}, "ok"),
    ("receipt", {"messageId": SM[0], "outcome": "delivered"}, "ok"),
    ("receive", {"type": "offer", "messageId": SM[2], "body": OFFER_BODY}, "ok"),
    ("send", {"type": "accept", "messageId": SM[3], "body": {"offerId": SM[2]}}, "ok"),
    ("receive", {"type": "offer", "messageId": SM[4], "body": {"price": "7", "currency": "USDC"}}, "thread_busy"),
    ("receipt", {"messageId": SM[3], "outcome": "rejected", "code": "thread_busy"}, "ok"),
    ("send", {"type": "accept", "messageId": SM[5], "body": {"offerId": SM[2]}}, "ok"),
    ("abandon", {"messageId": SM[5]}, "ok"),
    ("receipt", {"messageId": SM[5], "outcome": "delivered"}, "ok"),
    ("receipt", {"messageId": SM[5], "outcome": "delivered"}, "ok"),
    ("send", {"type": "accept", "messageId": SM[6], "body": {"offerId": SM[2]}}, "transition_not_allowed"),
])}]
assert [s["state"] for s in sender_cases[0]["steps"]] == [
    None, None, None, "requested", "offered", "offered", "offered", "offered", "offered", "offered", "accepted", "accepted", "accepted"]

EXT = [(COMMERCE_EXT, True), ({"settlement": [{"method": "stripe-link"}]}, True), ({"settlement": []}, False),
       ({"settlement": [{"method": "stripe-link", "url": "https://x"}]}, False), ({"settlement": [{"method": "stablecoin"}]}, False),
       ({"settlement": [{"method": "card"}]}, False), ({}, False)]
for v, ok in EXT:
    assert (outcome(lambda: validate_commerce_ext(v)) is None) == ok, v
commerce = {
    "rules": (
        "profiles/commerce.md. transitions: a fresh thread store per case for the local party agents.alice (buyer) or "
        "agents.bob (seller); the third party is agents.carol. For each step, run the commerce rule check then commit for "
        "event {direction: receive when 'from' is not local else send, messageId, from, to, timestamp, type, threadId} "
        "and body (already schema-valid): the resulting thread state equals 'expect', or check fails with the code "
        "'expect' and nothing changes. ext: validateCommerceExt accepts iff 'valid' (invalid_authorization). "
        "sender (08 § Sender state and busy threads): an Outbox for agents.alice with commerceRules, peer agents.bob, "
        "clock now + step index. Ops: send = enqueue(to bob, type, body, threadId (default t1), messageId); receipt = "
        "apply a receipt from bob {messageId, outcome, code?}; abandon = abandon(messageId) (the entry becomes expired: "
        "outcome unknown, a later receipt still settles it); receive = an inbound "
        "message from bob at pipeline step 10 (timestamp = clock): thread_busy if the Outbox reports thread t1 busy "
        "towards bob, else commerce check then commit. 'expect' is 'ok' or the error code; after each step the thread "
        "t1 state (null = no thread) and whether t1 is busy towards bob equal 'state' and 'busy'."
    ),
    "parties": {"buyer": "alice", "seller": "bob", "third": "carol"},
    "transitions": comm_cases,
    "sender": sender_cases,
    "ext": [{"value": v, "valid": ok} for v, ok in EXT],
}

# =============================================================================== receive pipeline (06)

CAROL_PREKEY_SEED = seed("carol-prekey").hex()
CAROL_PREKEY = prekey_of(CAROL_PREKEY_SEED)
CAROL_PA = published({**_min, "aceId": carol.id, "prekey": CAROL_PREKEY}, signer=carol)
CONTACT_SOURCE = published({**BASE, "issuedAt": NOW - 7300, "expiresAt": NOW + 3600})
RECEIPT_SEEDS = {alice.id: seed("alice-prekey").hex(), carol.id: CAROL_PREKEY_SEED}


OFFERS_TO_BOB = {alice.id: ALICE_OFFER_BOB, carol.id: CAROL_OFFER_BOB}  # the prekey each sender's contents carry


def text_packet(sender: Agent, n: int, ts: int, to_prekey=BOB_PREKEY) -> dict:
    content = {**CONTENT, "prekey": OFFERS_TO_BOB[sender.id]["publicKey"]}
    return manual_packet(sender, bob.id, to_prekey, content, ts, mid_=mid(n), kem=KEM if to_prekey is BOB_PREKEY else None)


def contact_packet(n: int, ts: int) -> dict:
    body = {"kind": "request", "profile": TEXT.id, "note": "hello", "source": CONTACT_SOURCE,
            "permit": permit_doc(alice, bob.id, NOW - 7300, NOW - 7300 + 2592000)}
    content = {"type": "ace:contact:1", "schemaDigest": D["ace:contact:1"], "body": body, "prekey": ALICE_OFFER_BOB["publicKey"]}
    return manual_packet(alice, bob.id, BOB_PREKEY, content, ts, mid_=mid(n))


def receipt_packet(n: int, ts: int, about: str) -> dict:
    """A receipt from alice to bob for bob's message ``about``."""
    content = {"type": "ace:receipt:1", "schemaDigest": D["ace:receipt:1"], "body": {"messageId": about, "outcome": "delivered"},
               "prekey": ALICE_OFFER_BOB["publicKey"]}
    return manual_packet(alice, bob.id, BOB_PREKEY, content, ts, mid_=mid(n))


def receipt_of(out) -> str | None:
    """The outcome of the receipt the receiver sends, read back by decrypting it."""
    if out.receipt is None:
        return None
    p = decode_packet(out.receipt.packet)
    v = PrekeyVault()
    v._state = _State(_entry(bytes.fromhex(RECEIPT_SEEDS[p.to_id]), T0), [], {})
    content = decode_content(decrypt_packet(p, v, NOW))
    assert content["type"] == "ace:receipt:1"
    return content["body"]["outcome"]


def pipeline_case(name, steps, *, contact="closed", capacity=100_000, pinned=(), peer_seeds=None, vault_after=None):
    clock = {"t": NOW}
    store = MemoryStore()
    peers = PeerStore(store, clock=lambda: clock["t"])
    pins = {}
    for agent, pa in pinned:
        peers.adopt(pa, NOW)
        peers.set_status(agent.id, "admitted")
        pins[agent.name] = pa
    vault = bob_vault(peer_seeds)
    inbox = Inbox.open(bob.identity, store, vault, peers, Profiles(), on_message=lambda m: None, contact=contact,
                       capacity=capacity, clock=lambda: clock["t"])
    out_steps = []
    for packet_, now, want in steps:
        clock["t"] = now
        out = inbox.receive(json.dumps(packet_).encode())
        disposition = {"delivered": "delivered", "duplicate": "duplicate", "dropped": "drop", "rejected": "reject"}[out.kind]
        got = {"disposition": disposition, "code": None if out.error is None else out.error.code, "receipt": receipt_of(out)}
        assert got == want, (name, got, want)
        out_steps.append({"packet": packet_, "now": now, "expect": want})
    inbox.close()
    case = {"name": name, "receiver": "bob", "contact": contact, "capacity": capacity, "admitted": pins,
            **({"peerSeeds": peer_seeds} if peer_seeds else {}), "steps": out_steps}
    if vault_after is not None:
        # the offered key the steps opened under became the in-use key (the receipt to peer offered a fresh one);
        # the in-use one still opens for peer only
        p = vault._state.peers[vault_after["peer"]]
        assert p.in_use is not None and p.in_use.prekey.id == vault_after["inUse"], name
        assert p.offered is None or p.offered.prekey.id != vault_after["inUse"], name
        vault.open(vault_after["inUse"], clock["t"], sender=vault_after["peer"])
        assert outcome(lambda: vault.open(vault_after["inUse"], clock["t"], sender=carol.id)) == "unknown_prekey"
        if "held" in vault_after:  # the holder rule: the key the peer's packets carried, under bob's pin for it
            pin = verify_kel(pins[next(n for n, a in AGENTS.items() if a.id == vault_after["peer"])]["kel"], NOW).last_hash
            got = vault.held(vault_after["peer"], pin, clock["t"])
            assert got is not None and b64(got.public_key) == vault_after["held"]["publicKey"], name
            assert vault._state.peers[vault_after["peer"]].held.timestamp == vault_after["held"]["timestamp"], name
        case["vaultAfter"] = vault_after
    return case


def X(disposition, code=None, receipt=None):
    return {"disposition": disposition, "code": code, "receipt": receipt}


_p1, _p2 = text_packet(alice, 900, NOW - 20), text_packet(alice, 901, NOW - 10)
pipeline_cases = [
    pipeline_case("a duplicate is receipted delivered; beyond the horizon is dropped and never receipted (capacity 16: Q = 1)", [
        (_p1, NOW, X("delivered", receipt="delivered")),
        (_p2, NOW, X("delivered", receipt="delivered")),  # evicts _p1: H[alice] = NOW - 20
        (text_packet(alice, 902, NOW - 20), NOW, X("drop", "replay_horizon")),
        (_p1, NOW, X("drop", "replay_horizon")),
        (_p2, NOW, X("duplicate", receipt="delivered")),
    ], capacity=16, pinned=[(alice, BASE_PA)]),
    pipeline_case("a stranger's contact request signed two hours ago is held (no separate contact window)", [
        (contact_packet(920, NOW - 7200), NOW, X("delivered")),
        (contact_packet(921, NOW - 604801), NOW, X("drop", "stale_timestamp")),
    ], contact="open"),
    pipeline_case("back-dated: signed before the sender's notAfter, received after it, is dropped stale_peer_binding", [
        (text_packet(carol, 911, NOW + 50), NOW + 60, X("delivered", receipt="delivered")),
        (text_packet(carol, 910, NOW + 50), NOW + 150, X("drop", "stale_peer_binding")),
    ], pinned=[(carol, CAROL_PA)]),
    pipeline_case("first message opened under offered key is delivered", [
        (text_packet(alice, 940, NOW - 10, BOB_OFFER_ALICE), NOW, X("delivered", receipt="delivered")),
        (text_packet(alice, 941, NOW - 5, BOB_OFFER_ALICE), NOW, X("delivered", receipt="delivered")),  # in use: still opens
    ], pinned=[(alice, BASE_PA)], peer_seeds={alice.id: BOB_OFFER_ALICE_SEED},
       vault_after={"peer": alice.id, "inUse": BOB_OFFER_ALICE["id"],
                    "held": {"publicKey": ALICE_OFFER_BOB["publicKey"], "timestamp": NOW - 5}}),
    pipeline_case("a replayed receipt is a duplicate (deduplicated at step 9, applied once) and is never receipted", [
        (_r1 := receipt_packet(930, NOW - 5, PKT_MID), NOW, X("delivered")),
        (_r1, NOW + 1, X("duplicate")),
        (receipt_packet(931, NOW - 4, PKT_MID), NOW + 2, X("delivered")),
    ], pinned=[(alice, BASE_PA)]),
]
pipeline = {
    "rules": (
        "06 § Receive pipeline. For each case a fresh receiver agents[receiver] whose vault holds "
        "packet.deterministic.prekeySeed as its published current prekey and, for an optional 'peerSeeds' {aceId: "
        "seedHex}, each seed as the peer prekey offered to that aceId (peers[aceId].offered = {seed, offeredAt: the "
        "vectors' top-level now}; same meaning as packet.open), whose own card record has contact 'contact' (open or closed), whose seen store has "
        "capacity 'capacity', and which has pinned and admitted each 'admitted' PublishedAgent (verified at the vectors' "
        "'now'). Run the steps in order, each at clock 'now': processing 'packet' ends in 'disposition' (delivered, "
        "duplicate, drop or reject) with record code 'code' (null on success), and the receiver sends a receipt whose "
        "outcome is 'receipt', or none (null). Receipts and contact requests are never receipted (a replayed receipt is a "
        "duplicate like any packet); a packet beyond the replay horizon "
        "is dropped with record code replay_horizon and no receipt. Every content carries 'prekey' (the key the sender "
        "offers the receiver); the receiver strips it before validation. After step 6 opens a packet under the key offered "
        "to its sender, that key becomes the sender's in-use key (used(from, prekeyId)). An optional 'vaultAfter' "
        "{peer: aceId, inUse: prekeyId} is the receiver vault after the last step: peers[peer].inUse is that key, the key "
        "offered to peer (if any; a receipt to peer offers a fresh one) is a different one, and open(inUse, sender = "
        "peer) still succeeds (unknown_prekey for any other sender). Its optional 'held' {publicKey, timestamp} is the holder "
        "rule's record for peer: the content prekey of peer's newest packet and that packet's timestamp; held(peer, pin, "
        "now) returns that key, where pin is the receiver's pin for peer = lastHash of verifyKel(admitted[name of peer].kel, "
        "the vectors' top-level now) (the digest of the peer's last KEL event)."
    ),
    "cases": pipeline_cases,
}

# =============================================================================== auth headers and registration (07)

AUDIENCE = RELAY
OTHER_RELAY = "https://other-relay.example"
_DEC = re.compile(r"0|[1-9][0-9]{0,15}")
AUTH_REQUESTS = [
    {"action": "listen", "since": "-"}, {"action": "listen", "since": "1760140800000-3"},
    {"action": "inbox", "since": "-", "limit": 100}, {"action": "inbox", "since": "1760140800000-3", "limit": 1},
    {"action": "inbox-ack", "through": "1760140800000-3"},
    {"action": "block", "peer": alice.id, "blocked": True, "revision": 1},
    {"action": "block", "peer": alice.id, "blocked": False, "revision": 9007199254740991},
    {"action": "unregister"},
    {"action": "wake", "gateway": "https://push.example/ace", "token": "dG9rZW4tMDEyMzQ1Njc4OWFi"},
    {"action": "wake"},
]


def action_payload(r) -> bytes:
    """02 § Signing actions."""
    a = r["action"]
    if a == "listen":
        return encode_payload(r["since"])
    if a == "inbox":
        return encode_payload(r["since"], str(r["limit"]))
    if a == "inbox-ack":
        return encode_payload(r["through"])
    if a == "block":
        return encode_payload(r["peer"], "block" if r["blocked"] else "unblock", str(r["revision"]))
    if a == "wake" and "gateway" in r:
        return encode_payload(r["gateway"], r["token"])
    return b""


def relay_verify_auth(headers, r, agent: Agent, now, audience=AUDIENCE):
    """07 § Authentication, in its order, against agents[agent]'s registered KEL (reference check)."""
    h = {k.lower(): v for k, v in headers.items()}
    names = ("x-ace-id", "x-ace-timestamp", "x-ace-seq", "x-ace-audience", "x-ace-nonce", "x-ace-signature")
    ace_id, ts, seq, aud, nonce, sig = (h.get(n) for n in names)
    if (not all(isinstance(v, str) for v in (ace_id, ts, seq, aud, nonce, sig)) or not is_ace_id(ace_id)
            or not _DEC.fullmatch(ts) or not _DEC.fullmatch(seq) or max(int(ts), int(seq)) > 2 ** 53 - 1
            or not is_canonical_relay_url(aud, allow_loopback=False) or not re.fullmatch(r"[0-9a-f]{64}", nonce)
            or len(sig) != 4412):
        raise ACEError("invalid_argument", "malformed auth headers")
    raw = from_base64(sig)
    if ace_id != agent.id:
        raise ACEError("not_registered", "")
    state = verify_kel(agent.kel, now)
    if int(seq) != state.signing.seq:
        raise ACEError("stale_seq" if int(seq) < state.signing.seq else "future_seq", "")
    if aud != audience:
        raise ACEError("invalid_signature", "audience")
    if abs(now - int(ts)) > 300:
        raise ACEError("stale_timestamp", "")
    na = state.signing.not_after
    dlg_ts = state.events[state.signing.seq]["ts"]
    if int(ts) < dlg_ts or (na is not None and int(ts) >= na) or not is_usable(state, now):  # signed while live (01 rule 3)
        raise ACEError("stale_peer_binding", "")
    m = signing_message(ace_id, int(ts), int(seq), encode_payload(aud, nonce, action_payload(r)))
    if not verify_signature(m, r["action"], raw, state.signing.public_key):
        raise ACEError("invalid_signature", "")


auth_cases = []
for i, r in enumerate(AUTH_REQUESTS):
    nonce = hashlib.sha256(f"nonce-{i}".encode()).hexdigest()
    hdrs = create_auth_headers(bob.identity, r["action"], action_payload(r), NOW, audience=AUDIENCE, nonce=nonce)
    assert set(hdrs) == {"X-ACE-Audience", "X-ACE-Nonce", "X-ACE-Id", "X-ACE-Timestamp", "X-ACE-Seq", "X-ACE-Signature"}
    relay_verify_auth(hdrs, r, bob, NOW)
    ap_ = encode_payload(AUDIENCE, nonce, action_payload(r))
    m = signing_message(bob.id, NOW, bob.seq, ap_)
    assert verify_signature(m, r["action"], from_base64(hdrs["X-ACE-Signature"]), bob.signing.public_key())
    auth_cases.append({"agent": "bob", "request": r, "timestamp": NOW, "audience": AUDIENCE, "nonce": nonce,
                       "payloadHex": action_payload(r).hex(), "authPayloadHex": ap_.hex(), "messageHex": m.hex(), "headers": hdrs})
auth_negative = []
_h = auth_cases[0]["headers"]


def auth_neg(name, headers, now, code, request=None, agent=bob):
    r = request or AUTH_REQUESTS[0]
    expect(f"auth {name}", lambda: relay_verify_auth(headers, r, agent, now), code)
    auth_negative.append({"name": name, "agent": agent.name, "headers": headers, "request": r, "now": now, "error": code})


auth_neg("timestamp older than 300 s", _h, NOW + 301, "stale_timestamp")
auth_neg("timestamp more than 300 s ahead", _h, NOW - 301, "stale_timestamp")
auth_neg("signed for another action's payload", _h, NOW, "invalid_signature", request=AUTH_REQUESTS[1])
auth_neg("nonce changed after signing", {**_h, "X-ACE-Nonce": "ab" * 32}, NOW, "invalid_signature")
auth_neg("superseded delegation seq", {**_h, "X-ACE-Seq": "1"}, NOW, "stale_seq")
auth_neg("seq ahead of the registered KEL", {**_h, "X-ACE-Seq": "4"}, NOW, "future_seq")
auth_neg("timestamp with a leading zero", {**_h, "X-ACE-Timestamp": "0" + _h["X-ACE-Timestamp"]}, NOW, "invalid_argument")
auth_neg("uppercase nonce", {**_h, "X-ACE-Nonce": _h["X-ACE-Nonce"].upper()}, NOW, "invalid_argument")
auth_neg("signature of 4408 characters", {**_h, "X-ACE-Signature": _h["X-ACE-Signature"][:-4]}, NOW, "invalid_argument")
_other = create_auth_headers(bob.identity, "listen", action_payload(AUTH_REQUESTS[0]), NOW, audience=OTHER_RELAY,
                             nonce=hashlib.sha256(b"nonce-other").hexdigest())
auth_neg("signed for another relay's audience", _other, NOW, "invalid_signature")
_carol_h = create_auth_headers(carol.identity, "listen", action_payload(AUTH_REQUESTS[0]), NOW + 99, audience=AUDIENCE,
                               nonce=hashlib.sha256(b"nonce-carol").hexdigest())
relay_verify_auth(_carol_h, AUTH_REQUESTS[0], carol, NOW + 99)
auth_neg("signed while live, verified after the delegation's notAfter", _carol_h, NOW + 101, "stale_peer_binding", agent=carol)
# signed one second before bob's current dlg (T0 + 10): create_auth_headers signs at the log tail, so these are made by hand
_early_nonce = hashlib.sha256(b"nonce-early").hexdigest()
_early_m = signing_message(bob.id, BOB_DLG_TS - 1, bob.seq, encode_payload(AUDIENCE, _early_nonce, action_payload(AUTH_REQUESTS[0])))
_early_h = {**_h, "X-ACE-Nonce": _early_nonce, "X-ACE-Timestamp": str(BOB_DLG_TS - 1),
            "X-ACE-Signature": b64(bob.signing.sign(_early_m, "listen"))}
auth_neg("timestamp before the dlg ts", _early_h, BOB_DLG_TS + 100, "stale_peer_binding")
# a signer never produces them: its timestamp is max(now, ts of its last event)
assert create_auth_headers(bob.identity, "listen", action_payload(AUTH_REQUESTS[0]), BOB_DLG_TS - 1,
                           audience=AUDIENCE)["X-ACE-Timestamp"] == str(BOB_DLG_TS)


def relay_verify_registration(req, audience, now) -> str:
    """07 § Registration steps 1-5 (reference check); returns the idempotency digest SHA-256(M)."""
    sig = req.get("signature") if isinstance(req, dict) else None
    if (not isinstance(req, dict) or set(req) != {"aceId", "kel", "timestamp", "audience", "signature"}
            or not is_ace_id(req["aceId"]) or not isinstance(req["kel"], list)
            or not is_canonical_relay_url(req["audience"], allow_loopback=False) or wire_int(req["timestamp"]) is None
            or not isinstance(sig, dict) or set(sig) != {"scheme", "seq", "value"} or sig["scheme"] != "ml-dsa-65"
            or wire_int(sig["seq"]) is None):
        raise ACEError("invalid_registration", "")
    if req["audience"] != audience:
        raise ACEError("invalid_signature", "audience")
    ts = wire_int(req["timestamp"])
    if abs(now - ts) > 300:
        raise ACEError("stale_timestamp", "")
    state = verify_kel(req["kel"], now)
    if not is_usable(state, now):
        raise ACEError("invalid_kel", "")
    if state.ace_id != req["aceId"]:
        raise ACEError("invalid_registration", "")
    if wire_int(sig["seq"]) != state.signing.seq:
        raise ACEError("invalid_signature", "seq")
    if ts < state.events[state.signing.seq]["ts"] or (state.signing.not_after is not None and ts >= state.signing.not_after):
        raise ACEError("stale_peer_binding", "")  # signed while live (01 rule 3)
    m = signing_message(state.ace_id, ts, state.signing.seq, encode_payload(state.last_hash, req["audience"]))
    if not verify_signature(m, "register-request", from_base64(sig["value"]), state.signing.public_key):
        raise ACEError("invalid_authorization", "")
    return hashlib.sha256(m).hexdigest()


reg = create_registration_request(bob.identity, NOW, audience=RELAY)
REG_MESSAGE = signing_message(bob.id, NOW, bob.seq, encode_payload(bob.state.last_hash, RELAY))
assert relay_verify_registration(reg, RELAY, NOW) == hashlib.sha256(REG_MESSAGE).hexdigest()
_reg_retarget = {**reg, "audience": OTHER_RELAY}
_reg_seq = {**reg, "signature": {**reg["signature"], "seq": 1}}
# signed one second before bob's current dlg (T0 + 10): create_registration_request signs at the log tail, so this
# one is made by hand
_reg_early_m = signing_message(bob.id, BOB_DLG_TS - 1, bob.seq, encode_payload(bob.state.last_hash, RELAY))
_reg_early = {**reg, "timestamp": BOB_DLG_TS - 1,
              "signature": {**reg["signature"], "value": b64(bob.signing.sign(_reg_early_m, "register-request"))}}
REG_NEGATIVE = [
    ("verified by another relay", reg, OTHER_RELAY, NOW, "invalid_signature"),
    ("audience changed after signing", _reg_retarget, OTHER_RELAY, NOW, "invalid_authorization"),
    ("timestamp older than 300 s", reg, RELAY, NOW + 301, "stale_timestamp"),
    ("signature seq of a superseded delegation", _reg_seq, RELAY, NOW, "invalid_signature"),
    ("timestamp before the dlg ts: stale_peer_binding", _reg_early, RELAY, BOB_DLG_TS + 100, "stale_peer_binding"),
]
for name, rq, aud, now_, code in REG_NEGATIVE:
    expect(f"registration {name}", lambda: relay_verify_registration(rq, aud, now_), code)
# a signer never produces it: its timestamp is max(now, ts of its last event)
assert create_registration_request(bob.identity, BOB_DLG_TS - 1, audience=RELAY)["timestamp"] == BOB_DLG_TS
WAKE_TOKEN = re.compile(r"[A-Za-z0-9_-]{22,512}")


def wake_registration_ok(body) -> bool:
    """07 § Wake hints: the closed {gateway, token}; gateway a canonical relay URL."""
    return (isinstance(body, dict) and set(body) == {"gateway", "token"} and isinstance(body["gateway"], str)
            and is_canonical_relay_url(body["gateway"], allow_loopback=False) and isinstance(body["token"], str)
            and WAKE_TOKEN.fullmatch(body["token"]) is not None)


_tok = "A" * 22
WAKE_VALID = [
    {"gateway": "https://push.example", "token": _tok},
    {"gateway": "https://push.example/v1/ace-wake", "token": "aZ09_-" * 4},
    {"gateway": "https://push.example:8443/w", "token": "x" * 512},
]
WAKE_INVALID = [
    ("http gateway", {"gateway": "http://push.example", "token": _tok}),
    ("gateway with a query", {"gateway": "https://push.example/w?k=1", "token": _tok}),
    ("gateway with a trailing slash", {"gateway": "https://push.example/w/", "token": _tok}),
    ("gateway with an uppercase host", {"gateway": "https://Push.example", "token": _tok}),
    ("gateway with userinfo", {"gateway": "https://u@push.example", "token": _tok}),
    ("token of 21 characters", {"gateway": "https://push.example", "token": "A" * 21}),
    ("token of 513 characters", {"gateway": "https://push.example", "token": "A" * 513}),
    ("token with base64 padding", {"gateway": "https://push.example", "token": _tok + "=="}),
    ("token with '+'", {"gateway": "https://push.example", "token": _tok + "+"}),
    ("extra member", {"gateway": "https://push.example", "token": _tok, "aceId": alice.id}),
    ("missing token", {"gateway": "https://push.example"}),
]
for _b in WAKE_VALID:
    assert wake_registration_ok(_b), _b
for _n, _b in WAKE_INVALID:
    assert not wake_registration_ok(_b), _n

auth = {
    "rules": (
        "07 § Authentication. cases: the action payload (02 § Signing actions) of 'request' == payloadHex; "
        "encodePayload(audience, nonce, payload) == authPayloadHex; M(agents[agent].aceId, timestamp, seq, authPayload) == "
        "messageHex, over which X-ACE-Signature verifies with ctx = the action; a relay verifying 'headers' for "
        "'request' at clock = timestamp with its own audience accepts them. negative: a relay holding agents[agent]'s "
        "KEL, verifying 'headers' for 'request' at clock 'now' with audience " + AUDIENCE + ", fails with 'error' "
        "(checks in 07 order). registration: the RegistrationRequest verifies at clock 'now' for 'audience'; "
        "payloadHex = encodePayload(lastHashHex, audience); messageHex = M(aceId, timestamp, seq, payload); the "
        "idempotency digest is requestDigest = SHA-256(M); each 'negative' entry (request, audience, now) fails with its "
        "'error' (07 § Registration steps 1-5). wake: each 'valid' body is a well-formed PUT /v1/wake request "
        "{gateway, token} (07 § Wake hints) that a client sends; each 'invalid' body is refused before signing and by a "
        "relay with invalid_argument. A wake request with no gateway is DELETE /v1/wake with an empty payload."
    ),
    "cases": auth_cases,
    "negative": auth_negative,
    "registration": {"agent": "bob", "request": reg, "audience": RELAY, "now": NOW, "lastHashHex": bob.state.last_hash,
                     "payloadHex": encode_payload(bob.state.last_hash, RELAY).hex(), "messageHex": REG_MESSAGE.hex(),
                     "requestDigest": hashlib.sha256(REG_MESSAGE).hexdigest(),
                     "negative": [{"name": n, "request": rq, "audience": a_, "now": t_, "error": c}
                                  for n, rq, a_, t_, c in REG_NEGATIVE]},
    "wake": {"valid": WAKE_VALID, "invalid": [{"name": n, "body": b, "error": "invalid_argument"} for n, b in WAKE_INVALID]},
}

# =============================================================================== relay error mapping (07 § Client rules)


def _e(code, msg=""):
    return json.dumps({"error": code, **({"message": msg} if msg else {})}, separators=(",", ":"))


RELAY_ERRORS = [
    ("301 redirect", 301, "", {"Location": "https://elsewhere.example/"}, "relay_protocol_error", None, None),
    ("303 redirect with Retry-After", 303, "", {"Retry-After": "5"}, "relay_protocol_error", None, 5),
    ("204 where JSON was expected", 204, "", {}, "relay_protocol_error", None, None),
    ("200 where another status was expected", 200, _e("internal_error"), {}, "relay_protocol_error", "internal_error", None),
    ("100 informational", 100, "", {}, "relay_protocol_error", None, None),
    ("400 invalid_packet", 400, _e("invalid_packet", "bad"), {}, "relay_rejected", "invalid_packet", None),
    ("400 error member not a string", 400, json.dumps({"error": 5}), {}, "relay_rejected", None, None),
    ("400 body not JSON", 400, "Bad Request", {}, "relay_rejected", None, None),
    ("400 with Retry-After (permanent: ignored)", 400, _e("invalid_argument"), {"Retry-After": "5"}, "relay_rejected", "invalid_argument", None),
    ("401 stale_peer_binding", 401, _e("stale_peer_binding"), {}, "relay_rejected", "stale_peer_binding", None),
    ("403 not_registered", 403, _e("not_registered"), {}, "not_registered", "not_registered", None),
    ("403 not_permitted", 403, _e("not_permitted"), {}, "not_permitted", "not_permitted", None),
    ("403 other code", 403, _e("forbidden"), {}, "relay_rejected", "forbidden", None),
    ("404 unknown_peer", 404, _e("unknown_peer"), {}, "unknown_peer", "unknown_peer", None),
    ("404 without body", 404, "", {}, "relay_rejected", None, None),
    ("408 request timeout with Retry-After", 408, "", {"Retry-After": "3"}, "relay_unavailable", None, 3),
    ("409 replay (after the one retry)", 409, _e("replay"), {}, "relay_rejected", "replay", None),
    ("409 stale_descriptor", 409, _e("stale_descriptor"), {}, "relay_rejected", "stale_descriptor", None),
    ("413 payload_too_large", 413, _e("payload_too_large"), {}, "relay_rejected", "payload_too_large", None),
    ("429 rate_limited", 429, _e("rate_limited"), {"Retry-After": "7"}, "relay_unavailable", "rate_limited", 7),
    ("429 recipient_inbox_full", 429, _e("recipient_inbox_full"), {}, "relay_unavailable", "recipient_inbox_full", None),
    ("429 without code", 429, "", {"Retry-After": "2"}, "relay_unavailable", None, 2),
    ("429 recipient_inbox_full with Retry-After (the sender's share)", 429, _e("recipient_inbox_full"), {"Retry-After": "30"}, "relay_unavailable", "recipient_inbox_full", 30),
    ("429 with another code (any 429 is transient)", 429, _e("sender_quota_exceeded"), {"Retry-After": "2"}, "relay_unavailable", "sender_quota_exceeded", 2),
    ("500 internal_error", 500, _e("internal_error"), {}, "relay_unavailable", "internal_error", None),
    ("503 Retry-After seconds", 503, "", {"Retry-After": "120"}, "relay_unavailable", None, 120),
    ("503 Retry-After HTTP-date ignored", 503, "", {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"}, "relay_unavailable", None, None),
    ("503 Retry-After fraction ignored", 503, "", {"Retry-After": "1.5"}, "relay_unavailable", None, None),
    ("599 last 5xx", 599, "", {}, "relay_unavailable", None, None),
    ("600 out of range", 600, _e("internal_error"), {"Retry-After": "2"}, "relay_protocol_error", "internal_error", 2),
]
err_cases = []
for name, status, body, headers, code, relay_code, retry in RELAY_ERRORS:
    e = map_relay_response(status, body.encode(), headers.get("Retry-After"))
    assert (e.code, e.relay_code, e.retry_after_seconds, e.status) == (code, relay_code, retry, status), (name, e.code, e.relay_code, e.retry_after_seconds)
    err_cases.append({"name": name, "status": status, "headers": headers, "body": body, "code": code,
                      "category": "transient" if code in ("relay_unavailable", "relay_protocol_error") else "permanent",
                      "relayCode": relay_code, "retryAfterSeconds": retry})
relay_errors = {
    "rules": ("Map a relay response that is not the call's expected success (status, headers, raw body) to an ACEError: "
              "'code', its 'category', the relay 'error' string ('relayCode', null if absent) and 'retryAfterSeconds' "
              "(only for transient codes, only delay-seconds; null otherwise). The error's status equals 'status'."),
    "cases": err_cases,
}

# =============================================================================== output

with open(os.path.join(SPEC, "protocol-contract.json"), encoding="utf-8") as f:
    contract = json.load(f)
assert contract["profiles"] == {o["id"]: o["digest"] for o in official}

vectors = {
    "version": 12,
    "description": "ACE shared conformance vectors (2026-10-27 revision). Generated by scripts/generate-vectors.py; see each section's rules.",
    "now": NOW,
    "agents": {a.name: {"aceId": a.id, "export": a.export(), **({"supersededSigningSeeds": {"1": b64(bob.extra_signing[1].seed)}} if a is bob else {})}
               for a in AGENTS.values()},
    "encoding": encoding,
    "signing": signing,
    "kel": kel,
    "xwing": {"rules": ("draft-connolly-cfrg-xwing-kem-11 Appendix C vectors 1-3: public key from seed; decapsulate(ciphertext, "
                        "seed) == sharedSecret; implementations with derandomized encapsulation also check "
                        "encapsulate(publicKey, eseed) == (sharedSecret, ciphertext)."),
              "cases": XWING},
    "packet": packet,
    "privateContent": private_content,
    "descriptor": descriptor,
    "delegation": delegation,
    "permit": permit,
    "cardRecords": card_records,
    "erc8004": erc8004,
    "manifests": manifests,
    "coreRules": core_rules,
    "replay": replay,
    "commerce": commerce,
    "pipeline": pipeline,
    "auth": auth,
    "relayErrors": relay_errors,
}
text = json.dumps(vectors, indent=1, ensure_ascii=False) + "\n"
with open(OUT, "w", encoding="utf-8") as f:
    f.write(text)
print(f"wrote {OUT} ({len(text.encode()) // 1024} KiB)")
for k, v in vectors.items():
    if isinstance(v, dict):
        n = sum(len(x) for x in v.values() if isinstance(x, list))
        print(f"  {k}: {n}")

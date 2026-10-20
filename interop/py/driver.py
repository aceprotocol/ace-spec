"""ACE interop driver for the Python SDK (contract: ../README.md). Run with sdk-py on PYTHONPATH."""

from __future__ import annotations

import argparse
import json
import os
import sys

from ace import (
    CORE,
    TEXT,
    ACEError,
    PrekeyVault,
    Profiles,
    SoftwareIdentity,
    check_receipt_body,
    create_packet,
    create_permit,
    create_card_record,
    create_published_agent,
    decode_content,
    decode_packet,
    decrypt_packet,
    encode_content,
    verify_packet,
    verify_card_bundle,
    verify_kel,
    verify_permit,
    verify_published_agent,
)
from ace.limits import MAX_NOTE_BYTES
from ace.packet import check_window
from ace.profiles import CONTACT_TYPE as CONTACT
from ace.profiles import RECEIPT_TYPE as RECEIPT

RELAY = "https://relay.interop.test"
TEXT_TYPE = "ace:text:1"


def read(path: str):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def write(path: str, value) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(value, f, indent=1, ensure_ascii=False)
        f.write("\n")


def load(d: str, now: int):
    identity = SoftwareIdentity.from_export(read(os.path.join(d, "identity.json")), now=now)
    vault = PrekeyVault(os.path.join(d, "prekeys.json"))
    return identity, vault, read(os.path.join(d, "agent.json"))


def gen_identity(d: str, now: int, handle: str | None) -> None:
    os.makedirs(d, exist_ok=True)
    identity = SoftwareIdentity.generate(now=now)
    vault = PrekeyVault(os.path.join(d, "prekeys.json"))
    prekey = vault.current(now)
    agent = create_published_agent(
        identity,
        relays=[RELAY],
        prekey=prekey,
        profiles=Profiles().entries(),
        now=now,
    )
    write(os.path.join(d, "identity.json"), identity.export_private_key())
    write(os.path.join(d, "agent.json"), agent)
    card = create_card_record(identity, home=RELAY, handle=handle, contact="open", listed=False, now=now)
    write(os.path.join(d, "card.json"), card)


def verify_card(path: str, now: int) -> dict:
    try:
        v = verify_card_bundle(read(path), now=now)
    except ACEError as exc:
        return {"error": exc.code}
    out = {"ok": True, "aceId": v.ace_id, "contact": v.contact, "listed": v.listed}
    if v.handle is not None:
        out["handle"] = v.handle
    return out


def content_for(kind: str, a, identity, self_agent, peer: str, now: int) -> dict:
    def core(type_: str, body: dict) -> dict:
        return {"type": type_, "schemaDigest": CORE.messages[type_].digest, "body": body}

    if kind == "text":
        return {"type": TEXT_TYPE, "schemaDigest": TEXT.messages[TEXT_TYPE].digest,
                "body": {"message": a.message or "hello"}}
    if kind == "receipt-delivered":
        return core(RECEIPT, {"messageId": a.ref_message_id, "outcome": "delivered"})
    if kind == "receipt-unknown-prekey":
        return core(RECEIPT, {"messageId": a.ref_message_id, "outcome": "rejected",
                              "code": "unknown_prekey", "prekey": a.ref_prekey})
    if kind == "receipt-rejected":
        return core(RECEIPT, {"messageId": a.ref_message_id, "outcome": "rejected",
                              "code": a.code or "unsupported_schema",
                              "permit": create_permit(identity, peer, now=now)})
    if kind in ("contact-request", "contact-accepted"):
        return core(CONTACT, {"kind": kind.split("-")[1], "profile": TEXT_TYPE,
                              "note": a.note if a.note is not None else "hi", "source": self_agent,
                              "permit": create_permit(identity, peer, now=now)})
    if kind == "contact-rejected":
        return core(CONTACT, {"kind": "rejected", "profile": TEXT_TYPE, "note": "", "source": self_agent})
    raise SystemExit(f"unknown kind {kind}")


def create(d: str, a, now: int) -> None:
    identity, _, self_agent = load(d, now)
    to = verify_published_agent(read(a.to_agent), now=now)
    target = verify_published_agent(read(a.prekey_agent), now=now) if a.prekey_agent else to
    content = content_for(a.kind, a, identity, self_agent, to.ace_id, now)
    plaintext = encode_content(content["type"], content["schemaDigest"], content["body"])
    packet = create_packet(identity, to.ace_id, target.prekey, plaintext, timestamp=now,
                           message_id=a.message_id)
    write(a.out, packet)
    write(a.out + ".content.json", content)


def open_(d: str, a, now: int) -> dict:
    identity, vault, _ = load(d, now)
    me = identity.get_ace_id()
    p = decode_packet(read(a.packet))
    if p.to_id != me:
        raise ACEError("wrong_recipient", "not addressed to this identity")
    # The sender's KEL stands for the receiver's pin (06 step 3); its descriptor is not needed here.
    sender = verify_kel(read(a.from_agent)["kel"], now)
    if sender.ace_id != p.from_id:
        raise ACEError("invalid_signature", "packet is not from the given agent")
    # No public open_packet: the lowest public steps that verify, check the window and decrypt.
    verify_packet(p, sender, now)
    check_window(p, now)
    c = decode_content(decrypt_packet(p, vault, now))
    Profiles().validate(c["type"], c["schemaDigest"], c["body"])
    b = c["body"]
    if c["type"] == CONTACT:
        src = verify_published_agent(b["source"], now=now)
        if src.ace_id != p.from_id:
            raise ACEError("invalid_authorization", "contact source is not the sender")
        verify_packet(p, src.state, now)
        if len(b["note"].encode("utf-8")) > MAX_NOTE_BYTES:
            raise ACEError("invalid_body", "note too long")
        if (b["kind"] == "rejected") == ("permit" in b):
            raise ACEError("invalid_authorization", "permit presence")
        if "permit" in b:
            verify_permit(b["permit"], src.state, me, now=now)
    elif c["type"] == RECEIPT:
        check_receipt_body(b)
        if "permit" in b:
            verify_permit(b["permit"], sender, me, now=now)
    out = {"ok": True, "from": p.from_id, "messageId": p.message_id, "type": c["type"],
           "schemaDigest": c["schemaDigest"], "body": b}
    if "threadId" in c:
        out["threadId"] = c["threadId"]
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["gen-identity", "create-packet", "open-packet", "verify-card"])
    ap.add_argument("dir")
    ap.add_argument("--now", type=int, default=os.environ.get("ACE_INTEROP_NOW"))
    for o in ("to-agent", "prekey-agent", "kind", "out", "message", "message-id", "ref-message-id",
              "ref-prekey", "code", "note", "from-agent", "packet", "handle"):
        ap.add_argument("--" + o)
    a = ap.parse_args()
    if a.now is None:
        raise SystemExit("--now is required")
    now = int(a.now)
    if a.command == "gen-identity":
        gen_identity(a.dir, now, a.handle)
    elif a.command == "verify-card":
        print(json.dumps(verify_card(a.dir, now)))
    elif a.command == "create-packet":
        create(a.dir, a, now)
    else:
        try:
            out = open_(a.dir, a, now)
        except ACEError as exc:
            out = {"error": exc.code}
        write(a.out, out)


if __name__ == "__main__":
    try:
        main()
    except ACEError as exc:
        print(f"driver error: {exc}", file=sys.stderr)
        sys.exit(2)

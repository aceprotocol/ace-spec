"""ACE cross-SDK interop harness — Python side.

Usage: python interop.py <phase> <workdir>
Phases: gen | verify | send1 | recv1 | recv2 | persist | load | pverify | psend | precv | pdecide | pload.
See ../README.md.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import time
from typing import Any, Callable

import ace
from ace.principal import load_request_record, principal_payload
from ace.store import write_record


def dump_record(obj: dict) -> bytes:
    """The bytes the SDK persists for ``obj`` (Inbox writes replay.json via ``write_record``)."""
    store = ace.MemoryStore()
    write_record(store, "record.json", obj)
    return store.read("record.json")

LANG = "py"
LANGS = ["ts", "py", "swift"]
SCHEMES = ["ed25519", "secp256k1"]
phase, W = sys.argv[1], sys.argv[2]


def P(*p: str) -> str:
    return os.path.join(W, *p)


def rd(p: str) -> Any:
    with open(P(p), encoding="utf-8") as f:
        return json.load(f)


def wr(p: str, v: Any) -> None:
    os.makedirs(os.path.dirname(P(p)), exist_ok=True)
    with open(P(p), "w", encoding="utf-8") as f:
        json.dump(v, f, indent=1, ensure_ascii=False)


def now() -> int:
    return int(time.time())


b64 = ace.to_base64


def fail(e: BaseException) -> dict:
    return {"ok": False, "code": getattr(e, "code", "exception"), "message": f"{type(e).__name__}: {e}"}


def attempt(fn: Callable[[], Any]) -> dict:
    try:
        r = fn()
        return {"ok": True, **(r or {})}
    except Exception as e:  # noqa: BLE001
        return fail(e)


AUTH = {
    "listen": ace.RelayAuthRequest.listen("-"),
    "inbox": ace.RelayAuthRequest.inbox("1700000000000-0", 50),
    "unregister": ace.RelayAuthRequest.unregister(),
    "intent": ace.RelayAuthRequest.intent("Translate EN→FR", ["nlp", "fr"],
                                          {ace.COMMERCE_EXT: {"maxPrice": "10", "currency": "USDC"}}, 3600),
}


def profile(lang: str) -> dict:
    return {
        "name": f"Agent {lang} é", "description": "interop / matrix", "tags": ["interop", "ace"],
        "capabilities": ["translate"], "endpoint": f"https://{lang}.example/ace",
        "ext": {ace.COMMERCE_EXT: {"pricing": {"currency": "USDC", "maxAmount": "10"}, "chains": ["eip155:8453"]},
                "urn:example:v1": {"z": [1, {"y": None}], "é": "/ü", "a": True}},
    }


def text_body(s: str, r: str, sch: str) -> dict:
    return {"message": f'hello {s}→{r} ({sch}) héllo 世界 / "q" \\ ✓'}


RFQ = {"need": "Translate 500 words EN→FR", "maxPrice": "10.50", "currency": "USDC", "ttl": 3600}
OFFER = {"price": "9.75", "currency": "USDC", "terms": "delivery in 24h / net", "ttl": 600}

# --- principal fixtures (same values in every language; 09-principal) ---------------------
# One shared CAIP-10 account. The controller signer (owner key) of scheme s is a v4
# test-vectors agent (ed25519: alice, secp256k1: bob), so every language signs with the same
# key and every Inbox trusts it as `selfSigner`. `<lang>-<s>` is a delegate (["delegate"]),
# `<lang>-<s>-rx` a controller (["controller"]).
VECTORS_PATH = os.environ.get("ACE_VECTORS") or os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "..", "test-vectors.json")
with open(VECTORS_PATH, encoding="utf-8") as _f:
    VECTORS = json.load(_f)
ACCOUNT = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:InteropOwner1111111111111111111111111111111"
OWNER_AGENT = {"ed25519": "alice", "secp256k1": "bob"}
SCOPE = "interop ✓"
# Deterministic record: same signer, delegate subject (vectors principalRules.senders.agent),
# issuedAt and expiresAt in every language, so record, payload and signData must be byte-equal.
FIXED_SUBJECT = VECTORS["vectors"]["principalRules"]["senders"]["agent"]["signingPublicKey"]
FIXED_ISSUED_AT = VECTORS["vectors"]["principal"]["now"]
REQ = {"action": "x402.pay", "summary": "Pay 1 USDC ✓", "amount": "1", "currency": "USDC",
       "details": {"payTo": "x", "network": "solana"}, "ttl": 600}
REP = {"action": "copy.run", "summary": "copied 2 trades", "outcome": "ok", "proof": {"txHash": "0x01"}}


def owner(s: str) -> ace.SoftwareIdentity:
    a = VECTORS["agents"][OWNER_AGENT[s]]
    return ace.SoftwareIdentity.from_export({k: a[k] for k in ("scheme", "signingPrivateKey", "encryptionPrivateKey")})


def owner_key(s: str) -> dict:
    return {"scheme": s, "publicKey": VECTORS["agents"][OWNER_AGENT[s]]["signingPublicKey"]}


def inbox_principal(s: str) -> dict:
    """``Inbox.open`` principal: the shared account, the owner key of this scheme as
    ``selfSigner`` and the other scheme's owner key as a trusted signer."""
    return {"account": ACCOUNT, "selfSigner": owner_key(s),
            "trustedSigners": [owner_key(x) for x in SCHEMES if x != s]}


def decision_bodies(rid: str, conv: str) -> dict:
    return {
        "decisionBody": {"requestId": rid, "outcome": "approve", "result": {"payload": "signed ✓"}},
        "decision2Body": {"requestId": rid, "outcome": "deny", "reason": "changed my mind ✓"},
        "reportBody": {"action": "x402.pay", "summary": "paid 1 USDC ✓", "outcome": "ok", "requestId": rid,
                       "ref": {"conversationId": conv, "messageId": rid}},
    }


def rx(s: str) -> str:
    """``<lang>-<scheme>`` sends; a second identity ``<lang>-<scheme>-rx`` receives."""
    return f"{s}-rx"


def identity(lang: str, s: str) -> ace.SoftwareIdentity:
    return ace.SoftwareIdentity.from_export(rd(f"ids/{lang}-{s}.json")["export"])


def peer_of(lang: str, s: str) -> ace.VerifiedPeer:
    return ace.verify_registration_file(rd(f"ids/{lang}-{s}.json")["registrationFile"])


def principal_peer(lang: str, s: str) -> ace.VerifiedPeer:
    return ace.verify_registration_file(rd(f"ids/{lang}-{s}.json")["registrationFilePrincipal"])


def summary(p: ace.ParsedMessage) -> dict:
    return {
        "messageId": p.message_id, "from": p.from_id, "to": p.to_id, "conversationId": p.conversation_id,
        "type": p.type, "schemaDigest": p.schema_digest, "threadId": p.thread_id, "timestamp": p.timestamp, "body": p.body,
    }


def peer_summary(p: ace.VerifiedPeer) -> dict:
    return {
        "aceId": p.ace_id, "scheme": p.scheme, "signingPublicKey": b64(p.signing_public_key),
        "encryptionPublicKey": b64(p.encryption_public_key), "address": p.address, "source": p.source,
    }


def parse_fresh(env: dict, me: ace.SoftwareIdentity, peer: ace.VerifiedPeer) -> ace.ParsedMessage:
    return ace.parse_message(ace.decode_envelope(env), me, peer,
                             threads=ace.ThreadStateMachine(me.get_ace_id()), replay=ace.ReplayDetector())


def gen() -> None:
    for s in SCHEMES + [rx(x) for x in SCHEMES]:
        idn = ace.SoftwareIdentity.generate(s.replace("-rx", ""))  # type: ignore[arg-type]
        ts = now()
        auth = {k: {"headers": ace.create_auth_headers(idn, req, ts)} for k, req in AUTH.items()}
        base = s.replace("-rx", "")
        principal = ace.create_principal_record(
            ace.PrincipalSigner.from_identity(owner(base)), subject_signing_public_key=idn.get_signing_public_key(),
            account=ACCOUNT, roles=["controller"] if s.endswith("-rx") else ["delegate"],
            expires_at=ts + 3600, issued_at=ts)
        wr(f"ids/{LANG}-{s}.json", {
            "lang": LANG, "scheme": s.replace("-rx", ""), "export": idn.export_private_key(), "aceId": idn.get_ace_id(),
            "address": idn.get_address(), "signingPublicKey": b64(idn.get_signing_public_key()),
            "encryptionPublicKey": b64(idn.get_encryption_public_key()),
            "registrationFile": ace.create_registration_file(idn, name=f"Agent {LANG} {s}", endpoint=f"https://{LANG}.example/ace").to_dict(),
            "registrationRequest": ace.create_registration_request(idn, profile(LANG), ts),
            "auth": auth,
            "principal": principal.to_dict(),
            "registrationFilePrincipal": ace.create_registration_file(
                idn, name=f"Agent {LANG} {s}", endpoint=f"https://{LANG}.example/ace", principal=principal).to_dict(),
            "registrationRequestPrincipal": ace.create_registration_request(
                idn, {**profile(LANG), "principal": principal.to_dict()}, ts),
        })
    for s in SCHEMES:
        subject = ace.from_base64(FIXED_SUBJECT)
        rec = ace.create_principal_record(
            ace.PrincipalSigner.from_identity(owner(s)), subject_signing_public_key=subject, account=ACCOUNT,
            roles=["delegate"], scope=SCOPE, expires_at=FIXED_ISSUED_AT + 3600, issued_at=FIXED_ISSUED_AT)
        wr(f"fixed/{LANG}-{s}.json", {"record": rec.to_dict(), "payloadHex": principal_payload(rec, subject).hex(),
                                      "signDataHex": ace.principal_sign_data(rec, subject).hex()})


def verify() -> None:
    out: dict = {}
    for src in LANGS:
        for s in SCHEMES:
            d = rd(f"ids/{src}-{s}.json")
            r: dict = {}

            def imp() -> dict:
                idn = ace.SoftwareIdentity.from_export(d["export"])
                reg = ace.create_registration_file(idn, name=d["registrationFile"]["name"], endpoint=d["registrationFile"]["endpoint"], timestamp=d["registrationFile"]["registeredAt"])
                return {
                    "aceId": idn.get_ace_id(), "address": idn.get_address(), "scheme": idn.get_signing_scheme(),
                    "signingPublicKey": b64(idn.get_signing_public_key()),
                    "encryptionPublicKey": b64(idn.get_encryption_public_key()),
                    "reexport": idn.export_private_key(), "registrationFile": reg.to_dict(),
                }
            r["import"] = attempt(imp)
            holder: dict = {}

            def regfile() -> dict:
                holder["peer"] = ace.verify_registration_file(d["registrationFile"])
                return peer_summary(holder["peer"])
            r["regFile"] = attempt(regfile)

            def regreq() -> dict:
                v = ace.verify_registration_request(d["registrationRequest"])
                return {"requestDigest": v.request_digest, "peer": peer_summary(v.peer)}
            r["regRequest"] = attempt(regreq)
            spk = holder["peer"].signing_public_key if "peer" in holder else ace.from_base64(d["signingPublicKey"])

            def check(headers: dict, req: ace.RelayAuthRequest) -> Callable[[], None]:
                def go() -> None:
                    ace.verify_auth_headers(ace.parse_auth_headers(headers), req, ace_id=d["aceId"],
                                            scheme=d["scheme"], signing_public_key=spk)
                return go
            r["auth"] = {k: attempt(check(d["auth"][k]["headers"], req)) for k, req in AUTH.items()}
            r["authWrongRequest"] = attempt(check(d["auth"]["listen"]["headers"], AUTH["inbox"]))
            out[f"{src}-{s}"] = r
    wr(f"out/{LANG}/verify.json", out)


def send1() -> None:
    for R in LANGS:
        for s in SCHEMES:
            key = f"{LANG}-{R}-{s}"
            try:
                me = identity(LANG, s)
                peer = peer_of(R, rx(s))
                threads = ace.ThreadStateMachine(me.get_ace_id())
                thread_id = f"deal/{key}/✓"
                tb = text_body(LANG, R, s)
                text = ace.create_message(me, peer, "text", tb, threads)
                custom = ace.create_message(me, peer, "urn:example:task:1", {"task": "你好"}, schema_digest="ab" * 32, thread_id="private")
                rfq = ace.create_message(me, peer, "rfq", RFQ, threads, thread_id=thread_id)
                wr(f"msgs/m1/{key}.json", {"threadId": thread_id, "textBody": tb, "rfqBody": RFQ,
                                           "text": text.to_dict(), "rfq": rfq.to_dict(), "custom": custom.to_dict()})
                wr(f"priv/{LANG}/threads-{R}-{s}.json", [x.to_dict() for x in threads.export_state()])
            except Exception as e:  # noqa: BLE001
                wr(f"msgs/m1/{key}.json", {"error": fail(e)})


def recv1() -> None:
    out: dict = {}
    for S in LANGS:
        for s in SCHEMES:
            key = f"{S}-{LANG}-{s}"
            r: dict = {}
            out[key] = r
            try:
                m = rd(f"msgs/m1/{key}.json")
                if "error" in m:
                    raise RuntimeError(f"sender failed: {m['error']}")
                t = rd(f"msgs/tampered/{key}.json")
                me = identity(LANG, rx(s))
                peer = peer_of(S, s)
                r["tamperedText"] = attempt(lambda: summary(parse_fresh(t["text"], me, peer)))
                r["tamperedRfq"] = attempt(lambda: summary(parse_fresh(t["rfq"], me, peer)))
                threads = ace.ThreadStateMachine(me.get_ace_id())
                replay = ace.ReplayDetector()

                def parse(env: dict) -> dict:
                    return summary(ace.parse_message(ace.decode_envelope(env), me, peer, threads=threads, replay=replay))
                r["custom"] = attempt(lambda: parse(m["custom"]))
                r["text"] = attempt(lambda: parse(m["text"]))
                r["rfq"] = attempt(lambda: parse(m["rfq"]))
                r["replayAgain"] = attempt(lambda: parse(m["text"]))
                conv = m["rfq"]["conversationId"]
                r["stateAfterRfq"] = threads.get_state(conv, m["threadId"])

                def reply() -> None:
                    offer = ace.create_message(me, peer, "offer", OFFER, threads, thread_id=m["threadId"])
                    wr(f"msgs/m2/{LANG}-{S}-{s}.json", {"threadId": m["threadId"], "offerBody": OFFER, "offer": offer.to_dict()})
                r["reply"] = attempt(reply)
                r["stateAfterOffer"] = threads.get_state(conv, m["threadId"])
            except Exception as e:  # noqa: BLE001
                r["error"] = fail(e)
    wr(f"out/{LANG}/recv1.json", out)


def recv2() -> None:
    out: dict = {}
    for R in LANGS:
        for s in SCHEMES:
            key = f"{R}-{LANG}-{s}"
            r: dict = {}
            out[key] = r
            try:
                if not os.path.exists(P(f"msgs/m2/{key}.json")):
                    raise RuntimeError("no offer from receiver")
                m = rd(f"msgs/m2/{key}.json")
                me = identity(LANG, s)
                snaps = [ace.ThreadSnapshot.from_dict(x) for x in rd(f"priv/{LANG}/threads-{R}-{s}.json")]
                threads = ace.ThreadStateMachine.from_state(snaps, me.get_ace_id())
                replay = ace.ReplayDetector()
                r["offer"] = attempt(lambda: summary(ace.parse_message(
                    ace.decode_envelope(m["offer"]), me, peer_of(R, rx(s)), threads=threads, replay=replay)))
                conv = m["offer"]["conversationId"]
                r["state"] = threads.get_state(conv, m["threadId"])
                snap = threads.get_snapshot(conv, m["threadId"])
                r["snapshot"] = snap.to_dict() if snap else None
            except Exception as e:  # noqa: BLE001
                r["error"] = fail(e)
    wr(f"out/{LANG}/recv2.json", out)


def wire(envelope: dict) -> bytes:
    """The wire bytes of an envelope (``Inbox.receive`` takes raw message bytes)."""
    return json.dumps(envelope, ensure_ascii=False).encode("utf-8")


def outcome(o: ace.ReceiveOutcome) -> dict:
    if o.kind == "delivered":
        return {"kind": o.kind, "messageId": o.message.message_id}  # type: ignore[union-attr]
    if o.kind == "duplicate":
        return {"kind": o.kind, "messageId": o.message_id}
    return {"kind": o.kind, "code": getattr(o.error, "code", None), "message": str(o.error)}


def persist() -> None:
    out: dict = {}
    for s in SCHEMES:
        r: dict = {"receives": {}}
        out[s] = r
        try:
            me = identity(LANG, rx(s))
            store = ace.FileStore(P(f"stores/{LANG}-{s}"))
            peers = ace.PeerStore(store)
            for S in LANGS:
                peers.pin_registration_file(rd(f"ids/{S}-{s}.json")["registrationFile"])
            handed = []
            inbox = ace.Inbox.open(me, store, peers, lambda m: handed.append(m.message_id), commerce=True)
            try:
                for S in LANGS:
                    m = rd(f"msgs/m1/{S}-{LANG}-{s}.json")
                    if "error" in m:
                        raise RuntimeError(f"sender {S} failed: {m['error']}")
                    r["receives"][S] = {
                        "text": outcome(inbox.receive(wire(m["text"]))),
                        "rfq": outcome(inbox.receive(wire(m["rfq"]))),
                        "textAgain": outcome(inbox.receive(wire(m["text"]))),
                    }
            finally:
                inbox.close()
            r["handed"] = len(handed)
        except Exception as e:  # noqa: BLE001
            r["error"] = fail(e)
    wr(f"out/{LANG}/persist.json", out)


SNAP_KEYS = ("conversationId", "threadId", "localAceId", "peerAceId", "state", "history")


def load() -> None:
    out: dict = {}
    for R in LANGS:
        for s in SCHEMES:
            key = f"{R}-{s}"
            r: dict = {}
            out[key] = r
            try:
                src, dst = P(f"stores/{key}"), P(f"tmp/{LANG}/{key}")
                shutil.rmtree(dst, ignore_errors=True)
                shutil.copytree(src, dst)
                with open(os.path.join(src, "replay.json"), "rb") as f:
                    raw = f.read()

                def replay() -> dict:
                    st = json.loads(raw.decode("utf-8"))
                    b = dump_record(ace.ReplayDetector.from_state(st).export_state())
                    return {"identical": b == raw, "reexport": b.decode("utf-8"), "entries": len(st["entries"])}
                r["replay"] = attempt(replay)
                r["threads"] = []
                tdir = os.path.join(src, "threads")
                for fn in sorted(x for x in (os.listdir(tdir) if os.path.isdir(tdir) else []) if x.endswith(".json")):
                    def thread(fn: str = fn) -> dict:
                        with open(os.path.join(tdir, fn), encoding="utf-8") as f:
                            rec = json.load(f)
                        snap = {k: rec[k] for k in SNAP_KEYS}
                        m = ace.ThreadStateMachine.from_state([ace.ThreadSnapshot.from_dict(snap)], rec["localAceId"])
                        return {"file": fn, "original": snap, "exported": m.export_state()[0].to_dict(),
                                "state": m.get_state(rec["conversationId"], rec["threadId"])}
                    r["threads"].append(attempt(thread))
                me = identity(R, rx(s))
                store = ace.FileStore(dst)

                def thread_store() -> dict:
                    lst = ace.ThreadStore(store, me.get_ace_id()).list()
                    return {"count": len(lst), "states": sorted(x.state for x in lst)}
                r["threadStore"] = attempt(thread_store)
                peers = ace.PeerStore(store)

                def get_peers() -> dict:
                    got = {}
                    for S in LANGS:
                        p = peers.get(rd(f"ids/{S}-{s}.json")["aceId"])
                        got[S] = peer_summary(p) if p else None
                    return {"peers": got}
                r["peers"] = attempt(get_peers)

                def reopen() -> dict:
                    handed: list = []
                    inbox = ace.Inbox.open(me, store, peers, lambda m: handed.append(m.message_id), commerce=True)
                    try:
                        m = rd(f"msgs/m1/{LANGS[0]}-{R}-{s}.json")
                        dup = outcome(inbox.receive(wire(m["rfq"])))
                        return {"handedOnOpen": len(handed), "duplicate": dup}
                    finally:
                        inbox.close()
                r["inboxReopen"] = attempt(reopen)
            except Exception as e:  # noqa: BLE001
                r["error"] = fail(e)
    wr(f"out/{LANG}/load.json", out)


# --- 6, 7: principal ---------------------------------------------------------------------


def ledger(rec: dict | None) -> dict | None:
    """A ``requests/`` record as loaded (without the store ``version``)."""
    return None if rec is None else {k: v for k, v in rec.items() if k != "version"}


def pverify() -> None:
    out: dict = {}
    for src in LANGS:
        for s in SCHEMES:
            r: dict = {}
            out[f"{src}-{s}"] = r
            for role, suffix, other in (("delegate", "", "-rx"), ("controller", "-rx", "")):
                d = rd(f"ids/{src}-{s}{suffix}.json")
                spk = ace.from_base64(d["signingPublicKey"])

                def record() -> dict:
                    p = ace.validate_principal_record(d["principal"], spk, now())
                    return {"record": p.to_dict(), "payloadHex": principal_payload(p, spk).hex(),
                            "signDataHex": ace.principal_sign_data(p, spk).hex()}

                def reg_file() -> dict:
                    p = ace.verify_registration_file(d["registrationFilePrincipal"]).principal
                    return {"principal": p.to_dict() if p else None}

                def reg_request() -> dict:
                    v = ace.verify_registration_request(d["registrationRequestPrincipal"])
                    return {"requestDigest": v.request_digest, "aceId": v.peer.ace_id}
                other_key = ace.from_base64(rd(f"ids/{src}-{s}{other}.json")["signingPublicKey"])
                r[role] = {
                    "record": attempt(record), "regFile": attempt(reg_file), "regRequest": attempt(reg_request),
                    "wrongSubject": attempt(lambda: {"x": ace.validate_principal_record(d["principal"], other_key, now()).account}),
                }
            f = rd(f"fixed/{src}-{s}.json")

            def fixed() -> dict:
                subject = ace.from_base64(FIXED_SUBJECT)
                p = ace.validate_principal_record(f["record"], subject, FIXED_ISSUED_AT)
                return {"payloadHex": principal_payload(p, subject).hex(),
                        "signDataHex": ace.principal_sign_data(p, subject).hex()}
            r["fixed"] = attempt(fixed)
    wr(f"out/{LANG}/pverify.json", out)


def psend() -> None:
    """Delegate ``<LANG>-<s>`` sends a ``request`` and a ``report`` to every controller through
    its Outbox (FileStore ``pstores/<LANG>-<s>``); delivery writes the ``requests/`` record."""
    out: dict = {}
    for s in SCHEMES:
        try:
            me = identity(LANG, s)
            store = ace.FileStore(P(f"pstores/{LANG}-{s}"))
            outbox = ace.Outbox.open(me, store)
        except Exception as e:  # noqa: BLE001
            for R in LANGS:
                wr(f"msgs/p1/{LANG}-{R}-{s}.json", {"error": fail(e)})
            continue
        for R in LANGS:
            key = f"{LANG}-{R}-{s}"
            try:
                peer = principal_peer(R, rx(s))
                req = outbox.deliver(outbox.stage(peer, "request", REQ).request_id, lambda m: m.to_dict())
                rep = outbox.deliver(outbox.stage(peer, "report", REP).request_id, lambda m: m.to_dict())
                out[key] = {"ledger": ledger(load_request_record(store, req["conversationId"], req["messageId"]))}
                wr(f"msgs/p1/{key}.json", {"requestBody": REQ, "reportBody": REP, "request": req, "report": rep})
            except Exception as e:  # noqa: BLE001
                wr(f"msgs/p1/{key}.json", {"error": fail(e)})
    wr(f"out/{LANG}/psend.json", out)


def precv() -> None:
    """Controller ``<LANG>-<s>-rx`` receives every delegate's request and report through an
    Inbox opened with the shared principal, then answers with two different decisions and a
    report (``msgs/p2/<LANG>-<S>-<s>.json``)."""
    out: dict = {}
    for s in SCHEMES:
        keys = [f"{S}-{LANG}-{s}" for S in LANGS]
        try:
            me = identity(LANG, rx(s))
            store = ace.FileStore(P(f"pstores/{LANG}-{rx(s)}"))
            peers = ace.PeerStore(store)
            for S in LANGS:
                peers.pin_registration_file(rd(f"ids/{S}-{s}.json")["registrationFilePrincipal"])
            handed: dict = {}
            inbox = ace.Inbox.open(me, store, peers, lambda m: handed.__setitem__(m.message_id, summary(m)),
                                   principal=inbox_principal(s))
        except Exception as e:  # noqa: BLE001
            for k in keys:
                out[k] = {"error": fail(e)}
            continue
        try:
            for S in LANGS:
                key = f"{S}-{LANG}-{s}"
                r: dict = {}
                out[key] = r
                try:
                    m = rd(f"msgs/p1/{key}.json")
                    if "error" in m:
                        raise RuntimeError(f"sender failed: {m['error']}")
                    peer = principal_peer(S, s)
                    for k in ("request", "report"):
                        r[k] = outcome(inbox.receive(wire(m[k])))
                        r[f"{k}Parsed"] = handed.get(m[k]["messageId"])
                    r["noContext"] = attempt(lambda: summary(parse_fresh(m["report"], me, peer)))
                    rid, conv = m["request"]["messageId"], m["request"]["conversationId"]
                    bodies = decision_bodies(rid, conv)
                    msgs: dict = dict(bodies)
                    for k, typ in (("decision", "decision"), ("decision2", "decision"), ("report", "report")):
                        msgs[k] = ace.create_message(me, peer, typ, bodies[f"{k}Body"], ace.ThreadStateMachine(me.get_ace_id())).to_dict()
                    wr(f"msgs/p2/{LANG}-{S}-{s}.json", msgs)
                except Exception as e:  # noqa: BLE001
                    r["error"] = fail(e)
        finally:
            inbox.close()
    wr(f"out/{LANG}/precv.json", out)


def pdecide() -> None:
    """Delegate ``<LANG>-<s>`` receives each controller's decisions and report through an Inbox
    on the store its Outbox wrote: the first decision fills the request, a replay is a
    duplicate, the second different decision is ``bad_reference``."""
    out: dict = {}
    for s in SCHEMES:
        keys = [f"{R}-{LANG}-{s}" for R in LANGS]
        try:
            me = identity(LANG, s)
            store = ace.FileStore(P(f"pstores/{LANG}-{s}"))
            peers = ace.PeerStore(store)
            for R in LANGS:
                peers.pin_registration_file(rd(f"ids/{R}-{rx(s)}.json")["registrationFilePrincipal"])
            handed: dict = {}
            inbox = ace.Inbox.open(me, store, peers, lambda m: handed.__setitem__(m.message_id, summary(m)),
                                   principal=inbox_principal(s))
        except Exception as e:  # noqa: BLE001
            for k in keys:
                out[k] = {"error": fail(e)}
            continue
        try:
            for R in LANGS:
                key = f"{R}-{LANG}-{s}"
                r: dict = {}
                out[key] = r
                try:
                    m = rd(f"msgs/p2/{key}.json")
                    req = rd(f"msgs/p1/{LANG}-{R}-{s}.json")["request"]
                    for k, env in (("decision", "decision"), ("decisionAgain", "decision"),
                                   ("decision2", "decision2"), ("report", "report")):
                        r[k] = outcome(inbox.receive(wire(m[env])))
                    r["decisionParsed"] = handed.get(m["decision"]["messageId"])
                    r["reportParsed"] = handed.get(m["report"]["messageId"])
                    r["ledger"] = attempt(lambda: {"record": ledger(load_request_record(store, req["conversationId"], req["messageId"]))})
                except Exception as e:  # noqa: BLE001
                    r["error"] = fail(e)
        finally:
            inbox.close()
    wr(f"out/{LANG}/pdecide.json", out)


def pload() -> None:
    """Every delegate's ``requests/`` record of its request to this language, loaded here."""
    out: dict = {}
    for S in LANGS:
        for s in SCHEMES:
            key = f"{S}-{LANG}-{s}"
            try:
                req = rd(f"msgs/p1/{key}.json")["request"]
                store = ace.FileStore(P(f"pstores/{S}-{s}"))
                out[key] = attempt(lambda: {"record": ledger(load_request_record(store, req["conversationId"], req["messageId"]))})
            except Exception as e:  # noqa: BLE001
                out[key] = fail(e)
    wr(f"out/{LANG}/pload.json", out)


PHASES = {"gen": gen, "verify": verify, "send1": send1, "recv1": recv1, "recv2": recv2, "persist": persist, "load": load,
          "pverify": pverify, "psend": psend, "precv": precv, "pdecide": pdecide, "pload": pload}
PHASES[phase]()

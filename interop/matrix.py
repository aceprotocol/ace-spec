#!/usr/bin/env python3
"""Run the ACE interop matrix across driver executables (contract: README.md).

Every directed pair (sender, receiver) of the selected SDKs, same-SDK pairs included, runs the
packet cases below, and every SDK verifies every SDK's card records (valid and tampered); exits
non-zero on any mismatch. Standard library only.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import shutil
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HERE = Path(__file__).resolve().parent
NOW = int(os.environ.get("ACE_INTEROP_NOW", "1760140800"))
TIMESTAMP_FUTURE = 300
OFFLINE_WINDOW = 604800
SDK_PY = Path(os.environ.get("SDK_PY", HERE.parents[1] / "sdk-py"))


def drivers() -> dict[str, list[str]]:
    python = os.environ.get("PYTHON", str(SDK_PY / ".venv/bin/python"))
    out = {
        "ts": [os.environ.get("NODE", "node"), "--disable-warning=ExperimentalWarning", str(HERE / "ts/driver.ts")],
        "py": [python, "-X", "utf8", str(HERE / "py/driver.py")],
    }
    if os.environ.get("ACE_INTEROP_SWIFT"):
        out["swift"] = [os.environ["ACE_INTEROP_SWIFT"]]
    langs = os.environ.get("INTEROP_LANGS", ",".join(out)).split(",")
    unknown = [lang for lang in langs if lang not in out]
    if unknown:
        sys.exit(f"INTEROP_LANGS: unavailable driver(s) {unknown} (swift needs ACE_INTEROP_SWIFT)")
    return {lang: out[lang] for lang in langs}


DRIVERS = drivers()
WORK = Path(os.environ.get("WORK") or (Path(os.environ.get("TMPDIR", "/tmp")) / "ace-interop"))
ENV = {**os.environ, "PYTHONPATH": str(SDK_PY)}


def run(lang: str, *args: str, now: int = NOW) -> str:
    cmd = [*DRIVERS[lang], *args, "--now", str(now)]
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(f"{lang} {' '.join(args[:2])} failed ({r.returncode}):\n{r.stderr[-3000:]}")
    return r.stdout


def read(p: Path):
    return json.loads(p.read_text())


def write(p: Path, v) -> None:
    p.write_text(json.dumps(v))


def flip_b64(text: str, index: int) -> str:
    raw = bytearray(base64.b64decode(text))
    raw[index] ^= 0x01
    return base64.b64encode(bytes(raw)).decode()


THIRD = "ace:sha256:" + "1" * 64


def prekey_id(public_key_b64: str) -> str:
    return hashlib.sha256(base64.b64decode(public_key_b64)).hexdigest()


def run_pair(s: str, r: str) -> dict[str, str]:
    """Every case for one directed pair (sender SDK ``s``, receiver SDK ``r``): case -> "ok" or a failure."""
    pair = WORK / f"{s}-to-{r}"
    sdir, rdir = pair / "sender", pair / "receiver"
    shutil.copytree(WORK / s / "a", sdir)
    shutil.copytree(WORK / r / "b", rdir)
    s_agent, r_agent = str(sdir / "agent.json"), str(rdir / "agent.json")
    sender_id = read(sdir / "agent.json")["descriptor"]["aceId"]
    other = WORK / r / "c" / "agent.json"
    cells: dict[str, str] = {}
    # The forward direction (s's identity to r's); `back` swaps roles for packets r sends back to s.
    fwd = (s, sdir, r, rdir, r_agent, s_agent)
    back = (r, rdir, s, sdir, s_agent, r_agent)

    def create(name: str, kind: str, *extra: str, now: int = NOW, roles=fwd) -> Path:
        maker, mdir, _, _, to_agent, _ = roles
        out = pair / f"{name}.json"
        run(maker, "create-packet", str(mdir), "--to-agent", to_agent, "--kind", kind, "--out", str(out), *extra, now=now)
        return out

    def open_(name: str, packet: Path, from_agent: str | None = None, now: int = NOW, roles=fwd) -> dict:
        _, _, opener, odir, _, own_agent = roles
        out = pair / f"{name}.result.json"
        run(opener, "open-packet", str(odir), "--from-agent", from_agent or own_agent, "--packet", str(packet),
            "--out", str(out), now=now)
        return read(out)

    def expect_ok(name: str, packet: Path, **kw) -> dict:
        got = open_(name, packet, **kw)
        content, p = read(Path(str(packet) + ".content.json")), read(packet)
        # The opener reports the ID of the peer prekey the packet carried (04 § Peer prekeys).
        ok = (got.get("ok") is True and got["from"] == p["from"] and got["messageId"] == p["messageId"]
              and got["type"] == content["type"] and got["schemaDigest"] == content["schemaDigest"]
              and got["body"] == content["body"] and got.get("threadId") == content.get("threadId")
              and got.get("prekeyId") == prekey_id(content["prekey"]))
        cells[name] = "ok" if ok else f"FAIL {json.dumps(got)[:200]}"
        return got

    def expect_error(name: str, packet: Path, code: str, **kw) -> None:
        got = open_(name, packet, **kw)
        cells[name] = "ok" if got == {"error": code} else f"FAIL want {code}, got {json.dumps(got)[:200]}"

    try:
        text = create("text", "text", "--message", "héllo / ☃ \U0001F600")
        if read(text)["from"] != sender_id:
            cells["driver"] = "FAIL packet from is not the sender identity"
        expect_ok("text", text)
        # Peer prekeys: the receiver answers on the key the text packet offered it, and only its issuer opens that.
        offered = read(Path(str(text) + ".content.json"))["prekey"]
        reply = create("peer-prekey-reply", "text", "--message", "reply on the peer prekey", "--to-prekey", offered, roles=back)
        if read(reply)["encryption"]["prekey"] != prekey_id(offered):
            cells["peer-prekey-reply"] = "FAIL reply is not encrypted to the offered prekey"
        else:
            expect_ok("peer-prekey-reply", reply, roles=back)
        # A bystander (r's identity "c") encrypting to that key: it was offered to another peer, so unknown_prekey.
        third = pair / "third"
        shutil.copytree(WORK / r / "c", third)
        expect_error("peer-prekey-other-sender",
                     create("peer-prekey-other-sender", "text", "--to-prekey", offered, roles=(r, third, s, sdir, s_agent, None)),
                     "unknown_prekey", roles=back, from_agent=str(third / "agent.json"))
        ref = read(text)["messageId"]
        expect_ok("receipt-delivered", create("receipt-delivered", "receipt-delivered", "--ref-message-id", ref))
        expect_ok("receipt-rejected", create("receipt-rejected", "receipt-rejected", "--ref-message-id", ref, "--code", "invalid_body"))
        expect_ok("receipt-unknown-prekey", create("receipt-unknown-prekey", "receipt-unknown-prekey", "--ref-message-id", ref,
                                                   "--ref-prekey", read(text)["encryption"]["prekey"]))
        contact = create("contact-request", "contact-request", "--note", "let's talk")
        expect_ok("contact-request", contact)
        expect_ok("contact-accepted", create("contact-accepted", "contact-accepted"))
        expect_ok("contact-rejected", create("contact-rejected", "contact-rejected"))
        # Encrypted to a prekey the receiver does not hold (the sender's own), validly signed.
        expect_error("unknown-prekey", create("unknown-prekey", "text", "--prekey-agent", s_agent), "unknown_prekey")
        # Signed at now+301: outside the future window when opened at now.
        expect_error("future", create("future", "text", now=NOW + TIMESTAMP_FUTURE + 1), "stale_timestamp")
        # Every packet, contacts included, is accepted for the offline window and no longer.
        expect_ok("text-old-but-in-window", text, now=NOW + 3600)
        expect_ok("contact-old-but-in-window", contact, now=NOW + 3 * 3600)
        expect_error("stale-contact", contact, "stale_timestamp", now=NOW + OFFLINE_WINDOW + 1)
        # Tampering: the signature covers the ciphertext and is verified before decryption. The last
        # case claims another sender (its agent supplied) and fails that sender's signature check.
        base = read(text)
        for name, mutate, code, from_agent in [
            ("tamper-payload", lambda p: p["encryption"].__setitem__("payload", flip_b64(p["encryption"]["payload"], 20)), "invalid_signature", s_agent),
            ("tamper-kem", lambda p: p["encryption"].__setitem__("kemCiphertext", flip_b64(p["encryption"]["kemCiphertext"], 5)), "invalid_signature", s_agent),
            ("tamper-prekey-id", lambda p: p["encryption"].__setitem__("prekey", "0" * 64), "invalid_signature", s_agent),
            ("tamper-timestamp", lambda p: p.__setitem__("timestamp", p["timestamp"] - 1), "invalid_signature", s_agent),
            ("tamper-message-id", lambda p: p.__setitem__("messageId", "00000000-0000-4000-8000-000000000000"), "invalid_signature", s_agent),
            ("tamper-to", lambda p: p.__setitem__("to", THIRD), "wrong_recipient", s_agent),
            ("tamper-version", lambda p: p.__setitem__("ace", "2"), "unsupported_version", s_agent),
            ("tamper-unknown-member", lambda p: p.__setitem__("conversationId", "x"), "invalid_packet", s_agent),
            ("tamper-short-kem", lambda p: p["encryption"].__setitem__("kemCiphertext", base64.b64encode(b"\0" * 1119).decode()), "invalid_packet", s_agent),
            ("tamper-seq", lambda p: p["signature"].__setitem__("seq", p["signature"]["seq"] + 1), "stale_peer_binding", s_agent),
            ("tamper-from", lambda p: p.__setitem__("from", read(other)["descriptor"]["aceId"]), "invalid_signature", str(other)),
        ]:
            p = copy.deepcopy(base)
            mutate(p)
            path = pair / f"{name}.json"
            write(path, p)
            expect_error(name, path, code, from_agent=from_agent)
    except RuntimeError as exc:
        cells["driver"] = f"FAIL {exc}"
    return cells


RELAY = "https://relay.interop.test"


def handle_of(lang: str, who: str) -> str | None:
    """Only "a" publishes a handle ("<lang>-a"); "b" and "c" publish none."""
    return f"{lang}-a" if who == "a" else None


def card_cases(lang: str, who: str) -> list[tuple[str, Path, dict]]:
    """(case, card.json, expected verify-card result) for one generated identity's card record."""
    d = WORK / lang / who
    card = read(d / "card.json")
    rec = card["card"]
    handle = {"handle": h} if (h := handle_of(lang, who)) else {}
    expected = {"ok": True, "aceId": read(d / "agent.json")["descriptor"]["aceId"], "contact": "open", "listed": False, **handle}
    # The generated record itself must carry exactly what gen-identity was asked for.
    want = {"home": RELAY, "card": {}, "contact": "open", "listed": False, **handle}
    shape = {k: v for k, v in rec.items() if k not in ("aceId", "issuedAt", "signature")} == want and rec["issuedAt"] == NOW
    if not shape:
        expected = {"generated": "record does not match the gen-identity contract"}
    cases = [("valid", d / "card.json", expected)]
    bad = "invalid_authorization"
    for name, mutate, code in [
        ("tamper-signature", lambda c: c["card"]["signature"].__setitem__("value", flip_b64(c["card"]["signature"]["value"], 10)), bad),
        ("tamper-listed", lambda c: c["card"].__setitem__("listed", True), bad),
        ("tamper-contact", lambda c: c["card"].__setitem__("contact", "closed"), bad),
        ("tamper-unknown-member", lambda c: c["card"].__setitem__("x", 1), bad),
        ("tamper-seq", lambda c: c["card"]["signature"].__setitem__("seq", c["card"]["signature"]["seq"] + 1), "stale_peer_binding"),
    ]:
        c = {**card, "card": copy.deepcopy(rec)}  # the KEL is never tampered: share it
        mutate(c)
        path = WORK / "cards" / f"{lang}-{who}.{name}.json"
        write(path, c)
        cases.append((name, path, {"error": code}))
    return cases


def verify_card(verifier: str, path: Path, expected: dict) -> str:
    """One card case verified by SDK ``verifier``: "ok" or a failure."""
    try:
        got = json.loads(run(verifier, "verify-card", str(path)))
    except (RuntimeError, ValueError) as exc:
        return f"FAIL {exc}"
    return "ok" if got == expected else f"FAIL want {json.dumps(expected)}, got {json.dumps(got)[:200]}"


def report(label: str, cells: dict[str, str]) -> int:
    bad = {k: v for k, v in cells.items() if v != "ok"}
    print(f"{label} {len(cells) - len(bad)}/{len(cells)} ok")
    for k, v in bad.items():
        print(f"        {k}: {v}")
    return len(bad)


def main() -> int:
    if WORK.exists():
        shutil.rmtree(WORK)
    (WORK / "cards").mkdir(parents=True)
    print(f"work dir: {WORK}; SDKs: {','.join(DRIVERS)}; now: {NOW}")
    # Three identities per SDK: "a" sends, "b" receives, "c" is a bystander whose identity a forger claims.
    # Each pair runs on its own copies of the identities (drivers may rewrite prekey state), so pairs run in parallel.
    with ThreadPoolExecutor() as pool:
        list(pool.map(lambda lw: run(lw[0], "gen-identity", str(WORK / lw[0] / lw[1]),
                                     *(["--handle", h] if (h := handle_of(*lw)) else [])),
                      [(lang, who) for lang in DRIVERS for who in ("a", "b", "c")]))
        cards = [(lang, who, *case) for lang in DRIVERS for who in ("a", "b") for case in card_cases(lang, who)]
        # Card verifications and packet pairs are independent: submit both before collecting either.
        card_jobs = [(v, *case) for v in DRIVERS for case in cards]
        card_cells = pool.map(lambda j: verify_card(j[0], j[4], j[5]), card_jobs)
        pairs = [(s, r) for s in DRIVERS for r in DRIVERS]
        results = dict(zip(pairs, pool.map(lambda sr: run_pair(*sr), pairs)))
        card_results: dict[str, dict[str, str]] = {v: {} for v in DRIVERS}
        for (v, maker, who, name, _, _), cell in zip(card_jobs, card_cells):
            card_results[v][f"{maker}-{who} {name}"] = cell

    failed = sum(report(f"{s:>5} -> {r:<5}", cells) for (s, r), cells in results.items())
    failed += sum(report(f"verify-card {v:<5}", cells) for v, cells in card_results.items())
    print(f"cases per pair: {len({k for c in results.values() for k in c})}; pairs: {len(results)}; "
          f"card cases per verifier: {len(cards)}; failures: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

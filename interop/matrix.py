#!/usr/bin/env python3
"""Run the ACE interop matrix across driver executables (contract: README.md).

Every directed pair (sender, receiver) of the selected SDKs, same-SDK pairs included, runs the
packet cases below, and every SDK verifies every SDK's card records (valid and tampered); exits
non-zero on any mismatch. Standard library only.
"""

from __future__ import annotations

import base64
import copy
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

    def create(name: str, kind: str, *extra: str, now: int = NOW) -> Path:
        out = pair / f"{name}.json"
        run(s, "create-packet", str(sdir), "--to-agent", r_agent, "--kind", kind, "--out", str(out), *extra, now=now)
        return out

    def open_(name: str, packet: Path, from_agent: str = s_agent, now: int = NOW) -> dict:
        out = pair / f"{name}.result.json"
        run(r, "open-packet", str(rdir), "--from-agent", from_agent, "--packet", str(packet), "--out", str(out), now=now)
        return read(out)

    def expect_ok(name: str, packet: Path, **kw) -> None:
        got = open_(name, packet, **kw)
        content, p = read(Path(str(packet) + ".content.json")), read(packet)
        ok = (got.get("ok") is True and got["from"] == sender_id and got["messageId"] == p["messageId"]
              and got["type"] == content["type"] and got["schemaDigest"] == content["schemaDigest"]
              and got["body"] == content["body"] and got.get("threadId") == content.get("threadId"))
        cells[name] = "ok" if ok else f"FAIL {json.dumps(got)[:200]}"

    def expect_error(name: str, packet: Path, code: str, **kw) -> None:
        got = open_(name, packet, **kw)
        cells[name] = "ok" if got == {"error": code} else f"FAIL want {code}, got {json.dumps(got)[:200]}"

    try:
        text = create("text", "text", "--message", "héllo / ☃ \U0001F600")
        expect_ok("text", text)
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
# Identities with a handle (the matrix names them "<lang>-a"); "b" and "c" publish no handle.
HANDLED = ("a",)


def handle_of(lang: str, who: str) -> str | None:
    return f"{lang}-{who}" if who in HANDLED else None


def card_cases(lang: str, who: str) -> list[tuple[str, Path, dict]]:
    """(case, card.json, expected verify-card result) for one generated identity's card record."""
    d = WORK / lang / who
    card = read(d / "card.json")
    rec = card["card"]
    expected = {"ok": True, "aceId": read(d / "agent.json")["descriptor"]["aceId"], "contact": "open", "listed": False}
    if handle_of(lang, who):
        expected["handle"] = handle_of(lang, who)
    # The generated record itself must carry exactly what gen-identity was asked for.
    want = {"home": RELAY, "card": {}, "contact": "open", "listed": False}
    if handle_of(lang, who):
        want["handle"] = handle_of(lang, who)
    shape = {k: v for k, v in rec.items() if k not in ("aceId", "issuedAt", "signature")} == want and rec["issuedAt"] == NOW
    if not shape:
        expected = {"generated": "record does not match the gen-identity contract"}
    cases = [("valid", d / "card.json", expected)]
    bad = "invalid_authorization"
    for name, mutate, code in [
        ("tamper-signature", lambda c: c["card"]["signature"].__setitem__("value", flip_b64(c["card"]["signature"]["value"], 10)), bad),
        ("tamper-listed", lambda c: c["card"].__setitem__("listed", True), bad),
        ("tamper-contact", lambda c: c["card"].__setitem__("contact", "closed"), bad),
        ("tamper-unknown-member", lambda c: c["card"].__setitem__("visibility", "public"), bad),
        ("tamper-seq", lambda c: c["card"]["signature"].__setitem__("seq", c["card"]["signature"]["seq"] + 1), "stale_peer_binding"),
    ]:
        c = copy.deepcopy(card)
        mutate(c)
        path = WORK / "cards" / f"{lang}-{who}.{name}.json"
        path.parent.mkdir(exist_ok=True)
        write(path, c)
        cases.append((name, path, {"error": code}))
    return cases


def run_cards(verifier: str, cases: list[tuple[str, str, str, Path, dict]]) -> dict[str, str]:
    """Every card case verified by SDK ``verifier``: "<maker>-<who> <case>" -> "ok" or a failure."""
    cells: dict[str, str] = {}
    for maker, who, name, path, expected in cases:
        key = f"{maker}-{who} {name}"
        try:
            got = json.loads(run(verifier, "verify-card", str(path)))
        except (RuntimeError, ValueError) as exc:
            cells[key] = f"FAIL {exc}"
            continue
        cells[key] = "ok" if got == expected else f"FAIL want {json.dumps(expected)}, got {json.dumps(got)[:200]}"
    return cells


def main() -> int:
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    print(f"work dir: {WORK}; SDKs: {','.join(DRIVERS)}; now: {NOW}")
    # Three identities per SDK: "a" sends, "b" receives, "c" is a bystander whose identity a forger claims.
    # Each pair runs on its own copies of the identities (drivers may rewrite prekey state), so pairs run in parallel.
    with ThreadPoolExecutor() as pool:
        list(pool.map(lambda lw: run(lw[0], "gen-identity", str(WORK / lw[0] / lw[1]),
                                     *(["--handle", h] if (h := handle_of(*lw)) else [])),
                      [(lang, who) for lang in DRIVERS for who in ("a", "b", "c")]))
        cards = [(lang, who, *case) for lang in DRIVERS for who in ("a", "b") for case in card_cases(lang, who)]
        card_results = dict(zip(DRIVERS, pool.map(lambda v: run_cards(v, cards), DRIVERS)))
        pairs = [(s, r) for s in DRIVERS for r in DRIVERS]
        results = dict(zip(pairs, pool.map(lambda sr: run_pair(*sr), pairs)))

    failed = 0
    for (s, r), cells in results.items():
        bad = {k: v for k, v in cells.items() if v != "ok"}
        failed += len(bad)
        print(f"{s:>5} -> {r:<5} {len(cells) - len(bad)}/{len(cells)} ok")
        for k, v in bad.items():
            print(f"        {k}: {v}")
    for v, cells in card_results.items():
        bad = {k: c for k, c in cells.items() if c != "ok"}
        failed += len(bad)
        print(f"verify-card {v:<5} {len(cells) - len(bad)}/{len(cells)} ok")
        for k, c in bad.items():
            print(f"        {k}: {c}")
    print(f"cases per pair: {len({k for c in results.values() for k in c})}; pairs: {len(results)}; "
          f"card cases per verifier: {len(cards)}; failures: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

"""ACE interop: tamper fixtures and evaluate the cross-SDK matrix (stdlib only).

    python3 compare.py tamper <workdir>   # flip one byte of every m1 envelope's kemCiphertext
    python3 compare.py check  <workdir>   # assert, print the matrices, exit 1 on any mismatch
"""

from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any

LANGS = ["ts", "py", "swift"]
SCHEMES = ["ed25519", "secp256k1"]
AUTH = ["listen", "inbox", "unregister", "intent"]


def load(w: str, p: str) -> Any:
    path = os.path.join(w, p)
    if not os.path.exists(path):
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def tamper(w: str) -> None:
    src, dst = os.path.join(w, "msgs/m1"), os.path.join(w, "msgs/tampered")
    os.makedirs(dst, exist_ok=True)
    for fn in sorted(os.listdir(src)):
        m = load(w, f"msgs/m1/{fn}")
        out: dict = {}
        for k in ("text", "rfq"):
            if k not in m:
                continue
            env = json.loads(json.dumps(m[k]))
            raw = bytearray(base64.b64decode(env["encryption"]["kemCiphertext"], validate=True))
            raw[len(raw) // 2] ^= 0x01
            env["encryption"]["kemCiphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
            out[k] = env
        with open(os.path.join(dst, fn), "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False)


def strip_none(v: Any) -> Any:
    if isinstance(v, dict):
        return {k: strip_none(x) for k, x in v.items() if x is not None}
    if isinstance(v, list):
        return [strip_none(x) for x in v]
    return v


class Checker:
    def __init__(self, w: str) -> None:
        self.w = w
        self.failures: list[str] = []
        self.cells: dict[str, dict[tuple[str, str, str], bool]] = {}

    def cell(self, table: str, row: str, col: str, scheme: str, ok: bool, why: str) -> None:
        key = (row, col, scheme)
        t = self.cells.setdefault(table, {})
        t[key] = t.get(key, True) and ok
        if not ok:
            self.failures.append(f"[{table}] {row}->{col} ({scheme}): {why}")

    def expect(self, table: str, row: str, col: str, s: str, cond: bool, why: str) -> bool:
        self.cell(table, row, col, s, bool(cond), why)
        return bool(cond)

    def ok(self, table: str, row: str, col: str, s: str, res: Any, what: str) -> bool:
        good = isinstance(res, dict) and res.get("ok") is True
        detail = res if not good else ""
        return self.expect(table, row, col, s, good, f"{what} failed: {json.dumps(detail, ensure_ascii=False)[:400]}")

    def code(self, table: str, row: str, col: str, s: str, res: Any, want: str, what: str) -> None:
        got = res.get("code") if isinstance(res, dict) and res.get("ok") is False else ("<accepted>" if res else "<missing>")
        self.expect(table, row, col, s, got == want, f"{what}: expected {want}, got {got}")

    # --- 1, 3, 4: identities, registration requests, auth headers ------------------------

    def identities(self) -> None:
        ids = {(lang, s): load(self.w, f"ids/{lang}-{s}.json") for lang in LANGS for s in SCHEMES}
        digests: dict[tuple[str, str], dict[str, str]] = {}
        for v in LANGS:
            out = load(self.w, f"out/{v}/verify.json") or {}
            for src in LANGS:
                for s in SCHEMES:
                    d, r = ids[(src, s)], out.get(f"{src}-{s}")
                    if d is None or r is None:
                        for t in ("1 identity", "3 registration request", "4 auth headers"):
                            self.cell(t, src, v, s, False, "missing output")
                        continue
                    T = "1 identity"
                    imp = r["import"]
                    if self.ok(T, src, v, s, imp, "fromExport"):
                        for k in ("aceId", "address", "scheme", "signingPublicKey", "encryptionPublicKey"):
                            self.expect(T, src, v, s, imp[k] == d[k], f"import {k}: {imp[k]!r} != {d[k]!r}")
                        self.expect(T, src, v, s, imp["reexport"] == d["export"], "re-export differs from export")
                        self.expect(T, src, v, s, strip_none(imp["registrationFile"]) == strip_none(d["registrationFile"]),
                                    f"createRegistrationFile differs: {imp['registrationFile']} vs {d['registrationFile']}")
                    rf = r["regFile"]
                    if self.ok(T, src, v, s, rf, "verifyRegistrationFile"):
                        for k in ("aceId", "scheme", "signingPublicKey", "encryptionPublicKey", "address"):
                            self.expect(T, src, v, s, rf[k] == d[k], f"regFile peer {k} mismatch")
                    T = "3 registration request"
                    rr = r["regRequest"]
                    if self.ok(T, src, v, s, rr, "verifyRegistrationRequest"):
                        digests.setdefault((src, s), {})[v] = rr["requestDigest"]
                        for k in ("aceId", "signingPublicKey", "encryptionPublicKey"):
                            self.expect(T, src, v, s, rr["peer"][k] == d[k], f"request peer {k} mismatch")
                    T = "4 auth headers"
                    for a in AUTH:
                        self.ok(T, src, v, s, r["auth"][a], f"verifyAuthHeaders({a})")
                    self.code(T, src, v, s, r["authWrongRequest"], "invalid_signature", "listen headers checked as inbox")
        for (src, s), per in digests.items():
            same = len(set(per.values())) == 1
            for v in per:
                self.expect("3 registration request", src, v, s, same, f"requestDigest differs across verifiers: {per}")

    # --- 2: messages -------------------------------------------------------------------

    def messages(self) -> None:
        T = "2 messages"
        ids = {(lang, s): load(self.w, f"ids/{lang}-{s}.json") for lang in LANGS for s in SCHEMES}
        rxs = {(lang, s): load(self.w, f"ids/{lang}-{s}-rx.json") for lang in LANGS for s in SCHEMES}
        r1 = {lang: load(self.w, f"out/{lang}/recv1.json") or {} for lang in LANGS}
        r2 = {lang: load(self.w, f"out/{lang}/recv2.json") or {} for lang in LANGS}
        tampered_codes: dict[str, set] = {}
        for S in LANGS:
            for R in LANGS:
                for s in SCHEMES:
                    key = f"{S}-{R}-{s}"
                    m1 = load(self.w, f"msgs/m1/{key}.json")
                    if not self.expect(T, S, R, s, m1 is not None and "error" not in m1, f"send failed: {m1 and m1.get('error')}"):
                        continue
                    r = r1[R].get(key)
                    if not self.expect(T, S, R, s, r is not None and "error" not in r, f"receiver failed: {r and r.get('error')}"):
                        continue
                    sid, rid = ids[(S, s)]["aceId"], rxs[(R, s)]["aceId"]
                    for k, body, typ, tid in (("text", m1["textBody"], "text", None), ("rfq", m1["rfqBody"], "rfq", m1["threadId"])):
                        p = r[k]
                        if self.ok(T, S, R, s, p, f"parse {k}"):
                            self.expect(T, S, R, s, p["body"] == body, f"{k} body differs: {p['body']} vs {body}")
                            self.expect(T, S, R, s, p["type"] == typ and p["threadId"] == tid, f"{k} type/threadId mismatch")
                            self.expect(T, S, R, s, p["from"] == sid and p["to"] == rid, f"{k} from/to mismatch")
                            self.expect(T, S, R, s, p["messageId"] == m1[k]["messageId"], f"{k} messageId mismatch")
                    for k in ("tamperedText", "tamperedRfq"):
                        c = r[k].get("code") if r[k].get("ok") is False else "<accepted>"
                        tampered_codes.setdefault(key, set()).add(c)
                        self.code(T, S, R, s, r[k], "invalid_signature", f"{k} (kemCiphertext byte flipped)")
                    self.code(T, S, R, s, r["replayAgain"], "replay", "second parse of the same text")
                    self.expect(T, S, R, s, r["stateAfterRfq"] == "rfq", f"receiver state after rfq = {r['stateAfterRfq']}")
                    if not self.ok(T, S, R, s, r["reply"], "create offer reply"):
                        continue
                    self.expect(T, S, R, s, r["stateAfterOffer"] == "offered", f"receiver state after offer = {r['stateAfterOffer']}")
                    m2 = load(self.w, f"msgs/m2/{R}-{S}-{s}.json")
                    q = r2[S].get(f"{R}-{S}-{s}")
                    if not self.expect(T, S, R, s, q is not None and "error" not in q, f"original sender failed: {q and q.get('error')}"):
                        continue
                    o = q["offer"]
                    if self.ok(T, S, R, s, o, "sender parses offer"):
                        self.expect(T, S, R, s, o["body"] == m2["offerBody"], f"offer body differs: {o['body']}")
                        self.expect(T, S, R, s, o["threadId"] == m1["threadId"], "offer threadId does not reference the rfq thread")
                        self.expect(T, S, R, s, o["conversationId"] == m1["rfq"]["conversationId"], "offer conversationId differs")
                        self.expect(T, S, R, s, o["from"] == rid and o["to"] == sid, "offer from/to mismatch")
                    self.expect(T, S, R, s, q["state"] == "offered", f"sender state after offer = {q['state']}")
                    snap = q.get("snapshot") or {}
                    hist = [h.get("type") for h in snap.get("history", [])]
                    self.expect(T, S, R, s, hist == ["rfq", "offer"], f"sender history = {hist}")

    # --- 5: persisted state ------------------------------------------------------------

    def persistence(self) -> None:
        T = "5 persisted state"
        ids = {(lang, s): load(self.w, f"ids/{lang}-{s}.json") for lang in LANGS for s in SCHEMES}
        for R in LANGS:
            p = load(self.w, f"out/{R}/persist.json") or {}
            for s in SCHEMES:
                r = p.get(s) or {"error": "missing"}
                good = "error" not in r
                why = f"writer {R} failed: {r.get('error')}"
                if good:
                    for S, rec in r["receives"].items():
                        if rec["text"]["kind"] != "delivered" or rec["rfq"]["kind"] != "delivered":
                            good, why = False, f"writer {R} Inbox.receive from {S}: {rec}"
                        elif rec["textAgain"]["kind"] != "duplicate":
                            good, why = False, f"writer {R} re-receive from {S} not duplicate: {rec['textAgain']}"
                    if good and r.get("handed") != 2 * len(LANGS):
                        good, why = False, f"writer {R} handed {r.get('handed')} messages, expected {2 * len(LANGS)}"
                for L in LANGS:
                    self.expect(T, R, L, s, good, why)
            for L in LANGS:
                out = load(self.w, f"out/{L}/load.json") or {}
                for s in SCHEMES:
                    r = out.get(f"{R}-{s}")
                    if not self.expect(T, R, L, s, r is not None and "error" not in r, f"loader failed: {r and r.get('error')}"):
                        continue
                    if self.ok(T, R, L, s, r["replay"], "ReplayDetector.fromState(replay.json)"):
                        self.expect(T, R, L, s, r["replay"]["identical"], f"replay.json re-export not byte-identical: {r['replay']['reexport'][:300]}")
                        self.expect(T, R, L, s, r["replay"]["entries"] == 2 * len(LANGS), f"replay entries = {r['replay']['entries']}")
                    self.expect(T, R, L, s, len(r["threads"]) == len(LANGS), f"{len(r['threads'])} thread records, expected {len(LANGS)}")
                    for t in r["threads"]:
                        if self.ok(T, R, L, s, t, "ThreadStateMachine.fromState(thread record)"):
                            self.expect(T, R, L, s, t["exported"] == t["original"], f"thread re-export differs: {t['exported']} vs {t['original']}")
                            self.expect(T, R, L, s, t["state"] == "rfq", f"thread state = {t['state']}")
                    if self.ok(T, R, L, s, r["threadStore"], "ThreadStore.list"):
                        self.expect(T, R, L, s, r["threadStore"]["count"] == len(LANGS), f"ThreadStore count = {r['threadStore']['count']}")
                    if self.ok(T, R, L, s, r["peers"], "PeerStore.get"):
                        for S, got in r["peers"]["peers"].items():
                            d = ids[(S, s)]
                            same = got is not None and all(got[k] == d[k] for k in ("aceId", "signingPublicKey", "encryptionPublicKey"))
                            self.expect(T, R, L, s, same, f"peer record for {S}: {got}")
                    if self.ok(T, R, L, s, r["inboxReopen"], "Inbox.open on foreign store"):
                        ro = r["inboxReopen"]
                        self.expect(T, R, L, s, ro["handedOnOpen"] == 0, f"recovery re-handed {ro['handedOnOpen']} messages")
                        self.expect(T, R, L, s, ro["duplicate"]["kind"] == "duplicate", f"re-receive after reopen: {ro['duplicate']}")

    # --- report ------------------------------------------------------------------------

    def report(self) -> int:
        labels = {
            "1 identity": ("exporter", "importer"),
            "2 messages": ("sender", "receiver"),
            "3 registration request": ("creator", "verifier"),
            "4 auth headers": ("creator", "verifier"),
            "5 persisted state": ("writer", "loader"),
        }
        total = passed = 0
        for table in sorted(self.cells):
            rows, cols = labels[table]
            print(f"\n== {table}  (rows: {rows}, columns: {cols}) ==")
            for s in SCHEMES:
                print(f"  [{s}]".ljust(14) + "".join(c.ljust(8) for c in LANGS))
                for r in LANGS:
                    line = f"  {r}".ljust(14)
                    for c in LANGS:
                        v = self.cells[table].get((r, c, s))
                        total += v is not None
                        passed += bool(v)
                        line += ("PASS" if v else "FAIL" if v is not None else "-").ljust(8)
                    print(line)
        print(f"\n{passed}/{total} cells passed")
        if self.failures:
            print(f"\n{len(self.failures)} failure(s):")
            for f in self.failures:
                print("  - " + f)
            return 1
        return 0


def main() -> int:
    cmd, w = sys.argv[1], sys.argv[2]
    if cmd == "tamper":
        tamper(w)
        return 0
    c = Checker(w)
    c.identities()
    c.messages()
    c.persistence()
    return c.report()


if __name__ == "__main__":
    sys.exit(main())

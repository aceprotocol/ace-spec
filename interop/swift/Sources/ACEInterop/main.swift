// ACE cross-SDK interop harness — Swift side.
// Usage: ACEInterop <phase> <workdir>
// Phases: gen | verify | send1 | recv1 | recv2 | persist | load | pverify | psend | precv | pdecide | pload.
// See ../../../README.md.
import ACE
import Foundation

let LANG = "swift"
let LANGS = ["ts", "py", "swift"]
let SCHEMES: [SigningScheme] = [.ed25519, .secp256k1]
let args = CommandLine.arguments
guard args.count == 3 else { fatalError("usage: ACEInterop <phase> <workdir>") }
let phase = args[1]
let W = URL(fileURLWithPath: args[2])

// MARK: - JSON / file helpers

func url(_ p: String) -> URL { W.appendingPathComponent(p) }
func parseJSON(_ d: Data) throws -> Any { try JSONSerialization.jsonObject(with: d, options: [.fragmentsAllowed]) }
func rd(_ p: String) throws -> [String: Any] { try parseJSON(Data(contentsOf: url(p))) as! [String: Any] }
func rdAny(_ p: String) throws -> Any { try parseJSON(Data(contentsOf: url(p))) }
func anyJSON(_ o: [String: JSONValue]) throws -> Any { try parseJSON(JSONValue.object(o).jsonData()) }
func data(_ v: Any) throws -> Data { try JSONSerialization.data(withJSONObject: v, options: [.sortedKeys, .withoutEscapingSlashes]) }
func wr(_ p: String, _ v: Any) throws {
    let u = url(p)
    try FileManager.default.createDirectory(at: u.deletingLastPathComponent(), withIntermediateDirectories: true)
    try JSONSerialization.data(withJSONObject: v, options: [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]).write(to: u)
}
func encodable<T: Encodable>(_ v: T) throws -> Any {
    let enc = JSONEncoder()
    enc.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
    return try parseJSON(enc.encode(v))
}
func b64(_ d: Data) -> String { ACEBase64.encode(d) }
func now() -> Int { Int(Date().timeIntervalSince1970) }
func fail(_ e: Error) -> [String: Any] {
    if let a = e as? ACEError { return ["ok": false, "code": a.code.rawValue, "message": a.message] }
    return ["ok": false, "code": "exception", "message": String(describing: e)]
}
func attempt(_ fn: () throws -> [String: Any]) -> [String: Any] {
    do { return try fn().merging(["ok": true]) { a, _ in a } } catch { return fail(error) }
}
func attemptAsync(_ fn: () async throws -> [String: Any]) async -> [String: Any] {
    do { return try await fn().merging(["ok": true]) { a, _ in a } } catch { return fail(error) }
}
func obj(_ s: String) -> [String: JSONValue] { try! JSONValue(json: Data(s.utf8)).objectValue! }

// MARK: - Fixtures (same values in every language)

let AUTH: [(String, RelayAuthRequest)] = [
    ("listen", .listen(since: "-")),
    ("inbox", .inbox(since: "1700000000000-0", limit: 50)),
    ("unregister", .unregister),
    ("intent", .intent(need: "Translate EN→FR", tags: ["nlp", "fr"], maxPrice: "10", currency: "USDC", ttl: 3600)),
]
func profile(_ lang: String) -> AgentProfile {
    AgentProfile(name: "Agent \(lang) é", description: "interop / matrix", tags: ["interop", "ace"],
                 capabilities: ["translate"], endpoint: "https://\(lang).example/ace",
                 pricing: ProfilePricing(currency: "USDC", maxAmount: "10"))
}
func textBody(_ s: String, _ r: String, _ sch: String) -> [String: JSONValue] {
    ["message": "hello \(s)→\(r) (\(sch)) héllo 世界 / \"q\" \\ ✓"]
}
let RFQ = obj(#"{"need":"Translate 500 words EN→FR","maxPrice":"10.50","currency":"USDC","ttl":3600}"#)
let OFFER = obj(#"{"price":"9.75","currency":"USDC","terms":"delivery in 24h / net","ttl":600}"#)

// Principal fixtures (same values in every language; 09-principal). One shared CAIP-10 account; the controller
// signer (owner key) of scheme s is a v4 test-vectors agent (ed25519: alice, secp256k1: bob). `<lang>-<s>` is a
// delegate (["agent"]), `<lang>-<s>-rx` a controller (["controller"]).
nonisolated(unsafe) let VECTORS: [String: Any] = {
    let path = ProcessInfo.processInfo.environment["ACE_VECTORS"]
        ?? URL(fileURLWithPath: #filePath).deletingLastPathComponent()
            .appendingPathComponent("../../../../test-vectors.json").standardizedFileURL.path
    return try! parseJSON(Data(contentsOf: URL(fileURLWithPath: path))) as! [String: Any]
}()
let ACCOUNT = "solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:InteropOwner1111111111111111111111111111111"
let OWNER_AGENT: [SigningScheme: String] = [.ed25519: "alice", .secp256k1: "bob"]
let SCOPE = "interop ✓"
func vec(_ path: String...) -> Any { path.reduce(VECTORS as Any) { ($0 as! [String: Any])[$1]! } }
// Deterministic record: same signer, delegate subject, issuedAt and expiresAt in every language.
let FIXED_SUBJECT = vec("vectors", "principalRules", "senders", "agent", "signingPublicKey") as! String
let FIXED_ISSUED_AT = vec("vectors", "principal", "now") as! Int
let REQ = obj(#"{"action":"x402.pay","summary":"Pay 1 USDC ✓","amount":"1","currency":"USDC","details":{"payTo":"x","network":"solana"},"ttl":600}"#)
let REP = obj(#"{"action":"copy.run","summary":"copied 2 trades","outcome":"ok","proof":{"txHash":"0x01"}}"#)
func owner(_ s: SigningScheme) throws -> SoftwareIdentity {
    let a = vec("agents", OWNER_AGENT[s]!) as! [String: Any]
    return try SoftwareIdentity(export: SoftwareIdentityExport(
        scheme: s, signingPrivateKey: a["signingPrivateKey"] as! String, encryptionPrivateKey: a["encryptionPrivateKey"] as! String))
}
func ownerKey(_ s: SigningScheme) -> PrincipalKey {
    PrincipalKey(scheme: s.rawValue, publicKey: vec("agents", OWNER_AGENT[s]!, "signingPublicKey") as! String)
}
/// `Inbox.open` principal: the shared account, this scheme's owner key as `selfSigner`, the other one as trusted.
func inboxPrincipal(_ s: SigningScheme) -> InboxPrincipal {
    InboxPrincipal(account: ACCOUNT, selfSigner: ownerKey(s), trustedSigners: Set(SCHEMES.filter { $0 != s }.map(ownerKey)))
}
func decisionBodies(_ rid: String, _ conv: String) -> [String: [String: JSONValue]] {
    ["decisionBody": ["requestId": .string(rid), "outcome": "approve", "result": .object(["payload": "signed ✓"])],
     "decision2Body": ["requestId": .string(rid), "outcome": "deny", "reason": "changed my mind ✓"],
     "reportBody": ["action": "x402.pay", "summary": "paid 1 USDC ✓", "outcome": "ok", "requestId": .string(rid),
                    "ref": .object(["conversationId": .string(conv), "messageId": .string(rid)])]]
}
func hex(_ d: Data) -> String { d.map { String(format: "%02x", $0) }.joined() }

// `<lang>-<scheme>` sends; a second identity `<lang>-<scheme>-rx` receives (so swift→swift uses two parties).
func idFile(_ lang: String, _ s: SigningScheme, rx: Bool = false) throws -> [String: Any] {
    try rd("ids/\(lang)-\(s.rawValue)\(rx ? "-rx" : "").json")
}
func identity(_ lang: String, _ s: SigningScheme, rx: Bool = false) throws -> SoftwareIdentity {
    let e = try idFile(lang, s, rx: rx)["export"]!
    return try SoftwareIdentity(export: JSONDecoder().decode(SoftwareIdentityExport.self, from: data(e)))
}
func regFile(_ d: [String: Any]) throws -> RegistrationFile { try RegistrationFile(json: data(d["registrationFile"]!)) }
func peerOf(_ lang: String, _ s: SigningScheme, rx: Bool = false) throws -> VerifiedPeer {
    try verifyRegistrationFile(regFile(idFile(lang, s, rx: rx)))
}
func principalPeer(_ lang: String, _ s: SigningScheme, rx: Bool = false) throws -> VerifiedPeer {
    try verifyRegistrationFile(RegistrationFile(json: data(idFile(lang, s, rx: rx)["registrationFilePrincipal"]!)))
}
func envelope(_ v: Any) throws -> ACEMessage { try decodeEnvelope(data(v)) }
func summary(_ p: ParsedMessage) throws -> [String: Any] {
    ["messageId": p.messageId, "from": p.from, "to": p.to, "conversationId": p.conversationId,
     "type": p.type.rawValue, "threadId": p.threadId as Any? ?? NSNull(), "timestamp": p.timestamp,
     "body": try parseJSON(JSONValue.object(p.body).jsonData())]
}
func peerSummary(_ p: VerifiedPeer) -> [String: Any] {
    ["aceId": p.aceId, "scheme": p.scheme.rawValue, "signingPublicKey": b64(p.signingPublicKey),
     "encryptionPublicKey": b64(p.encryptionPublicKey), "address": p.address, "source": p.source.rawValue]
}
func parseFresh(_ env: Any, _ me: SoftwareIdentity, _ peer: VerifiedPeer) throws -> [String: Any] {
    try summary(parseMessage(envelope(env), receiver: me, sender: peer,
                             threads: ThreadStateMachine(localAceId: me.getACEId()), replay: ReplayDetector()))
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var n = 0
    func inc() { lock.lock(); n += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return n }
}

// MARK: - Phases

func gen() throws {
    for (s, suffix) in SCHEMES.map({ ($0, "") }) + SCHEMES.map({ ($0, "-rx") }) {
        let id = try SoftwareIdentity.generate(scheme: s)
        let ts = now()
        var auth: [String: Any] = [:]
        for (k, req) in AUTH { auth[k] = ["headers": try createAuthHeaders(identity: id, request: req, timestamp: ts)] }
        let reg = try createRegistrationFile(for: id, name: "Agent \(LANG) \(s.rawValue)", endpoint: "https://\(LANG).example/ace")
        let req = try createRegistrationRequest(identity: id, profile: .replace(profile(LANG)), timestamp: ts)
        let principal = try createPrincipalRecord(
            signer: PrincipalSigner(identity: owner(s)), subjectSigningPublicKey: id.getSigningPublicKey(), account: ACCOUNT,
            roles: suffix == "-rx" ? ["controller"] : ["agent"], expiresAt: ts + 3600, scope: SCOPE, issuedAt: ts)
        let regP = try createRegistrationFile(for: id, name: "Agent \(LANG) \(s.rawValue)\(suffix)",
                                              endpoint: "https://\(LANG).example/ace", principal: principal)
        var prof = profile(LANG)
        prof.principal = principal
        let reqP = try createRegistrationRequest(identity: id, profile: .replace(prof), timestamp: ts)
        try wr("ids/\(LANG)-\(s.rawValue)\(suffix).json", [
            "lang": LANG, "scheme": s.rawValue, "export": try encodable(id.exportPrivateKey()), "aceId": id.getACEId(),
            "address": id.getAddress(), "signingPublicKey": b64(id.getSigningPublicKey()),
            "encryptionPublicKey": b64(id.getEncryptionPublicKey()),
            "registrationFile": try encodable(reg), "registrationRequest": try parseJSON(req.jsonData()), "auth": auth,
            "principal": try parseJSON(principal.jsonData()), "registrationFilePrincipal": try encodable(regP),
            "registrationRequestPrincipal": try parseJSON(reqP.jsonData()),
        ])
    }
    for s in SCHEMES {
        let subject = try ACEBase64.decode(FIXED_SUBJECT)
        let rec = try createPrincipalRecord(signer: PrincipalSigner(identity: owner(s)), subjectSigningPublicKey: subject,
                                            account: ACCOUNT, roles: ["agent"], expiresAt: FIXED_ISSUED_AT + 3600, scope: SCOPE,
                                            issuedAt: FIXED_ISSUED_AT)
        try wr("fixed/\(LANG)-\(s.rawValue).json", [
            "record": try parseJSON(rec.jsonData()), "payloadHex": hex(principalPayload(rec, subjectSigningPublicKey: subject)),
            "signDataHex": hex(try principalSignData(rec, subjectSigningPublicKey: subject)),
        ])
    }
}

func verify() throws {
    var out: [String: Any] = [:]
    for src in LANGS {
        for s in SCHEMES {
            let d = try idFile(src, s)
            let rf = d["registrationFile"] as! [String: Any]
            var r: [String: Any] = [:]
            r["import"] = attempt {
                let e = try JSONDecoder().decode(SoftwareIdentityExport.self, from: data(d["export"]!))
                let idn = try SoftwareIdentity(export: e)
                let reg = try createRegistrationFile(for: idn, name: rf["name"] as! String, endpoint: rf["endpoint"] as! String)
                return ["aceId": idn.getACEId(), "address": idn.getAddress(), "scheme": idn.getSigningScheme().rawValue,
                        "signingPublicKey": b64(idn.getSigningPublicKey()), "encryptionPublicKey": b64(idn.getEncryptionPublicKey()),
                        "reexport": try encodable(idn.exportPrivateKey()), "registrationFile": try encodable(reg)]
            }
            var peer: VerifiedPeer?
            r["regFile"] = attempt {
                let p = try verifyRegistrationFile(regFile(d))
                peer = p
                return peerSummary(p)
            }
            r["regRequest"] = attempt {
                let v = try verifyRegistrationRequest(data(d["registrationRequest"]!))
                return ["requestDigest": v.requestDigest, "peer": peerSummary(v.peer)]
            }
            let spk = try peer?.signingPublicKey ?? ACEBase64.decode(d["signingPublicKey"] as! String)
            let scheme = SigningScheme(rawValue: d["scheme"] as! String)!
            let aceId = d["aceId"] as! String
            let authD = d["auth"] as! [String: Any]
            func headers(_ k: String) -> [String: String] { (authD[k] as! [String: Any])["headers"] as! [String: String] }
            var a: [String: Any] = [:]
            for (k, req) in AUTH {
                a[k] = attempt {
                    try verifyAuthHeaders(parseAuthHeaders(headers(k)), request: req, aceId: aceId, scheme: scheme, signingPublicKey: spk)
                    return [:]
                }
            }
            r["auth"] = a
            r["authWrongRequest"] = attempt {
                try verifyAuthHeaders(parseAuthHeaders(headers("listen")), request: AUTH[1].1, aceId: aceId, scheme: scheme, signingPublicKey: spk)
                return [:]
            }
            out["\(src)-\(s.rawValue)"] = r
        }
    }
    try wr("out/\(LANG)/verify.json", out)
}

func send1() throws {
    for R in LANGS {
        for s in SCHEMES {
            let key = "\(LANG)-\(R)-\(s.rawValue)"
            do {
                let me = try identity(LANG, s)
                let peer = try peerOf(R, s, rx: true)
                let threads = try ThreadStateMachine(localAceId: me.getACEId())
                let threadId = "deal/\(key)/✓"
                let tb = textBody(LANG, R, s.rawValue)
                let text = try createMessage(sender: me, recipient: peer, type: .text, body: tb, threads: threads)
                let rfq = try createMessage(sender: me, recipient: peer, type: .rfq, body: RFQ, threads: threads, threadId: threadId)
                try wr("msgs/m1/\(key).json", ["threadId": threadId, "textBody": try anyJSON(tb), "rfqBody": try anyJSON(RFQ),
                                               "text": try parseJSON(text.jsonData()), "rfq": try parseJSON(rfq.jsonData())])
                try wr("priv/\(LANG)/threads-\(R)-\(s.rawValue).json", try encodable(threads.exportState()))
            } catch {
                try wr("msgs/m1/\(key).json", ["error": fail(error)])
            }
        }
    }
}

func recv1() throws {
    var out: [String: Any] = [:]
    for S in LANGS {
        for s in SCHEMES {
            let key = "\(S)-\(LANG)-\(s.rawValue)"
            var r: [String: Any] = [:]
            do {
                let m = try rd("msgs/m1/\(key).json")
                if let e = m["error"] { throw NSError(domain: "sender failed: \(e)", code: 1) }
                let t = try rd("msgs/tampered/\(key).json")
                let me = try identity(LANG, s, rx: true)
                let peer = try peerOf(S, s)
                r["tamperedText"] = attempt { try parseFresh(t["text"]!, me, peer) }
                r["tamperedRfq"] = attempt { try parseFresh(t["rfq"]!, me, peer) }
                let threads = try ThreadStateMachine(localAceId: me.getACEId())
                let replay = try ReplayDetector()
                func parse(_ env: Any) throws -> [String: Any] {
                    try summary(parseMessage(envelope(env), receiver: me, sender: peer, threads: threads, replay: replay))
                }
                r["text"] = attempt { try parse(m["text"]!) }
                r["rfq"] = attempt { try parse(m["rfq"]!) }
                r["replayAgain"] = attempt { try parse(m["text"]!) }
                let conv = (m["rfq"] as! [String: Any])["conversationId"] as! String
                let threadId = m["threadId"] as! String
                r["stateAfterRfq"] = threads.getState(conversationId: conv, threadId: threadId).rawValue
                r["reply"] = attempt {
                    let offer = try createMessage(sender: me, recipient: peer, type: .offer, body: OFFER, threads: threads, threadId: threadId)
                    try wr("msgs/m2/\(LANG)-\(S)-\(s.rawValue).json",
                           ["threadId": threadId, "offerBody": try anyJSON(OFFER), "offer": try parseJSON(offer.jsonData())])
                    return [:]
                }
                r["stateAfterOffer"] = threads.getState(conversationId: conv, threadId: threadId).rawValue
            } catch {
                r["error"] = fail(error)
            }
            out[key] = r
        }
    }
    try wr("out/\(LANG)/recv1.json", out)
}

func recv2() throws {
    var out: [String: Any] = [:]
    for R in LANGS {
        for s in SCHEMES {
            let key = "\(R)-\(LANG)-\(s.rawValue)"
            var r: [String: Any] = [:]
            do {
                guard FileManager.default.fileExists(atPath: url("msgs/m2/\(key).json").path) else {
                    throw NSError(domain: "no offer from receiver", code: 1)
                }
                let m = try rd("msgs/m2/\(key).json")
                let me = try identity(LANG, s)
                let snaps = try JSONDecoder().decode([ThreadSnapshot].self, from: Data(contentsOf: url("priv/\(LANG)/threads-\(R)-\(s.rawValue).json")))
                let threads = try ThreadStateMachine(state: snaps, localAceId: me.getACEId())
                let replay = try ReplayDetector()
                let peer = try peerOf(R, s, rx: true)
                r["offer"] = attempt {
                    try summary(parseMessage(envelope(m["offer"]!), receiver: me, sender: peer, threads: threads, replay: replay))
                }
                let conv = (m["offer"] as! [String: Any])["conversationId"] as! String
                let threadId = m["threadId"] as! String
                r["state"] = threads.getState(conversationId: conv, threadId: threadId).rawValue
                r["snapshot"] = try threads.getSnapshot(conversationId: conv, threadId: threadId).map { try encodable($0) } ?? NSNull()
            } catch {
                r["error"] = fail(error)
            }
            out[key] = r
        }
    }
    try wr("out/\(LANG)/recv2.json", out)
}

func outcome(_ o: ReceiveOutcome) -> [String: Any] {
    switch o {
    case .delivered(let m): return ["kind": "delivered", "messageId": m.messageId]
    case .duplicate(_, let id): return ["kind": "duplicate", "messageId": id]
    case .quarantined(let e, _): return ["kind": "quarantined", "code": e.code.rawValue, "message": e.message]
    case .retryable(let e): return ["kind": "retryable", "code": e.code.rawValue, "message": e.message]
    }
}

func persist() async throws {
    var out: [String: Any] = [:]
    for s in SCHEMES {
        var r: [String: Any] = [:]
        var receives: [String: Any] = [:]
        do {
            let me = try identity(LANG, s, rx: true)
            let store = try FileStore(directory: url("stores/\(LANG)-\(s.rawValue)"))
            let peers = try PeerStore(store: store)
            for S in LANGS { _ = try await peers.pinRegistrationFile(regFile(idFile(S, s))) }
            let handed = Counter()
            let inbox = try await Inbox.open(identity: me, store: store, peers: peers) { _ in handed.inc() }
            for S in LANGS {
                let m = try rd("msgs/m1/\(S)-\(LANG)-\(s.rawValue).json")
                if let e = m["error"] { throw NSError(domain: "sender \(S) failed: \(e)", code: 1) }
                let text = try data(m["text"]!), rfq = try data(m["rfq"]!)
                receives[S] = [
                    "text": outcome(try await inbox.receive(text, source: .direct)),
                    "rfq": outcome(try await inbox.receive(rfq, source: .direct)),
                    "textAgain": outcome(try await inbox.receive(text, source: .direct)),
                ]
            }
            await inbox.close()
            r["handed"] = handed.value
        } catch {
            r["error"] = fail(error)
        }
        r["receives"] = receives
        out[s.rawValue] = r
    }
    try wr("out/\(LANG)/persist.json", out)
}

let SNAP_KEYS = ["conversationId", "threadId", "localAceId", "peerAceId", "state", "history"]

func load() async throws {
    var out: [String: Any] = [:]
    let fm = FileManager.default
    for R in LANGS {
        for s in SCHEMES {
            let key = "\(R)-\(s.rawValue)"
            var r: [String: Any] = [:]
            do {
                let src = url("stores/\(key)"), dst = url("tmp/\(LANG)/\(key)")
                try? fm.removeItem(at: dst)
                try fm.createDirectory(at: dst.deletingLastPathComponent(), withIntermediateDirectories: true)
                try fm.copyItem(at: src, to: dst)
                let raw = try Data(contentsOf: src.appendingPathComponent("replay.json"))
                r["replay"] = attempt {
                    let st = try ReplayState(json: raw)
                    let bytes = try ReplayDetector(state: st).exportState().jsonData()
                    return ["identical": bytes == raw, "reexport": String(decoding: bytes, as: UTF8.self), "entries": st.entries.count]
                }
                var threads: [Any] = []
                let tdir = src.appendingPathComponent("threads")
                let files = ((try? fm.contentsOfDirectory(atPath: tdir.path)) ?? []).filter { $0.hasSuffix(".json") }.sorted()
                for f in files {
                    threads.append(attempt {
                        let rec = try parseJSON(Data(contentsOf: tdir.appendingPathComponent(f))) as! [String: Any]
                        var snapD: [String: Any] = [:]
                        for k in SNAP_KEYS { snapD[k] = rec[k] }
                        let snap = try JSONDecoder().decode(ThreadSnapshot.self, from: data(snapD))
                        let m = try ThreadStateMachine(state: [snap], localAceId: snap.localAceId)
                        return ["file": f, "original": snapD, "exported": try encodable(m.exportState()[0]),
                                "state": m.getState(conversationId: snap.conversationId, threadId: snap.threadId).rawValue]
                    })
                }
                r["threads"] = threads
                let me = try identity(R, s, rx: true)
                let store = try FileStore(directory: dst)
                r["threadStore"] = attempt {
                    let list = try ThreadStore(store: store, localAceId: me.getACEId()).list()
                    return ["count": list.count, "states": list.map(\.state.rawValue).sorted()]
                }
                let peers = try PeerStore(store: store)
                r["peers"] = await attemptAsync {
                    var got: [String: Any] = [:]
                    for S in LANGS {
                        let p = try await peers.get(idFile(S, s)["aceId"] as! String)
                        got[S] = p.map(peerSummary) ?? NSNull()
                    }
                    return ["peers": got]
                }
                r["inboxReopen"] = await attemptAsync {
                    let handed = Counter()
                    let inbox = try await Inbox.open(identity: me, store: store, peers: peers) { _ in handed.inc() }
                    let m = try rd("msgs/m1/\(LANGS[0])-\(R)-\(s.rawValue).json")
                    let dup = outcome(try await inbox.receive(try data(m["rfq"]!), source: .direct))
                    await inbox.close()
                    return ["handedOnOpen": handed.value, "duplicate": dup]
                }
            } catch {
                r["error"] = fail(error)
            }
            out[key] = r
        }
    }
    try wr("out/\(LANG)/load.json", out)
}

// MARK: - 6, 7: principal

final class Handed: @unchecked Sendable {
    private let lock = NSLock()
    private var m: [String: [String: Any]] = [:]
    func put(_ p: ParsedMessage) { let s = try? summary(p); lock.lock(); m[p.messageId] = s; lock.unlock() }
    func get(_ id: String) -> Any { lock.lock(); defer { lock.unlock() }; return m[id] ?? NSNull() }
}

/// A `requests/` record as loaded (`NSNull` when absent).
func ledgerJSON(_ r: RequestRecord?) -> Any {
    guard let r else { return NSNull() }
    let decision: Any = r.decision.map { ["messageId": $0.messageId, "outcome": $0.outcome, "timestamp": $0.timestamp] as [String: Any] } ?? NSNull()
    return ["conversationId": r.conversationId, "messageId": r.messageId, "to": r.to, "sentAt": r.sentAt,
            "expiresAt": r.expiresAt as Any? ?? NSNull(), "decision": decision] as [String: Any]
}
func message(_ v: Any, _ k: String) -> [String: Any] { (v as! [String: Any])[k] as! [String: Any] }

func pverify() throws {
    var out: [String: Any] = [:]
    for src in LANGS {
        for s in SCHEMES {
            var r: [String: Any] = [:]
            for (role, rx) in [("delegate", false), ("controller", true)] {
                let d = try idFile(src, s, rx: rx)
                let spk = try ACEBase64.decode(d["signingPublicKey"] as! String)
                let otherKey = try ACEBase64.decode(idFile(src, s, rx: !rx)["signingPublicKey"] as! String)
                r[role] = [
                    "record": attempt {
                        let p = try validatePrincipalRecord(PrincipalRecord(json: data(d["principal"]!)), subjectSigningPublicKey: spk, now: now())
                        return ["record": try parseJSON(p.jsonData()), "payloadHex": hex(principalPayload(p, subjectSigningPublicKey: spk)),
                                "signDataHex": hex(try principalSignData(p, subjectSigningPublicKey: spk))]
                    },
                    "regFile": attempt {
                        let p = try verifyRegistrationFile(RegistrationFile(json: data(d["registrationFilePrincipal"]!))).principal
                        return ["principal": try p.map { try parseJSON($0.jsonData()) } ?? NSNull()]
                    },
                    "regRequest": attempt {
                        let v = try verifyRegistrationRequest(data(d["registrationRequestPrincipal"]!))
                        return ["requestDigest": v.requestDigest, "aceId": v.peer.aceId]
                    },
                    "wrongSubject": attempt {
                        ["x": try validatePrincipalRecord(PrincipalRecord(json: data(d["principal"]!)), subjectSigningPublicKey: otherKey, now: now()).account]
                    },
                ]
            }
            let f = try rd("fixed/\(src)-\(s.rawValue).json")
            r["fixed"] = attempt {
                let subject = try ACEBase64.decode(FIXED_SUBJECT)
                let p = try validatePrincipalRecord(PrincipalRecord(json: data(f["record"]!)), subjectSigningPublicKey: subject, now: FIXED_ISSUED_AT)
                return ["payloadHex": hex(principalPayload(p, subjectSigningPublicKey: subject)),
                        "signDataHex": hex(try principalSignData(p, subjectSigningPublicKey: subject))]
            }
            out["\(src)-\(s.rawValue)"] = r
        }
    }
    try wr("out/\(LANG)/pverify.json", out)
}

/// Delegate `<LANG>-<s>` sends a `request` and a `report` to every controller through its Outbox; delivery writes `requests/`.
func psend() async throws {
    var out: [String: Any] = [:]
    for s in SCHEMES {
        let store: FileStore, outbox: Outbox
        do {
            store = try FileStore(directory: url("pstores/\(LANG)-\(s.rawValue)"))
            outbox = try await Outbox.open(identity: identity(LANG, s), store: store)
        } catch {
            for R in LANGS { try wr("msgs/p1/\(LANG)-\(R)-\(s.rawValue).json", ["error": fail(error)]) }
            continue
        }
        for R in LANGS {
            let key = "\(LANG)-\(R)-\(s.rawValue)"
            do {
                let peer = try principalPeer(R, s, rx: true)
                func send(_ type: MessageType, _ body: [String: JSONValue]) async throws -> Any {
                    let p = try await outbox.stage(recipient: peer, type: type, body: body)
                    return try parseJSON(await outbox.deliver(p.requestId) { m in m.jsonData() })
                }
                let request = try await send(.request, REQ)
                let report = try await send(.report, REP)
                let req = request as! [String: Any]
                out[key] = ["ledger": ledgerJSON(try loadRequestRecord(store, conversationId: req["conversationId"] as! String,
                                                                       messageId: req["messageId"] as! String))]
                try wr("msgs/p1/\(key).json", ["requestBody": try anyJSON(REQ), "reportBody": try anyJSON(REP),
                                               "request": request, "report": report])
            } catch {
                try wr("msgs/p1/\(key).json", ["error": fail(error)])
            }
        }
    }
    try wr("out/\(LANG)/psend.json", out)
}

/// Controller `<LANG>-<s>-rx` receives every delegate's request and report through an Inbox opened with the shared
/// principal, then answers with two different decisions and a report.
func precv() async throws {
    var out: [String: Any] = [:]
    for s in SCHEMES {
        let me: SoftwareIdentity, inbox: Inbox
        let handed = Handed()
        do {
            me = try identity(LANG, s, rx: true)
            let store = try FileStore(directory: url("pstores/\(LANG)-\(s.rawValue)-rx"))
            let peers = try PeerStore(store: store)
            for S in LANGS {
                _ = try await peers.pinRegistrationFile(RegistrationFile(json: data(idFile(S, s)["registrationFilePrincipal"]!)))
            }
            inbox = try await Inbox.open(identity: me, store: store, peers: peers, onMessage: { handed.put($0) }, principal: inboxPrincipal(s))
        } catch {
            for S in LANGS { out["\(S)-\(LANG)-\(s.rawValue)"] = ["error": fail(error)] }
            continue
        }
        for S in LANGS {
            let key = "\(S)-\(LANG)-\(s.rawValue)"
            var r: [String: Any] = [:]
            do {
                let m = try rd("msgs/p1/\(key).json")
                if let e = m["error"] { throw NSError(domain: "sender failed: \(e)", code: 1) }
                let peer = try principalPeer(S, s)
                for k in ["request", "report"] {
                    r[k] = outcome(try await inbox.receive(try data(m[k]!), source: .direct))
                    r["\(k)Parsed"] = handed.get(message(m, k)["messageId"] as! String)
                }
                r["noContext"] = attempt { try parseFresh(m["report"]!, me, peer) }
                let req = message(m, "request")
                let bodies = decisionBodies(req["messageId"] as! String, req["conversationId"] as! String)
                var msgs: [String: Any] = [:]
                for (k, b) in bodies { msgs[k] = try anyJSON(b) }
                for (k, type) in [("decision", MessageType.decision), ("decision2", .decision), ("report", .report)] {
                    let env = try createMessage(sender: me, recipient: peer, type: type, body: bodies["\(k)Body"]!,
                                                threads: ThreadStateMachine(localAceId: me.getACEId()))
                    msgs[k] = try parseJSON(env.jsonData())
                }
                try wr("msgs/p2/\(LANG)-\(S)-\(s.rawValue).json", msgs)
            } catch {
                r["error"] = fail(error)
            }
            out[key] = r
        }
        await inbox.close()
    }
    try wr("out/\(LANG)/precv.json", out)
}

/// Delegate `<LANG>-<s>` receives each controller's decisions and report through an Inbox on its Outbox store: the
/// first decision fills the request, a replay is a duplicate, the second different decision is `bad_reference`.
func pdecide() async throws {
    var out: [String: Any] = [:]
    for s in SCHEMES {
        let store: FileStore, inbox: Inbox
        let handed = Handed()
        do {
            let me = try identity(LANG, s)
            store = try FileStore(directory: url("pstores/\(LANG)-\(s.rawValue)"))
            let peers = try PeerStore(store: store)
            for R in LANGS {
                _ = try await peers.pinRegistrationFile(RegistrationFile(json: data(idFile(R, s, rx: true)["registrationFilePrincipal"]!)))
            }
            inbox = try await Inbox.open(identity: me, store: store, peers: peers, onMessage: { handed.put($0) }, principal: inboxPrincipal(s))
        } catch {
            for R in LANGS { out["\(R)-\(LANG)-\(s.rawValue)"] = ["error": fail(error)] }
            continue
        }
        for R in LANGS {
            let key = "\(R)-\(LANG)-\(s.rawValue)"
            var r: [String: Any] = [:]
            do {
                let m = try rd("msgs/p2/\(key).json")
                let req = message(try rd("msgs/p1/\(LANG)-\(R)-\(s.rawValue).json"), "request")
                for (k, env) in [("decision", "decision"), ("decisionAgain", "decision"), ("decision2", "decision2"), ("report", "report")] {
                    r[k] = outcome(try await inbox.receive(try data(m[env]!), source: .direct))
                }
                r["decisionParsed"] = handed.get(message(m, "decision")["messageId"] as! String)
                r["reportParsed"] = handed.get(message(m, "report")["messageId"] as! String)
                r["ledger"] = attempt {
                    ["record": ledgerJSON(try loadRequestRecord(store, conversationId: req["conversationId"] as! String,
                                                                messageId: req["messageId"] as! String))]
                }
            } catch {
                r["error"] = fail(error)
            }
            out[key] = r
        }
        await inbox.close()
    }
    try wr("out/\(LANG)/pdecide.json", out)
}

/// Every delegate's `requests/` record of its request to this language, loaded here.
func pload() throws {
    var out: [String: Any] = [:]
    for S in LANGS {
        for s in SCHEMES {
            let key = "\(S)-\(LANG)-\(s.rawValue)"
            out[key] = attempt {
                let req = message(try rd("msgs/p1/\(key).json"), "request")
                let store = try FileStore(directory: url("pstores/\(S)-\(s.rawValue)"))
                return ["record": ledgerJSON(try loadRequestRecord(store, conversationId: req["conversationId"] as! String,
                                                                   messageId: req["messageId"] as! String))]
            }
        }
    }
    try wr("out/\(LANG)/pload.json", out)
}

switch phase {
case "gen": try gen()
case "verify": try verify()
case "send1": try send1()
case "recv1": try recv1()
case "recv2": try recv2()
case "persist": try await persist()
case "load": try await load()
case "pverify": try pverify()
case "psend": try await psend()
case "precv": try await precv()
case "pdecide": try await pdecide()
case "pload": try pload()
default: fatalError("unknown phase \(phase)")
}

// ACE cross-SDK interop harness — Swift side.
// Usage: ACEInterop <phase> <workdir>
// Phases: gen | verify | send1 | recv1 | recv2 | persist | load. See ../../../README.md.
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
func obj(_ s: String) -> JSONObject { try! JSONSerialization.jsonObject(with: Data(s.utf8)) as! JSONObject }

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
func textBody(_ s: String, _ r: String, _ sch: String) -> JSONObject {
    ["message": "hello \(s)→\(r) (\(sch)) héllo 世界 / \"q\" \\ ✓"]
}
nonisolated(unsafe) let RFQ = obj(#"{"need":"Translate 500 words EN→FR","maxPrice":"10.50","currency":"USDC","ttl":3600}"#)
nonisolated(unsafe) let OFFER = obj(#"{"price":"9.75","currency":"USDC","terms":"delivery in 24h / net","ttl":600}"#)

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
func envelope(_ v: Any) throws -> ACEMessage { try decodeEnvelope(data(v)) }
func summary(_ p: ParsedMessage) throws -> [String: Any] {
    ["messageId": p.messageId, "from": p.from, "to": p.to, "conversationId": p.conversationId,
     "type": p.type.rawValue, "threadId": p.threadId as Any? ?? NSNull(), "timestamp": p.timestamp,
     "body": try parseJSON(data(p.body))]
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
        let reg = try id.toRegistrationFile(name: "Agent \(LANG) \(s.rawValue)", endpoint: "https://\(LANG).example/ace")
        let req = try createRegistrationRequest(identity: id, profile: .replace(profile(LANG)), timestamp: ts)
        try wr("ids/\(LANG)-\(s.rawValue)\(suffix).json", [
            "lang": LANG, "scheme": s.rawValue, "export": try encodable(id.exportPrivateKey()), "aceId": id.getACEId(),
            "address": id.getAddress(), "signingPublicKey": b64(id.getSigningPublicKey()),
            "encryptionPublicKey": b64(id.getEncryptionPublicKey()),
            "registrationFile": try encodable(reg), "registrationRequest": try parseJSON(req.jsonData()), "auth": auth,
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
                let reg = try idn.toRegistrationFile(name: rf["name"] as! String, endpoint: rf["endpoint"] as! String)
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
                try wr("msgs/m1/\(key).json", ["threadId": threadId, "textBody": tb, "rfqBody": RFQ,
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
                           ["threadId": threadId, "offerBody": OFFER, "offer": try parseJSON(offer.jsonData())])
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
                    "text": outcome(await inbox.receive(text, source: .direct)),
                    "rfq": outcome(await inbox.receive(rfq, source: .direct)),
                    "textAgain": outcome(await inbox.receive(text, source: .direct)),
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
                    let dup = outcome(await inbox.receive(try data(m["rfq"]!), source: .direct))
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

switch phase {
case "gen": try gen()
case "verify": try verify()
case "send1": try send1()
case "recv1": try recv1()
case "recv2": try recv2()
case "persist": try await persist()
case "load": try await load()
default: fatalError("unknown phase \(phase)")
}

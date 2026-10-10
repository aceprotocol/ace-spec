// ACE cross-SDK interop harness — TypeScript side.
// Usage: node interop.ts <phase> <workdir>   (Node >= 22.18 strips types natively; or use tsx)
// Phases: gen | verify | send1 | recv1 | recv2 | persist | load | pverify | psend | precv | pdecide | pload. See ../README.md.
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';
import * as ace from '../../../sdk-ts/dist/index.js';
import { FileStore } from '../../../sdk-ts/dist/node.js';
import { canonicalStateBytes } from '../../../sdk-ts/dist/encoding.js';

const LANG = 'ts';
const LANGS = ['ts', 'py', 'swift'];
const SCHEMES = ['ed25519', 'secp256k1'];
const [phase, W] = process.argv.slice(2);
if (!phase || !W) throw new Error('usage: interop.ts <phase> <workdir>');

const P = (...p: string[]) => path.join(W, ...p);
const rd = (p: string): any => JSON.parse(fs.readFileSync(P(p), 'utf8'));
const exists = (p: string) => fs.existsSync(P(p));
function wr(p: string, v: unknown) {
  fs.mkdirSync(path.dirname(P(p)), { recursive: true });
  fs.writeFileSync(P(p), JSON.stringify(v, null, 1));
}
const now = () => Math.floor(Date.now() / 1000);
const b64 = (u: Uint8Array) => ace.toBase64(u);
/** The wire bytes of an envelope (`Inbox.receive` takes raw message bytes). */
const wire = (envelope: unknown) => new TextEncoder().encode(JSON.stringify(envelope));
function fail(e: any) {
  return { ok: false, code: e?.code ?? 'exception', message: String(e?.message ?? e) };
}
async function attempt(fn: () => any): Promise<any> {
  try {
    const r = await fn();
    return { ok: true, ...(r ?? {}) };
  } catch (e) {
    return fail(e);
  }
}

const AUTH: Record<string, any> = {
  listen: { action: 'listen', since: '-' },
  inbox: { action: 'inbox', since: '1700000000000-0', limit: 50 },
  unregister: { action: 'unregister' },
  intent: { action: 'intent', need: 'Translate EN→FR', tags: ['nlp', 'fr'], ext: { 'urn:ace:commerce:1': { maxPrice: '10', currency: 'USDC' } }, ttl: 3600 },
};
const profile = (lang: string) => ({
  name: `Agent ${lang} é`, description: 'interop / matrix', tags: ['interop', 'ace'],
  capabilities: ['translate'], endpoint: `https://${lang}.example/ace`, ext: { 'urn:ace:commerce:1': { pricing: { currency: 'USDC', maxAmount: '10' } } },
});
const textBody = (s: string, r: string, sch: string) => ({ message: `hello ${s}→${r} (${sch}) héllo 世界 / "q" \\ ✓` });
const RFQ = { need: 'Translate 500 words EN→FR', maxPrice: '10.50', currency: 'USDC', ttl: 3600 };
const OFFER = { price: '9.75', currency: 'USDC', terms: 'delivery in 24h / net', ttl: 600 };

// Principal fixtures (same values in every language; 09-principal). One shared CAIP-10 account; the controller
// signer (owner key) of scheme s is a v4 test-vectors agent (ed25519: alice, secp256k1: bob). `<lang>-<s>` is a
// delegate (["delegate"]), `<lang>-<s>-rx` a controller (["controller"]).
const VECTORS = JSON.parse(fs.readFileSync(
  process.env.ACE_VECTORS || path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'test-vectors.json'), 'utf8'));
const ACCOUNT = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp:InteropOwner1111111111111111111111111111111';
const OWNER_AGENT: Record<string, string> = { ed25519: 'alice', secp256k1: 'bob' };
const SCOPE = 'interop ✓';
// Deterministic record: same signer, delegate subject, issuedAt and expiresAt in every language.
const FIXED_SUBJECT: string = VECTORS.vectors.principalRules.senders.agent.signingPublicKey;
const FIXED_ISSUED_AT: number = VECTORS.vectors.principal.now;
const REQ = { action: 'x402.pay', summary: 'Pay 1 USDC ✓', amount: '1', currency: 'USDC', details: { payTo: 'x', network: 'solana' }, ttl: 600 };
const REP = { action: 'copy.run', summary: 'copied 2 trades', outcome: 'ok', proof: { txHash: '0x01' } };
const owner = (s: string) => {
  const a = VECTORS.agents[OWNER_AGENT[s]];
  return ace.SoftwareIdentity.fromExport({ scheme: a.scheme, signingPrivateKey: a.signingPrivateKey, encryptionPrivateKey: a.encryptionPrivateKey });
};
const ownerKey = (s: string) => ({ scheme: s as any, publicKey: VECTORS.agents[OWNER_AGENT[s]].signingPublicKey as string });
/** `Inbox.open` principal: the shared account, this scheme's owner key as `selfSigner`, the other one as trusted. */
const inboxPrincipal = (s: string) => ({ account: ACCOUNT, selfSigner: ownerKey(s), trustedSigners: SCHEMES.filter((x) => x !== s).map(ownerKey) });
const decisionBodies = (rid: string, conv: string): Record<string, any> => ({
  decisionBody: { requestId: rid, outcome: 'approve', result: { payload: 'signed ✓' } },
  decision2Body: { requestId: rid, outcome: 'deny', reason: 'changed my mind ✓' },
  reportBody: { action: 'x402.pay', summary: 'paid 1 USDC ✓', outcome: 'ok', requestId: rid, ref: { conversationId: conv, messageId: rid } },
});
const hex = (u: Uint8Array) => Buffer.from(u).toString('hex');

// `<lang>-<scheme>` sends; a second identity `<lang>-<scheme>-rx` receives (so ts→ts uses two parties).
const rx = (s: string) => `${s}-rx`;
const identity = (lang: string, s: string) => ace.SoftwareIdentity.fromExport(rd(`ids/${lang}-${s}.json`).export);
const peerOf = (lang: string, s: string) => ace.verifyRegistrationFile(rd(`ids/${lang}-${s}.json`).registrationFile);
const principalPeer = (lang: string, s: string) => ace.verifyRegistrationFile(rd(`ids/${lang}-${s}.json`).registrationFilePrincipal);
const summary = (p: any) => ({
  messageId: p.messageId, from: p.from, to: p.to, conversationId: p.conversationId,
  type: p.type, schemaDigest: p.schemaDigest, threadId: p.threadId ?? null, timestamp: p.timestamp, body: p.body,
});
const peerSummary = (p: any) => ({
  aceId: p.aceId, scheme: p.scheme, signingPublicKey: b64(p.signingPublicKey),
  encryptionPublicKey: b64(p.encryptionPublicKey), address: p.address, source: p.source,
});
const parseFresh = (env: any, me: any, peer: any) =>
  ace.parseMessage(ace.decodeEnvelope(env), me, peer, {
    threads: new ace.ThreadStateMachine({ localAceId: me.getACEId() }), replay: new ace.ReplayDetector(),
  });

async function gen() {
  for (const s of [...SCHEMES, ...SCHEMES.map(rx)]) {
    const id = await ace.SoftwareIdentity.generate(s.replace('-rx', '') as any);
    const ts = now();
    const auth: Record<string, any> = {};
    for (const [k, req] of Object.entries(AUTH)) auth[k] = { headers: await ace.createAuthHeaders(id, req, ts) };
    const principal = await ace.createPrincipalRecord(ace.principalSignerFromIdentity(owner(s.replace('-rx', ''))), {
      subjectSigningPublicKey: id.getSigningPublicKey(), account: ACCOUNT, roles: s.endsWith('-rx') ? ['controller'] : ['delegate'],
      expiresAt: ts + 3600, issuedAt: ts,
    });
    wr(`ids/${LANG}-${s}.json`, {
      lang: LANG, scheme: s.replace('-rx', ''), export: id.exportPrivateKey(), aceId: id.getACEId(), address: id.getAddress(),
      signingPublicKey: b64(id.getSigningPublicKey()), encryptionPublicKey: b64(id.getEncryptionPublicKey()),
      registrationFile: await ace.createRegistrationFile(id, { name: `Agent ${LANG} ${s}`, endpoint: `https://${LANG}.example/ace` }),
      registrationRequest: await ace.createRegistrationRequest(id, profile(LANG) as any, ts),
      auth,
      principal,
      registrationFilePrincipal: await ace.createRegistrationFile(id, { name: `Agent ${LANG} ${s}`, endpoint: `https://${LANG}.example/ace`, principal }),
      registrationRequestPrincipal: await ace.createRegistrationRequest(id, { ...profile(LANG), principal } as any, ts),
    });
  }
  for (const s of SCHEMES) {
    const subject = ace.fromBase64(FIXED_SUBJECT);
    const record = await ace.createPrincipalRecord(ace.principalSignerFromIdentity(owner(s)), {
      subjectSigningPublicKey: subject, account: ACCOUNT, roles: ['delegate'], scope: SCOPE,
      expiresAt: FIXED_ISSUED_AT + 3600, issuedAt: FIXED_ISSUED_AT,
    });
    wr(`fixed/${LANG}-${s}.json`, {
      record, payloadHex: hex(ace.principalPayload(record, subject)), signDataHex: hex(ace.principalSignData(record, subject)),
    });
  }
}

async function verify() {
  const out: Record<string, any> = {};
  for (const src of LANGS) for (const s of SCHEMES) {
    const d = rd(`ids/${src}-${s}.json`);
    const r: any = {};
    r.import = await attempt(async () => {
      const idn = ace.SoftwareIdentity.fromExport(d.export);
      return {
        aceId: idn.getACEId(), address: idn.getAddress(), scheme: idn.getSigningScheme(),
        signingPublicKey: b64(idn.getSigningPublicKey()), encryptionPublicKey: b64(idn.getEncryptionPublicKey()),
        reexport: idn.exportPrivateKey(),
        registrationFile: await ace.createRegistrationFile(idn, { name: d.registrationFile.name, endpoint: d.registrationFile.endpoint, timestamp: d.registrationFile.registeredAt }),
      };
    });
    let peer: any = null;
    r.regFile = await attempt(() => { peer = ace.verifyRegistrationFile(d.registrationFile); return peerSummary(peer); });
    r.regRequest = await attempt(() => {
      const v = ace.verifyRegistrationRequest(d.registrationRequest);
      return { requestDigest: v.requestDigest, peer: peerSummary(v.peer) };
    });
    const signer = { aceId: d.aceId, scheme: d.scheme, signingPublicKey: peer ? peer.signingPublicKey : ace.fromBase64(d.signingPublicKey) };
    r.auth = {};
    for (const [k, req] of Object.entries(AUTH)) {
      r.auth[k] = await attempt(() => { ace.verifyAuthHeaders(ace.parseAuthHeaders(d.auth[k].headers), req, signer); });
    }
    r.authWrongRequest = await attempt(() => { ace.verifyAuthHeaders(ace.parseAuthHeaders(d.auth.listen.headers), AUTH.inbox, signer); });
    out[`${src}-${s}`] = r;
  }
  wr(`out/${LANG}/verify.json`, out);
}

async function send1() {
  for (const R of LANGS) for (const s of SCHEMES) {
    const key = `${LANG}-${R}-${s}`;
    try {
      const me = identity(LANG, s);
      const peer = peerOf(R, rx(s));
      const threads = new ace.ThreadStateMachine({ localAceId: me.getACEId() });
      const threadId = `deal/${key}/✓`;
      const tb = textBody(LANG, R, s);
      const text = await ace.createMessage({ sender: me, recipient: peer, type: 'text', body: tb, threads });
      const custom = await ace.createMessage({ sender: me, recipient: peer, type: 'urn:example:task:1', schemaDigest: 'ab'.repeat(32), body: { task: '你好' }, threadId: 'private' });
      const rfq = await ace.createMessage({ sender: me, recipient: peer, type: 'rfq', threadId, body: RFQ, threads });
      wr(`msgs/m1/${key}.json`, { threadId, textBody: tb, rfqBody: RFQ, text, rfq, custom });
      wr(`priv/${LANG}/threads-${R}-${s}.json`, threads.exportState());
    } catch (e) {
      wr(`msgs/m1/${key}.json`, { error: fail(e) });
    }
  }
}

async function recv1() {
  const out: Record<string, any> = {};
  for (const S of LANGS) for (const s of SCHEMES) {
    const key = `${S}-${LANG}-${s}`;
    const r: any = {};
    out[key] = r;
    try {
      const m = rd(`msgs/m1/${key}.json`);
      if (m.error) throw new Error(`sender failed: ${JSON.stringify(m.error)}`);
      const t = rd(`msgs/tampered/${key}.json`);
      const me = identity(LANG, rx(s));
      const peer = peerOf(S, s);
      r.tamperedText = await attempt(async () => summary(await parseFresh(t.text, me, peer)));
      r.tamperedRfq = await attempt(async () => summary(await parseFresh(t.rfq, me, peer)));
      const threads = new ace.ThreadStateMachine({ localAceId: me.getACEId() });
      const replay = new ace.ReplayDetector();
      const parse = async (env: any) => summary(await ace.parseMessage(ace.decodeEnvelope(env), me, peer, { threads, replay }));
      r.custom = await attempt(() => parse(m.custom));
      r.text = await attempt(() => parse(m.text));
      r.rfq = await attempt(() => parse(m.rfq));
      r.replayAgain = await attempt(() => parse(m.text));
      const conv = m.rfq.conversationId;
      r.stateAfterRfq = threads.getState(conv, m.threadId);
      r.reply = await attempt(async () => {
        const offer = await ace.createMessage({ sender: me, recipient: peer, type: 'offer', threadId: m.threadId, body: OFFER, threads });
        wr(`msgs/m2/${LANG}-${S}-${s}.json`, { threadId: m.threadId, offerBody: OFFER, offer });
        return {};
      });
      r.stateAfterOffer = threads.getState(conv, m.threadId);
    } catch (e) {
      r.error = fail(e);
    }
  }
  wr(`out/${LANG}/recv1.json`, out);
}

async function recv2() {
  const out: Record<string, any> = {};
  for (const R of LANGS) for (const s of SCHEMES) {
    const key = `${R}-${LANG}-${s}`;
    const r: any = {};
    out[key] = r;
    try {
      if (!exists(`msgs/m2/${key}.json`)) throw new Error('no offer from receiver');
      const m = rd(`msgs/m2/${key}.json`);
      const me = identity(LANG, s);
      const threads = ace.ThreadStateMachine.fromState(rd(`priv/${LANG}/threads-${R}-${s}.json`), { localAceId: me.getACEId() });
      const replay = new ace.ReplayDetector();
      r.offer = await attempt(async () => summary(await ace.parseMessage(ace.decodeEnvelope(m.offer), me, peerOf(R, rx(s)), { threads, replay })));
      r.state = threads.getState(m.offer.conversationId, m.threadId);
      r.snapshot = threads.getSnapshot(m.offer.conversationId, m.threadId);
    } catch (e) {
      r.error = fail(e);
    }
  }
  wr(`out/${LANG}/recv2.json`, out);
}

const outcome = (o: any) =>
  o.kind === 'delivered' ? { kind: o.kind, messageId: o.message.messageId }
    : o.kind === 'duplicate' ? { kind: o.kind, messageId: o.messageId }
      : { kind: o.kind, code: o.error?.code, message: o.error?.message };

async function persist() {
  const out: Record<string, any> = {};
  for (const s of SCHEMES) {
    const r: any = { receives: {} };
    out[s] = r;
    try {
      const me = identity(LANG, rx(s));
      const store = new FileStore(P(`stores/${LANG}-${s}`));
      const peers = new ace.PeerStore({ store });
      for (const S of LANGS) await peers.pinRegistrationFile(rd(`ids/${S}-${s}.json`).registrationFile);
      let handed = 0;
      const inbox = await ace.Inbox.open({ commerce: true, identity: me, store, peers, onMessage: () => { handed++; } });
      try {
        for (const S of LANGS) {
          const m = rd(`msgs/m1/${S}-${LANG}-${s}.json`);
          if (m.error) throw new Error(`sender ${S} failed: ${JSON.stringify(m.error)}`);
          r.receives[S] = {
            text: outcome(await inbox.receive(wire(m.text))),
            rfq: outcome(await inbox.receive(wire(m.rfq))),
            textAgain: outcome(await inbox.receive(wire(m.text))),
          };
        }
      } finally {
        await inbox.close();
      }
      r.handed = handed;
    } catch (e) {
      r.error = fail(e);
    }
  }
  wr(`out/${LANG}/persist.json`, out);
}

function snapOf(rec: any) {
  const { conversationId, threadId, localAceId, peerAceId, state, history } = rec;
  return { conversationId, threadId, localAceId, peerAceId, state, history };
}

async function load() {
  const out: Record<string, any> = {};
  for (const R of LANGS) for (const s of SCHEMES) {
    const key = `${R}-${s}`;
    const r: any = {};
    out[key] = r;
    try {
      const src = P(`stores/${key}`);
      const dst = P(`tmp/${LANG}/${key}`);
      fs.rmSync(dst, { recursive: true, force: true });
      fs.cpSync(src, dst, { recursive: true });
      const raw = fs.readFileSync(path.join(src, 'replay.json'));
      r.replay = await attempt(() => {
        const st = JSON.parse(raw.toString('utf8'));
        const bytes = canonicalStateBytes(ace.ReplayDetector.fromState(st).exportState());
        return { identical: Buffer.compare(Buffer.from(bytes), raw) === 0, reexport: Buffer.from(bytes).toString('utf8'), entries: st.entries.length };
      });
      r.threads = [];
      const tdir = path.join(src, 'threads');
      for (const f of fs.existsSync(tdir) ? fs.readdirSync(tdir).filter((x) => x.endsWith('.json')).sort() : []) {
        r.threads.push(await attempt(() => {
          const rec = JSON.parse(fs.readFileSync(path.join(tdir, f), 'utf8'));
          const m = ace.ThreadStateMachine.fromState([snapOf(rec) as any], { localAceId: rec.localAceId });
          return { file: f, original: snapOf(rec), exported: m.exportState()[0], state: m.getState(rec.conversationId, rec.threadId) };
        }));
      }
      const me = identity(R, rx(s));
      const store = new FileStore(dst);
      r.threadStore = await attempt(async () => {
        const list = await new ace.ThreadStore({ store, localAceId: me.getACEId() }).list();
        return { count: list.length, states: list.map((x: any) => x.state).sort() };
      });
      const peers = new ace.PeerStore({ store });
      r.peers = await attempt(async () => {
        const got: Record<string, any> = {};
        for (const S of LANGS) {
          const p = await peers.get(rd(`ids/${S}-${s}.json`).aceId);
          got[S] = p ? peerSummary(p) : null;
        }
        return { peers: got };
      });
      r.inboxReopen = await attempt(async () => {
        let handed = 0;
        const inbox = await ace.Inbox.open({ commerce: true, identity: me, store, peers, onMessage: () => { handed++; } });
        try {
          const m = rd(`msgs/m1/${LANGS[0]}-${R}-${s}.json`);
          const dup = outcome(await inbox.receive(wire(m.rfq)));
          return { handedOnOpen: handed, duplicate: dup };
        } finally {
          await inbox.close();
        }
      });
    } catch (e) {
      r.error = fail(e);
    }
  }
  wr(`out/${LANG}/load.json`, out);
}

// --- 6, 7: principal ---------------------------------------------------------------------

async function pverify() {
  const out: Record<string, any> = {};
  for (const src of LANGS) for (const s of SCHEMES) {
    const r: any = {};
    out[`${src}-${s}`] = r;
    for (const [role, suffix, other] of [['delegate', '', '-rx'], ['controller', '-rx', '']]) {
      const d = rd(`ids/${src}-${s}${suffix}.json`);
      const spk = ace.fromBase64(d.signingPublicKey);
      const otherKey = ace.fromBase64(rd(`ids/${src}-${s}${other}.json`).signingPublicKey);
      r[role] = {
        record: await attempt(() => {
          const p = ace.validatePrincipalRecord(d.principal, spk, now());
          return { record: p, payloadHex: hex(ace.principalPayload(p, spk)), signDataHex: hex(ace.principalSignData(p, spk)) };
        }),
        regFile: await attempt(() => ({ principal: ace.verifyRegistrationFile(d.registrationFilePrincipal).principal ?? null })),
        regRequest: await attempt(() => {
          const v = ace.verifyRegistrationRequest(d.registrationRequestPrincipal);
          return { requestDigest: v.requestDigest, aceId: v.peer.aceId };
        }),
        wrongSubject: await attempt(() => ({ x: ace.validatePrincipalRecord(d.principal, otherKey, now()).account })),
      };
    }
    const f = rd(`fixed/${src}-${s}.json`);
    r.fixed = await attempt(() => {
      const subject = ace.fromBase64(FIXED_SUBJECT);
      const p = ace.validatePrincipalRecord(f.record, subject, FIXED_ISSUED_AT);
      return { payloadHex: hex(ace.principalPayload(p, subject)), signDataHex: hex(ace.principalSignData(p, subject)) };
    });
  }
  wr(`out/${LANG}/pverify.json`, out);
}

/** Delegate `<LANG>-<s>` sends a `request` and a `report` to every controller through its Outbox; delivery writes `requests/`. */
async function psend() {
  const out: Record<string, any> = {};
  for (const s of SCHEMES) {
    let store: any, outbox: any;
    try {
      store = new FileStore(P(`pstores/${LANG}-${s}`));
      outbox = await ace.Outbox.open({ commerce: true, identity: identity(LANG, s), store });
    } catch (e) {
      for (const R of LANGS) wr(`msgs/p1/${LANG}-${R}-${s}.json`, { error: fail(e) });
      continue;
    }
    for (const R of LANGS) {
      const key = `${LANG}-${R}-${s}`;
      try {
        const peer = principalPeer(R, rx(s));
        const send = async (type: string, body: any) =>
          outbox.deliver((await outbox.stage({ recipient: peer, type, body })).requestId, async (env: any) => env);
        const request = await send('request', REQ);
        const report = await send('report', REP);
        out[key] = { ledger: await ace.loadRequestRecord(store, request.conversationId, request.messageId) };
        wr(`msgs/p1/${key}.json`, { requestBody: REQ, reportBody: REP, request, report });
      } catch (e) {
        wr(`msgs/p1/${key}.json`, { error: fail(e) });
      }
    }
  }
  wr(`out/${LANG}/psend.json`, out);
}

/** Controller `<LANG>-<s>-rx` receives every delegate's request and report through an Inbox opened with the shared
 * principal, then answers with two different decisions and a report. */
async function precv() {
  const out: Record<string, any> = {};
  for (const s of SCHEMES) {
    let me: any, inbox: any;
    const handed = new Map<string, any>();
    try {
      me = identity(LANG, rx(s));
      const store = new FileStore(P(`pstores/${LANG}-${rx(s)}`));
      const peers = new ace.PeerStore({ store });
      for (const S of LANGS) await peers.pinRegistrationFile(rd(`ids/${S}-${s}.json`).registrationFilePrincipal);
      inbox = await ace.Inbox.open({ commerce: true, identity: me, store, peers, principal: inboxPrincipal(s), onMessage: (m: any) => { handed.set(m.messageId, summary(m)); } });
    } catch (e) {
      for (const S of LANGS) out[`${S}-${LANG}-${s}`] = { error: fail(e) };
      continue;
    }
    try {
      for (const S of LANGS) {
        const key = `${S}-${LANG}-${s}`;
        const r: any = {};
        out[key] = r;
        try {
          const m = rd(`msgs/p1/${key}.json`);
          if (m.error) throw new Error(`sender failed: ${JSON.stringify(m.error)}`);
          const peer = principalPeer(S, s);
          for (const k of ['request', 'report']) {
            r[k] = outcome(await inbox.receive(wire(m[k])));
            r[`${k}Parsed`] = handed.get(m[k].messageId) ?? null;
          }
          r.noContext = await attempt(async () => summary(await parseFresh(m.report, me, peer)));
          const bodies = decisionBodies(m.request.messageId, m.request.conversationId);
          const msgs: Record<string, any> = { ...bodies };
          for (const [k, type] of [['decision', 'decision'], ['decision2', 'decision'], ['report', 'report']]) {
            msgs[k] = await ace.createMessage({ sender: me, recipient: peer, type: type as any, body: bodies[`${k}Body`],
              threads: new ace.ThreadStateMachine({ localAceId: me.getACEId() }) });
          }
          wr(`msgs/p2/${LANG}-${S}-${s}.json`, msgs);
        } catch (e) {
          r.error = fail(e);
        }
      }
    } finally {
      await inbox.close();
    }
  }
  wr(`out/${LANG}/precv.json`, out);
}

/** Delegate `<LANG>-<s>` receives each controller's decisions and report through an Inbox on its Outbox store: the
 * first decision fills the request, a replay is a duplicate, the second different decision is `bad_reference`. */
async function pdecide() {
  const out: Record<string, any> = {};
  for (const s of SCHEMES) {
    let store: any, inbox: any;
    const handed = new Map<string, any>();
    try {
      const me = identity(LANG, s);
      store = new FileStore(P(`pstores/${LANG}-${s}`));
      const peers = new ace.PeerStore({ store });
      for (const R of LANGS) await peers.pinRegistrationFile(rd(`ids/${R}-${rx(s)}.json`).registrationFilePrincipal);
      inbox = await ace.Inbox.open({ commerce: true, identity: me, store, peers, principal: inboxPrincipal(s), onMessage: (m: any) => { handed.set(m.messageId, summary(m)); } });
    } catch (e) {
      for (const R of LANGS) out[`${R}-${LANG}-${s}`] = { error: fail(e) };
      continue;
    }
    try {
      for (const R of LANGS) {
        const key = `${R}-${LANG}-${s}`;
        const r: any = {};
        out[key] = r;
        try {
          const m = rd(`msgs/p2/${key}.json`);
          const req = rd(`msgs/p1/${LANG}-${R}-${s}.json`).request;
          for (const [k, env] of [['decision', 'decision'], ['decisionAgain', 'decision'], ['decision2', 'decision2'], ['report', 'report']]) {
            r[k] = outcome(await inbox.receive(wire(m[env])));
          }
          r.decisionParsed = handed.get(m.decision.messageId) ?? null;
          r.reportParsed = handed.get(m.report.messageId) ?? null;
          r.ledger = await attempt(async () => ({ record: await ace.loadRequestRecord(store, req.conversationId, req.messageId) }));
        } catch (e) {
          r.error = fail(e);
        }
      }
    } finally {
      await inbox.close();
    }
  }
  wr(`out/${LANG}/pdecide.json`, out);
}

/** Every delegate's `requests/` record of its request to this language, loaded here. */
async function pload() {
  const out: Record<string, any> = {};
  for (const S of LANGS) for (const s of SCHEMES) {
    const key = `${S}-${LANG}-${s}`;
    out[key] = await attempt(async () => {
      const req = rd(`msgs/p1/${key}.json`).request;
      return { record: await ace.loadRequestRecord(new FileStore(P(`pstores/${S}-${s}`)), req.conversationId, req.messageId) };
    });
  }
  wr(`out/${LANG}/pload.json`, out);
}

const phases: Record<string, () => Promise<void>> = { gen, verify, send1, recv1, recv2, persist, load, pverify, psend, precv, pdecide, pload };
if (!phases[phase]) throw new Error(`unknown phase ${phase}`);
await phases[phase]();

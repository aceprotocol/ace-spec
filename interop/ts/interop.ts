// ACE cross-SDK interop harness — TypeScript side.
// Usage: node interop.ts <phase> <workdir>   (Node >= 22.18 strips types natively; or use tsx)
// Phases: gen | verify | send1 | recv1 | recv2 | persist | load. See ../README.md.
import * as fs from 'node:fs';
import * as path from 'node:path';
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
  intent: { action: 'intent', need: 'Translate EN→FR', tags: ['nlp', 'fr'], maxPrice: '10', currency: 'USDC', ttl: 3600 },
};
const profile = (lang: string) => ({
  name: `Agent ${lang} é`, description: 'interop / matrix', tags: ['interop', 'ace'],
  capabilities: ['translate'], endpoint: `https://${lang}.example/ace`, pricing: { currency: 'USDC', maxAmount: '10' },
});
const textBody = (s: string, r: string, sch: string) => ({ message: `hello ${s}→${r} (${sch}) héllo 世界 / "q" \\ ✓` });
const RFQ = { need: 'Translate 500 words EN→FR', maxPrice: '10.50', currency: 'USDC', ttl: 3600 };
const OFFER = { price: '9.75', currency: 'USDC', terms: 'delivery in 24h / net', ttl: 600 };

// `<lang>-<scheme>` sends; a second identity `<lang>-<scheme>-rx` receives (so ts→ts uses two parties).
const rx = (s: string) => `${s}-rx`;
const identity = (lang: string, s: string) => ace.SoftwareIdentity.fromExport(rd(`ids/${lang}-${s}.json`).export);
const peerOf = (lang: string, s: string) => ace.verifyRegistrationFile(rd(`ids/${lang}-${s}.json`).registrationFile);
const summary = (p: any) => ({
  messageId: p.messageId, from: p.from, to: p.to, conversationId: p.conversationId,
  type: p.type, threadId: p.threadId ?? null, timestamp: p.timestamp, body: p.body,
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
    wr(`ids/${LANG}-${s}.json`, {
      lang: LANG, scheme: s.replace('-rx', ''), export: id.exportPrivateKey(), aceId: id.getACEId(), address: id.getAddress(),
      signingPublicKey: b64(id.getSigningPublicKey()), encryptionPublicKey: b64(id.getEncryptionPublicKey()),
      registrationFile: ace.createRegistrationFile(id, { name: `Agent ${LANG} ${s}`, endpoint: `https://${LANG}.example/ace` }),
      registrationRequest: await ace.createRegistrationRequest(id, profile(LANG) as any, ts),
      auth,
    });
  }
}

async function verify() {
  const out: Record<string, any> = {};
  for (const src of LANGS) for (const s of SCHEMES) {
    const d = rd(`ids/${src}-${s}.json`);
    const r: any = {};
    r.import = await attempt(() => {
      const idn = ace.SoftwareIdentity.fromExport(d.export);
      return {
        aceId: idn.getACEId(), address: idn.getAddress(), scheme: idn.getSigningScheme(),
        signingPublicKey: b64(idn.getSigningPublicKey()), encryptionPublicKey: b64(idn.getEncryptionPublicKey()),
        reexport: idn.exportPrivateKey(),
        registrationFile: ace.createRegistrationFile(idn, { name: d.registrationFile.name, endpoint: d.registrationFile.endpoint }),
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
      const rfq = await ace.createMessage({ sender: me, recipient: peer, type: 'rfq', threadId, body: RFQ, threads });
      wr(`msgs/m1/${key}.json`, { threadId, textBody: tb, rfqBody: RFQ, text, rfq });
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
      const inbox = await ace.Inbox.open({ identity: me, store, peers, onMessage: () => { handed++; } });
      try {
        for (const S of LANGS) {
          const m = rd(`msgs/m1/${S}-${LANG}-${s}.json`);
          if (m.error) throw new Error(`sender ${S} failed: ${JSON.stringify(m.error)}`);
          r.receives[S] = {
            text: outcome(await inbox.receive(wire(m.text), { kind: 'direct' })),
            rfq: outcome(await inbox.receive(wire(m.rfq), { kind: 'direct' })),
            textAgain: outcome(await inbox.receive(wire(m.text), { kind: 'direct' })),
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
        const inbox = await ace.Inbox.open({ identity: me, store, peers, onMessage: () => { handed++; } });
        try {
          const m = rd(`msgs/m1/${LANGS[0]}-${R}-${s}.json`);
          const dup = outcome(await inbox.receive(wire(m.rfq), { kind: 'direct' }));
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

const phases: Record<string, () => Promise<void>> = { gen, verify, send1, recv1, recv2, persist, load };
if (!phases[phase]) throw new Error(`unknown phase ${phase}`);
await phases[phase]();

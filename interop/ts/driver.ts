// ACE interop driver for the TypeScript SDK (contract: ../README.md). Imports the built SDK (sdk-ts/dist).
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import {
  ACEError, CONTACT_TYPE, MemoryStore, ProfileSet, RECEIPT_TYPE, SoftwareIdentity, StorePrekeyVault, checkPacketTime,
  contactContent, createDescriptor, verifyKel, createPacket, createPermit, decodePacket, decryptPacket, receiptContent,
  verifyPacketSignature, verifyPermit, verifyPublishedAgent, TEXT_TYPE, BUNDLED_MANIFESTS, messageDigest,
  checkReceiptBody, MAX_NOTE_BYTES,
  type PrivateContent, type PublishedAgent,
} from '../../../sdk-ts/dist/index.js';

const RELAY = 'https://relay.interop.test';
const VAULT_KEY = 'prekeys.json';
const TEXT_DIGEST = messageDigest(TEXT_TYPE, BUNDLED_MANIFESTS.text.messages.find((m) => m.type === TEXT_TYPE)!.schema);

function args(argv: string[]): { pos: string[]; opt: Record<string, string> } {
  const pos: string[] = [], opt: Record<string, string> = {};
  for (let i = 0; i < argv.length; i++) {
    if (argv[i].startsWith('--')) opt[argv[i].slice(2)] = argv[++i];
    else pos.push(argv[i]);
  }
  return { pos, opt };
}
const readJson = (p: string): any => JSON.parse(readFileSync(p, 'utf8'));
const writeJson = (p: string, v: unknown) => writeFileSync(p, JSON.stringify(v, null, 1) + '\n');

async function load(dir: string, now: number) {
  const identity = SoftwareIdentity.fromExport(readJson(join(dir, 'identity.json')), now);
  const store = new MemoryStore();
  await store.write(VAULT_KEY, readFileSync(join(dir, VAULT_KEY)));
  const vault = new StorePrekeyVault(store, { key: VAULT_KEY, clock: () => now });
  const agent = readJson(join(dir, 'agent.json')) as PublishedAgent;
  return { identity, vault, agent };
}

async function genIdentity(dir: string, now: number) {
  mkdirSync(dir, { recursive: true });
  const identity = await SoftwareIdentity.generate({ now });
  const store = new MemoryStore();
  const vault = new StorePrekeyVault(store, { key: VAULT_KEY, clock: () => now });
  const pk = await vault.rotate(now);
  // The vault's own document, kept in the driver directory (FileStore needs the optional native fs-ext lock).
  writeFileSync(join(dir, VAULT_KEY), (await store.read(VAULT_KEY))!, { mode: 0o600 });
  const profiles = new ProfileSet(['text']);
  const agent = await createDescriptor(identity, {
    relays: [RELAY], prekey: { id: pk.id, publicKey: pk.publicKey }, profiles: profiles.descriptors(), now,
  });
  writeJson(join(dir, 'identity.json'), identity.exportPrivateKey());
  writeJson(join(dir, 'agent.json'), agent);
}

async function create(dir: string, o: Record<string, string>, now: number) {
  const { identity, agent: self } = await load(dir, now);
  const to = verifyPublishedAgent(readJson(o['to-agent']), now).agent;
  const prekeyOf = o['prekey-agent'] ? verifyPublishedAgent(readJson(o['prekey-agent']), now).agent : to;
  const peer = to.descriptor.aceId;
  let content: PrivateContent;
  switch (o.kind) {
    case 'text': content = { type: TEXT_TYPE, schemaDigest: TEXT_DIGEST, body: { message: o.message ?? 'hello' } }; break;
    case 'receipt-delivered': content = receiptContent({ messageId: o['ref-message-id'], outcome: 'delivered' }); break;
    case 'receipt-unknown-prekey': content = receiptContent({ messageId: o['ref-message-id'], outcome: 'rejected', code: 'unknown_prekey', prekey: o['ref-prekey'] }); break;
    case 'receipt-rejected': content = receiptContent({ messageId: o['ref-message-id'], outcome: 'rejected', code: o.code ?? 'unsupported_schema', permit: await createPermit(identity, peer, { now }) }); break;
    case 'contact-request':
    case 'contact-accepted':
      content = contactContent({ kind: o.kind === 'contact-request' ? 'request' : 'accepted', profile: TEXT_TYPE, note: o.note ?? 'hi', source: self, permit: await createPermit(identity, peer, { now }) });
      break;
    case 'contact-rejected': content = contactContent({ kind: 'rejected', profile: TEXT_TYPE, note: '', source: self }); break;
    default: throw new Error(`unknown kind ${o.kind}`);
  }
  const packet = await createPacket({ identity, to: peer, prekey: prekeyOf.descriptor.prekey, content, timestamp: now, ...(o['message-id'] ? { messageId: o['message-id'] } : {}) });
  writeJson(o.out, packet);
  writeJson(`${o.out}.content.json`, content);
}

async function open(dir: string, o: Record<string, string>, now: number) {
  const { identity, vault } = await load(dir, now);
  const me = identity.getACEId();
  const profiles = new ProfileSet(['text']);
  const packet = decodePacket(readJson(o.packet));
  if (packet.to !== me) throw new ACEError('wrong_recipient', 'not addressed to this identity');
  // The sender's KEL stands for the receiver's pin (06 step 3); its descriptor is not needed to open a packet.
  const sender = verifyKel(readJson(o['from-agent']).kel, now);
  if (sender.aceId !== packet.from) throw new ACEError('invalid_signature', 'packet is not from the given agent');
  verifyPacketSignature(packet, sender, now);
  checkPacketTime(packet, now);
  const c = await decryptPacket(packet, vault);
  profiles.validate(c.type, c.schemaDigest, c.body);
  const b = c.body as any;
  if (c.type === CONTACT_TYPE) {
    const src = verifyPublishedAgent(b.source, now);
    if (src.state.aceId !== packet.from) throw new ACEError('invalid_authorization', 'contact source is not the sender');
    verifyPacketSignature(packet, src.state, now);
    if (new TextEncoder().encode(b.note).length > MAX_NOTE_BYTES) throw new ACEError('invalid_body', 'note too long');
    if ((b.kind === 'rejected') === (b.permit !== undefined)) throw new ACEError('invalid_authorization', 'permit presence');
    if (b.permit !== undefined) verifyPermit(b.permit, src.state, me, now);
  } else if (c.type === RECEIPT_TYPE) {
    checkReceiptBody(b);
    if (b.permit !== undefined) verifyPermit(b.permit, sender, me, now);
  }
  return { ok: true, from: packet.from, messageId: packet.messageId, type: c.type, schemaDigest: c.schemaDigest, ...(c.threadId !== undefined ? { threadId: c.threadId } : {}), body: c.body };
}

async function main() {
  const [cmd, ...rest] = process.argv.slice(2);
  const { pos, opt } = args(rest);
  const now = Number(opt.now ?? process.env.ACE_INTEROP_NOW);
  if (!Number.isSafeInteger(now)) throw new Error('--now is required');
  const dir = pos[0];
  if (cmd === 'gen-identity') return genIdentity(dir, now);
  if (cmd === 'create-packet') return create(dir, opt, now);
  if (cmd === 'open-packet') {
    let out: unknown;
    try { out = await open(dir, opt, now); } catch (e) {
      if (!(e instanceof ACEError)) throw e;
      out = { error: e.code };
    }
    return writeJson(opt.out, out);
  }
  throw new Error(`unknown command ${cmd}`);
}

main().catch((e) => { console.error(e); process.exit(2); });

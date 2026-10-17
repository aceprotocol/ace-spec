// Smoke test of the installed Node release tarballs (see README.md). Run from a consumer directory where
// @ace-protocol/{sdk,relay,cli,mcp} were installed from the tarballs. Needs a disposable Redis (default
// redis://127.0.0.1:16379, ACE_SMOKE_REDIS) and uses ONLY databases 14 and 15 (ACE_SMOKE_DBS=a,b), which it flushes.
//
// Checks: the installed CLI creates an identity; the installed relay serves two loopback listeners; the SDK
// NetworkClient publishes (registering on demand) and runs contact → accept → message → receipt across the two relays,
// with the receiver's FileStore closed and reopened while the message is queued.
import { execFileSync } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import assert from 'node:assert/strict';
import { Redis } from 'ioredis';
import { buildApp } from '@ace-protocol/relay';
import { loadConfig } from '@ace-protocol/relay/config';
import { MemoryStore, NetworkClient, RelayClient, SoftwareIdentity } from '@ace-protocol/sdk';

const REDIS = process.env.ACE_SMOKE_REDIS ?? 'redis://127.0.0.1:16379';
const [dbA, dbB] = (process.env.ACE_SMOKE_DBS ?? '14,15').split(',').map(Number);
const home = await mkdtemp(join(tmpdir(), 'ace-smoke-'));
const relays = [];
const listeners = new Map();

try {
  // 1. Installed CLI: a file-keystore identity in a throwaway ACE_HOME.
  const env = { ...process.env, ACE_HOME: join(home, 'cli') };
  const init = JSON.parse(execFileSync(join('node_modules', '.bin', 'ace'), ['init', '--keystore', 'file'], { env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }));
  assert.match(JSON.stringify(init), /ace:sha256:[0-9a-f]{64}/);

  // 2. Two installed relays on loopback, each with an HTTPS public URL mapped to its listener.
  async function serve(db, publicRelayUrl) {
    process.env.PUBLIC_RELAY_URL = publicRelayUrl;
    process.env.REDIS_URL = `${REDIS}/${db}`;
    const redis = new Redis(process.env.REDIS_URL), subscriberRedis = new Redis(process.env.REDIS_URL);
    await redis.flushdb();
    const relay = await buildApp({ config: loadConfig(), redis, subscriberRedis });
    await relay.app.listen({ host: '127.0.0.1', port: 0 });
    listeners.set(publicRelayUrl, `http://127.0.0.1:${relay.app.server.address().port}`);
    relays.push({ relay, redis, subscriberRedis });
  }
  await serve(dbA, 'https://relay-a.test');
  await serve(dbB, 'https://relay-b.test');
  const relay = (url) => new RelayClient(url, { connectUrl: listeners.get(url) });

  // 3. SDK NetworkClient across the two relays.
  const received = [];
  const aliceIdentity = await SoftwareIdentity.generate();
  const aliceId = aliceIdentity.getACEId();
  const openAlice = () => NetworkClient.open({
    identity: aliceIdentity, store: join(home, 'alice'), relay: relay('https://relay-a.test'), foreignRelay: relay,
    profiles: ['text'], visibility: 'public', acceptProfiles: ['ace:text:1'],
    onMessage: (m) => { received.push(m.body.message); },
  });
  let alice = await openAlice();
  const bob = await NetworkClient.open({
    identity: await SoftwareIdentity.generate(), store: new MemoryStore(), relay: relay('https://relay-b.test'), foreignRelay: relay,
    profiles: ['text'],
  });
  for (const c of [alice, bob]) await c.publish();   // registers on demand

  await bob.connect(await relay('https://relay-a.test').getDescriptor(aliceId), { profile: 'ace:text:1', note: 'smoke' });
  assert.equal((await alice.pull())[0].kind, 'contact');   // auto-accepted (acceptProfiles)
  assert.equal((await bob.pull())[0].kind, 'contact');     // accepted: bob now holds alice's permit

  await alice.close();                      // the receiver restarts from its FileStore while the message is queued
  const entry = await bob.send(aliceId, 'ace:text:1', { message: 'hello from the release candidate' });
  alice = await openAlice();
  assert.equal((await alice.pull())[0].kind, 'delivered');
  assert.deepEqual(received, ['hello from the release candidate']);
  assert.equal((await bob.pull())[0].kind, 'receipt');
  assert.equal((await bob.outbox.get(entry.messageId)).status, 'delivered');
  await Promise.all([alice.close(), bob.close()]);
  console.log(JSON.stringify({ ok: true, cli: 'init', relays: 2, delivered: entry.messageId }));
} finally {
  for (const { relay, redis, subscriberRedis } of relays) {
    relay.sseRegistry.drain();
    await relay.app.close();
    await redis.flushdb();
    await Promise.all([redis.quit(), subscriberRedis.quit()]);
  }
  await rm(home, { recursive: true, force: true });
}

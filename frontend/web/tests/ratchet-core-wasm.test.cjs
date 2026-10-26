const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.window = {};
global.document = { currentScript: { src: 'https://serein.test/core-bridge.js' } };
global.location = { href: 'https://serein.test/' };
const wasmPath = path.join(__dirname, '../serein_core.wasm');
if (fs.existsSync(wasmPath)) {
  const wasmBytes = fs.readFileSync(wasmPath);
  global.fetch = async () => ({ ok: true, arrayBuffer: async () => wasmBytes.buffer.slice(wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength) });
} else {
  global.fetch = async () => ({ ok: false, arrayBuffer: async () => new ArrayBuffer(0) });
}
require('../core-bridge.js');

const core = global.window.SereinCore;
const requireWasmArtifact = fs.existsSync(wasmPath) ? {} : { skip: 'CI builds and installs serein_core.wasm before this test.' };

test('WASM ratchet handles round-trip, ordering, authenticated state, and tamper rejection', requireWasmArtifact, async () => {
  assert.equal(await core.ready, true);
  assert.equal(core.wasmActive, true);
  const bootstrap = new Uint8Array(32).fill(0x42);
  const sessionId = new Uint8Array(16).fill(0x19);
  const roots = await core.deriveRatchetChains(bootstrap, sessionId, 0);
  const alice = await core.createRatchet({ sessionId, sendDirection: 0, sendChainKey: roots.initiatorToResponder, receiveChainKey: roots.responderToInitiator });
  const bob = await core.createRatchet({ sessionId, sendDirection: 1, sendChainKey: roots.responderToInitiator, receiveChainKey: roots.initiatorToResponder });
  const aad = new TextEncoder().encode('account=A;device=1;to=B;device=2');
  const frames = [];
  for (let n = 0; n < 5; n++) {
    frames.push(alice.encrypt(new Uint8Array(12).fill(n + 1), new TextEncoder().encode(`message-${n}`), aad));
  }
  const damaged = frames[4].ciphertext.slice();
  damaged[0] ^= 1;
  const beforeFailure = bob.snapshot();
  assert.throws(() => bob.decrypt(frames[4].header, frames[4].nonce, damaged, aad), /authentication failed/i);
  assert.deepEqual(bob.snapshot(), beforeFailure, 'an invalid tag must not consume ratchet state');
  assert.equal(new TextDecoder().decode(bob.decrypt(frames[4].header, frames[4].nonce, frames[4].ciphertext, aad)), 'message-4');
  const snap = bob.snapshot();
  bob.close();
  const restoredBob = await core.restoreRatchet(snap);
  assert.equal(new TextDecoder().decode(restoredBob.decrypt(frames[0].header, frames[0].nonce, frames[0].ciphertext, aad)), 'message-0');
  assert.equal(new TextDecoder().decode(restoredBob.decrypt(frames[1].header, frames[1].nonce, frames[1].ciphertext, aad)), 'message-1');
  assert.equal(new TextDecoder().decode(restoredBob.decrypt(frames[2].header, frames[2].nonce, frames[2].ciphertext, aad)), 'message-2');
  assert.throws(() => restoredBob.decrypt(frames[0].header, frames[0].nonce, frames[0].ciphertext, aad), /ordering|replay|invalid/i);
  const rootStep = await core.deriveRatchetRootStep(new Uint8Array(32).fill(0x11), new Uint8Array(32).fill(0x22));
  assert.notDeepEqual(rootStep.rootKey, rootStep.chainKey);
  await assert.rejects(core.deriveRatchetRootStep(new Uint8Array(32).fill(0x11), new Uint8Array(32)), /non-contributory|invalid/i);
  alice.close();
  restoredBob.close();
});

test('WASM X25519 Double Ratchet bridge supports key setup, DH turns, authentication, and sealed-state round trips', requireWasmArtifact, async () => {
  assert.equal(await core.ready, true);
  const sessionId = new Uint8Array(16).fill(0x27);
  const bootstrapSecret = new Uint8Array(32).fill(0x61);
  const alicePrivate = new Uint8Array(32).fill(0x32);
  const bobPrivate = new Uint8Array(32).fill(0x73);
  const alicePublic = await core.doubleRatchetPublicFromPrivate(alicePrivate);
  const bobPublic = await core.doubleRatchetPublicFromPrivate(bobPrivate);
  const alice = await core.createDoubleRatchetInitiator({
    sessionId, sendDirection: 0, bootstrapSecret, localDhPrivate: alicePrivate, remoteDhPublic: bobPublic,
  });
  const bob = await core.createDoubleRatchetResponder({
    sessionId, sendDirection: 1, bootstrapSecret, localDhPrivate: bobPrivate, remoteDhPublic: alicePublic,
  });
  const aad = new TextEncoder().encode('sender=device-a;recipient=device-b');
  const beforeOversized = alice.snapshot();
  assert.throws(() => alice.encrypt(new Uint8Array(12).fill(9), new Uint8Array(32769), aad), /limit/i);
  assert.deepEqual(alice.snapshot(), beforeOversized, 'oversized input is rejected before state changes');
  beforeOversized.fill(0);
  const first = alice.encrypt(new Uint8Array(12).fill(1), new TextEncoder().encode('hello'), aad);
  const corrupt = first.ciphertext.slice();
  corrupt[0] ^= 1;
  const beforeFailure = bob.snapshot();
  assert.throws(() => bob.decrypt(first.header, first.nonce, corrupt, aad, new Uint8Array(32).fill(0x91)), /authentication/i);
  assert.deepEqual(bob.snapshot(), beforeFailure, 'failed authentication leaves DH and chain state unchanged');
  assert.equal(new TextDecoder().decode(bob.decrypt(first.header, first.nonce, first.ciphertext, aad, new Uint8Array(32).fill(0x91))), 'hello');

  const reply = bob.encrypt(new Uint8Array(12).fill(2), new TextEncoder().encode('world'), aad, new Uint8Array(32).fill(0x42));
  assert.notDeepEqual(reply.header.slice(18, 50), bobPublic, 'responder reply begins a fresh DH sending chain');
  assert.equal(new TextDecoder().decode(alice.decrypt(reply.header, reply.nonce, reply.ciphertext, aad, new Uint8Array(32).fill(0x52))), 'world');

  const snapshot = alice.snapshot();
  alice.close();
  const restored = await core.restoreDoubleRatchet(snapshot);
  const next = restored.encrypt(new Uint8Array(12).fill(3), new TextEncoder().encode('after restore'), aad);
  assert.equal(new TextDecoder().decode(bob.decrypt(next.header, next.nonce, next.ciphertext, aad, new Uint8Array(32).fill(0x63))), 'after restore');
  restored.close();
  bob.close();
  snapshot.fill(0);
  beforeFailure.fill(0);
  bootstrapSecret.fill(0);
  alicePrivate.fill(0);
  bobPrivate.fill(0);
});

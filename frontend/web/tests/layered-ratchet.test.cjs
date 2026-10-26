const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.window = {};
global.crypto = require('node:crypto').webcrypto;
require('../device-crypto.js');
global.document = { currentScript: { src: 'https://serein.test/core-bridge.js' } };
global.location = { href: 'https://serein.test/' };
const wasmPath = path.join(__dirname, '../serein_core.wasm');
if (fs.existsSync(wasmPath)) {
  const wasmBytes = fs.readFileSync(wasmPath);
  global.fetch = async () => ({ ok: true, arrayBuffer: async () => wasmBytes.buffer.slice(wasmBytes.byteOffset, wasmBytes.byteOffset + wasmBytes.byteLength) });
} else global.fetch = async () => ({ ok: false, arrayBuffer: async () => new ArrayBuffer(0) });
require('../core-bridge.js');
require('../layered-ratchet.js');
const core = global.window.SereinCore;
const requireWasmArtifact = fs.existsSync(wasmPath) ? {} : { skip: 'CI builds and installs serein_core.wasm before this test.' };
const encoder = new TextEncoder();

async function makePair(layer) {
  const sessionId = new Uint8Array(16).fill(layer === 1 ? 0x16 : 0x26);
  const roots = await core.deriveRatchetChains(new Uint8Array(32).fill(layer === 1 ? 0x51 : 0x62), sessionId, 0);
  const a = await core.createRatchet({sessionId, sendDirection:0, sendChainKey:roots.initiatorToResponder, receiveChainKey:roots.responderToInitiator});
  const b = await core.createRatchet({sessionId, sendDirection:1, sendChainKey:roots.responderToInitiator, receiveChainKey:roots.initiatorToResponder});
  roots.initiatorToResponder.fill(0); roots.responderToInitiator.fill(0);
  return [a,b];
}

test('live v3 envelope nests two independent ratchets, authenticates routing, and commits neither layer on failed outer authentication', requireWasmArtifact, async () => {
  assert.equal(await core.ready, true);
  const [a1,b1] = await makePair(1), [a2,b2] = await makePair(2);
  const alice = new window.SereinLayeredRatchet.LayeredRatchet(a1,a2);
  const bob = new window.SereinLayeredRatchet.LayeredRatchet(b1,b2);
  const metadata = {conversationId:'thread-1',messageId:'message-1',senderUserId:'alice',senderDeviceId:'a1',recipientUserId:'bob',recipientDeviceId:'b1'};
  const original = encoder.encode(JSON.stringify({version:1,text:'two live application layers'}));
  const packet = alice.encrypt(original,metadata);
  assert.equal(packet.version,3);
  const before=bob.snapshots();
  const bytes=Uint8Array.from(atob(packet.ciphertext),c=>c.charCodeAt(0)); bytes[22]^=1;
  assert.throws(()=>bob.decrypt({...packet,ciphertext:btoa(String.fromCharCode(...bytes))},metadata),/authentication|session|direction|ordering/i);
  const after=bob.snapshots();
  assert.deepEqual(after.layer1,before.layer1);
  assert.deepEqual(after.layer2,before.layer2);
  const opened=bob.decrypt(packet,metadata);
  assert.deepEqual(opened,original);
  assert.throws(()=>bob.decrypt(packet,{...metadata,recipientDeviceId:'other-device'}),/authentication|session|direction|ordering/i);
  const states=bob.snapshots();
  assert.ok(states.layer1.length>0 && states.layer2.length>0);
  alice.close(); bob.close(); original.fill(0); bytes.fill(0); before.layer1.fill(0); before.layer2.fill(0); after.layer1.fill(0); after.layer2.fill(0); states.layer1.fill(0); states.layer2.fill(0);
});


test('static P-256 device bundles bootstrap interoperable nested ratchets with canonical sender/receiver routing', requireWasmArtifact, async () => {
  assert.equal(await core.ready, true);
  const deviceCrypto = window.SereinDeviceCrypto;
  const alice = { layer1: await deviceCrypto.generateDeviceKeyPair(), layer2: await deviceCrypto.generateDeviceKeyPair() };
  const bob = { layer1: await deviceCrypto.generateDeviceKeyPair(), layer2: await deviceCrypto.generateDeviceKeyPair() };
  const aliceFingerprint = await deviceCrypto.fingerprintDeviceKeyBundle(alice.layer1.publicJwk, alice.layer2.publicJwk);
  const bobFingerprint = await deviceCrypto.fingerprintDeviceKeyBundle(bob.layer1.publicJwk, bob.layer2.publicJwk);
  const make = async (own, ownUser, ownDevice, ownFingerprint, peer, peerUser, peerDevice, peerFingerprint, layer) => {
    const name = layer === 1 ? 'layer1' : 'layer2';
    const bootstrap = await deviceCrypto.deriveRatchetBootstrapSecret(
      own[name].privateKey, ownUser, ownDevice, peerUser, peerDevice, peer[name].publicJwk, name,
    );
    const parties = [`${ownUser}:${ownDevice}:${ownFingerprint}`, `${peerUser}:${peerDevice}:${peerFingerprint}`].sort();
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(`Serein/${name}/live-ratchet-session/v1|${parties.join('|')}`)));
    const sessionId = digest.slice(0, 16); if (sessionId.every(value => value === 0)) sessionId[15] = 1;
    const direction = `${ownUser}:${ownDevice}` < `${peerUser}:${peerDevice}` ? 0 : 1;
    const chains = await core.deriveRatchetChains(bootstrap, sessionId, 0);
    const send = direction === 0 ? chains.initiatorToResponder : chains.responderToInitiator;
    const receive = direction === 0 ? chains.responderToInitiator : chains.initiatorToResponder;
    const handle = await core.createRatchet({ sessionId, sendDirection: direction, sendChainKey: send, receiveChainKey: receive });
    bootstrap.fill(0); sessionId.fill(0); digest.fill(0); chains.initiatorToResponder.fill(0); chains.responderToInitiator.fill(0);
    return handle;
  };
  const alice1 = await make(alice, 'alice', 'alice-device', aliceFingerprint, bob, 'bob', 'bob-device', bobFingerprint, 1);
  const alice2 = await make(alice, 'alice', 'alice-device', aliceFingerprint, bob, 'bob', 'bob-device', bobFingerprint, 2);
  const bob1 = await make(bob, 'bob', 'bob-device', bobFingerprint, alice, 'alice', 'alice-device', aliceFingerprint, 1);
  const bob2 = await make(bob, 'bob', 'bob-device', bobFingerprint, alice, 'alice', 'alice-device', aliceFingerprint, 2);
  const sender = new window.SereinLayeredRatchet.LayeredRatchet(alice1, alice2);
  const receiver = new window.SereinLayeredRatchet.LayeredRatchet(bob1, bob2);
  const route = { conversationId: 'alice:bob', messageId: 'e2e-bootstrap-test', senderUserId: 'alice', senderDeviceId: 'alice-device', recipientUserId: 'bob', recipientDeviceId: 'bob-device' };
  const payload = encoder.encode('independent P-256 layer bootstraps');
  const encrypted = sender.encrypt(payload, route);
  assert.deepEqual(receiver.decrypt(encrypted, route), payload);
  sender.close(); receiver.close(); payload.fill(0);
});

test('version-3 double-layer encoding rejects truncated headers, malformed lengths, and oversized input before processing', requireWasmArtifact, async () => {
  assert.equal(await core.ready, true);
  const [a1,b1] = await makePair(1), [a2,b2] = await makePair(2);
  const pair = new window.SereinLayeredRatchet.LayeredRatchet(a1,a2);
  const metadata={conversationId:'c',messageId:'m',senderUserId:'a',senderDeviceId:'ad',recipientUserId:'b',recipientDeviceId:'bd'};
  assert.throws(()=>pair.encrypt(new Uint8Array(32711),metadata),/32 KiB/i);
  assert.throws(()=>pair.decrypt({version:3,iv:'AA==',ciphertext:'AA=='},metadata),/length|encoding/i);
  pair.close();b1.close();b2.close();
});

test('nested v3 plaintext limit reserves enough room for the full outer SRL1 payload', requireWasmArtifact, async () => {
  assert.equal(await core.ready, true);
  const [a1,b1] = await makePair(1), [a2,b2] = await makePair(2);
  const sender = new window.SereinLayeredRatchet.LayeredRatchet(a1,a2);
  const receiver = new window.SereinLayeredRatchet.LayeredRatchet(b1,b2);
  const metadata={conversationId:'c',messageId:'max-boundary',senderUserId:'a',senderDeviceId:'ad',recipientUserId:'b',recipientDeviceId:'bd'};
  const clear=new Uint8Array(32710).fill(0x5a), packet=sender.encrypt(clear,metadata);
  assert.equal(atob(packet.ciphertext).length,22+32784);
  assert.deepEqual(receiver.decrypt(packet,metadata),clear);
  sender.close();receiver.close();clear.fill(0);
});

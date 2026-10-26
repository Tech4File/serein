const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto, createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

global.crypto = webcrypto;
global.window = {};
require('../device-crypto.js');
const deviceCrypto = global.window.SereinDeviceCrypto;
const textEncoder = new TextEncoder();

async function generateDeviceBundle() {
  const layer1 = await deviceCrypto.generateDeviceKeyPair();
  const layer2 = await deviceCrypto.generateDeviceKeyPair();
  return { ...layer1, layer2PrivateKey: layer2.privateKey, layer2PublicJwk: layer2.publicJwk };
}

async function deriveOwnAndPeer(own, ownUser, ownDevice, peer, peerUser, peerDevice, layer2 = false) {
  const publicJwk = (({ kty, crv, x, y }) => ({ kty, crv, x, y }))(layer2 ? peer.layer2PublicJwk : peer.publicJwk);
  return (layer2 ? deviceCrypto.deriveLayer2ConversationKey : deviceCrypto.deriveCandidateConversationKey)(
    layer2 ? own.layer2PrivateKey : own.privateKey, ownUser, ownDevice, peerUser, peerDevice, publicJwk,
  );
}

test('device key generation keeps the private key non-extractable and publishes only a public JWK', async () => {
  const pair = await deviceCrypto.generateDeviceKeyPair();
  assert.equal(pair.privateKey.extractable, false);
  assert.equal(pair.privateKey.algorithm.name, 'ECDH');
  assert.equal(pair.publicJwk.kty, 'EC');
  assert.equal(pair.publicJwk.crv, 'P-256');
  assert.equal(Object.hasOwn(pair.publicJwk, 'd'), false);
  assert.match(await deviceCrypto.fingerprintP256(pair.publicJwk), /^[0-9a-f]{64}$/);
  const layer2 = await deviceCrypto.generateDeviceKeyPair();
  const bundleFingerprint = await deviceCrypto.fingerprintDeviceKeyBundle(pair.publicJwk, layer2.publicJwk);
  assert.match(bundleFingerprint, /^[0-9a-f]{64}$/);
  const rawCoordinates = jwk => Buffer.concat([Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const expectedBundle = createHash('sha256').update(Buffer.from('Serein ECDH P-256 device key bundle v2\0', 'utf8'))
    .update(rawCoordinates(pair.publicJwk)).update(rawCoordinates(layer2.publicJwk)).digest('hex');
  assert.equal(bundleFingerprint, expectedBundle);
});

test('public-key fingerprint matches the documented server byte encoding', async () => {
  const pair = await deviceCrypto.generateDeviceKeyPair();
  const coordinate = value => Buffer.from(value, 'base64url');
  const expected = createHash('sha256')
    .update(Buffer.from('Serein ECDH P-256 public key v1\0', 'utf8'))
    .update(coordinate(pair.publicJwk.x))
    .update(coordinate(pair.publicJwk.y))
    .digest('hex');
  assert.equal(await deviceCrypto.fingerprintP256(pair.publicJwk), expected);
});

test('both participants derive the same candidate key; AES-GCM decrypts and rejects tampering', async () => {
  const alice = await deviceCrypto.generateDeviceKeyPair();
  const bob = await deviceCrypto.generateDeviceKeyPair();
  const aliceKey = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b');
  const bobKey = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a');
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aad = textEncoder.encode('serein-message-crypto-test-v1');
  const clear = textEncoder.encode('local crypto conformance test');
  const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, aliceKey, clear);
  const opened = await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, bobKey, ciphertext);
  assert.equal(new TextDecoder().decode(opened), 'local crypto conformance test');
  const corrupted = new Uint8Array(ciphertext); corrupted[0] ^= 1;
  await assert.rejects(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, bobKey, corrupted));
});

test('web message envelope is interoperable Base64, binds routing metadata, and decrypts recipient content', async () => {
  const alice = await generateDeviceBundle();
  const bob = await generateDeviceBundle();
  const aliceKey = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b');
  const bobKey = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a');
  const aliceLayer2 = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b', true);
  const bobLayer2 = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a', true);
  const metadata = { conversationId: '11111111-1111-4111-8111-111111111111', messageId: '22222222-2222-4222-8222-222222222222', senderUserId: '33333333-3333-4333-8333-333333333333', senderDeviceId: '44444444-4444-4444-8444-444444444444', recipientUserId: '55555555-5555-4555-8555-555555555555', recipientDeviceId: '66666666-6666-4666-8666-666666666666' };
  const clearContent = { version: 1, text: 'ciphertext only on the wire', conversation_id: metadata.conversationId, sender_user_id: metadata.senderUserId, sender_device_id: metadata.senderDeviceId, recipient_user_id: metadata.recipientUserId, recipient_device_id: metadata.recipientDeviceId };
  const envelope = await deviceCrypto.encryptMessage(aliceKey, aliceLayer2, JSON.stringify(clearContent), metadata);
  assert.equal(envelope.version, 2);
  assert.equal(envelope.algorithm, 'SEREIN-LAYER2-AES-256-GCM');
  assert.equal(Buffer.from(envelope.iv, 'base64').length, 12);
  assert.match(envelope.iv, /^(?:[A-Za-z0-9+/]{4})+$/);
  assert.match(envelope.ciphertext, /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/);
  assert.equal(Object.hasOwn(envelope, 'plaintext'), false);
  const received = JSON.parse(await deviceCrypto.decryptMessage(bobKey, bobLayer2, envelope, metadata));
  assert.deepEqual(received, clearContent);
  await assert.rejects(deviceCrypto.decryptMessage(bobKey, bobLayer2, envelope, { ...metadata, recipientDeviceId: 'other-device' }));
  await assert.rejects(deviceCrypto.decryptMessage(bobKey, aliceKey, envelope, metadata));
  const tamperedBytes = Buffer.from(envelope.ciphertext, 'base64');
  tamperedBytes[0] ^= 1;
  const corrupted = { ...envelope, ciphertext: tamperedBytes.toString('base64') };
  await assert.rejects(deviceCrypto.decryptMessage(bobKey, bobLayer2, corrupted, metadata));
});



test('legacy Layer 1-only queued messages remain readable after Layer 2 rollout', async () => {
  const alice = await generateDeviceBundle();
  const bob = await generateDeviceBundle();
  const layer1Alice = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b');
  const layer1Bob = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a');
  const layer2Bob = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a', true);
  const metadata = { conversationId: 'conversation', messageId: 'message-old', senderUserId: 'account-a', senderDeviceId: 'device-a', recipientUserId: 'account-b', recipientDeviceId: 'device-b' };
  const clear = textEncoder.encode(JSON.stringify({ version: 1, text: 'legacy message' }));
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const aad = textEncoder.encode(JSON.stringify(['serein-message-v1', metadata.conversationId, metadata.messageId, metadata.senderUserId, metadata.senderDeviceId, metadata.recipientUserId, metadata.recipientDeviceId]));
  const encrypted = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, layer1Alice, clear);
  const envelope = { version: 1, algorithm: 'AES-256-GCM', iv: Buffer.from(iv).toString('base64'), ciphertext: Buffer.from(encrypted).toString('base64') };
  assert.equal(await deviceCrypto.decryptMessage(layer1Bob, layer2Bob, envelope, metadata), JSON.stringify({ version: 1, text: 'legacy message' }));
});

test('static-P256 bootstrap secrets agree per participant and are domain-separated by layer', async () => {
  const alice = await generateDeviceBundle();
  const bob = await generateDeviceBundle();
  const bootstrap = async (own, ownUser, ownDevice, peer, peerUser, peerDevice, layer2 = false) =>
    deviceCrypto.deriveRatchetBootstrapSecret(
      layer2 ? own.layer2PrivateKey : own.privateKey, ownUser, ownDevice, peerUser, peerDevice,
      layer2 ? peer.layer2PublicJwk : peer.publicJwk, layer2 ? 'layer2' : 'layer1',
    );
  const a1 = await bootstrap(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b');
  const b1 = await bootstrap(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a');
  const a2 = await bootstrap(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b', true);
  const b2 = await bootstrap(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a', true);
  assert.deepEqual(a1, b1);
  assert.deepEqual(a2, b2);
  assert.notDeepEqual(a1, a2);
  a1.fill(0); b1.fill(0); a2.fill(0); b2.fill(0);
});

test('independent Layer 2 keys match only for the same device pair and are distinct from Layer 1', async () => {
  const alice = await generateDeviceBundle();
  const bob = await generateDeviceBundle();
  const bobSecond = await generateDeviceBundle();
  const aliceL1 = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b');
  const bobL1 = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a');
  const aliceL2 = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b', true);
  const bobL2 = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a', true);
  const bobDevice2L2 = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bobSecond, 'account-b', 'device-b-2', true);
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const sample = textEncoder.encode('layer2 pair binding');
  const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, aliceL2, sample);
  assert.equal(new TextDecoder().decode(await webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, bobL2, ciphertext)), 'layer2 pair binding');
  await assert.rejects(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, bobDevice2L2, ciphertext));
  await assert.rejects(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, aliceL1, ciphertext));
});

test('encrypted transfer manifests and chunk data bind identity, position, and tampering', async () => {
  const metadata = { transferId: '11111111-1111-4111-8111-111111111111', senderUserId: '22222222-2222-4222-8222-222222222222', senderDeviceId: '33333333-3333-4333-8333-333333333333', recipientUserId: '44444444-4444-4444-8444-444444444444', recipientDeviceId: '55555555-5555-4555-8555-555555555555' };
  const { key, rawKey } = await deviceCrypto.generateTransferKey();
  const manifest = { version: 1, transfer_id: metadata.transferId, filename: 'test.webm', content_type: 'video/webm', size: 10, content_key: deviceCrypto.encodeBase64(rawKey), chunk_count: 1, nonce_prefix: deviceCrypto.encodeBase64(new Uint8Array([1, 2, 3, 4])) };
  const wrapped = await deviceCrypto.encryptTransferManifest(key, manifest, metadata);
  assert.deepEqual(await deviceCrypto.decryptTransferManifest(key, wrapped, metadata), manifest);
  const alice = await generateDeviceBundle(), bob = await generateDeviceBundle();
  const layer2Alice = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b', true);
  const layer2Bob = await deriveOwnAndPeer(bob, 'account-b', 'device-b', alice, 'account-a', 'device-a', true);
  const nested = await deviceCrypto.encryptTransferManifestLayer2(layer2Alice, wrapped, metadata);
  const inner = await deviceCrypto.decryptTransferManifestLayer2(layer2Bob, nested, metadata);
  assert.deepEqual(await deviceCrypto.decryptTransferManifest(key, inner, metadata), manifest);
  await assert.rejects(deviceCrypto.decryptTransferManifestLayer2(layer2Bob, nested, { ...metadata, recipientDeviceId: 'substituted-device' }));
  await assert.rejects(deviceCrypto.decryptTransferManifest(key, wrapped, { ...metadata, recipientDeviceId: 'substituted-device' }));
  const prefix = new Uint8Array([1, 2, 3, 4]);
  const iv = deviceCrypto.transferChunkIv(prefix, 0);
  const clear = new Uint8Array([0, 1, 2, 3, 255]);
  const encrypted = await deviceCrypto.encryptTransferChunk(key, clear, metadata, 0, 1, iv);
  assert.deepEqual(new Uint8Array(await deviceCrypto.decryptTransferChunk(key, encrypted.iv, encrypted.ciphertext, metadata, 0, 1)), clear);
  // The ciphertext is shared once per transfer; each recipient device gets its own
  // device-bound manifest envelope carrying the same file key.
  assert.deepEqual(new Uint8Array(await deviceCrypto.decryptTransferChunk(key, encrypted.iv, encrypted.ciphertext, { ...metadata, recipientDeviceId: 'second-recipient-device' }, 0, 1)), clear);
  await assert.rejects(deviceCrypto.decryptTransferChunk(key, encrypted.iv, encrypted.ciphertext, { ...metadata, recipientUserId: 'different-recipient-account' }, 0, 1));
  await assert.rejects(deviceCrypto.decryptTransferChunk(key, encrypted.iv, encrypted.ciphertext, metadata, 1, 1));
  const changed = new Uint8Array(encrypted.ciphertext); changed[0] ^= 1;
  await assert.rejects(deviceCrypto.decryptTransferChunk(key, encrypted.iv, changed, metadata, 0, 1));
  assert.match(await deviceCrypto.sha256Hex(encrypted.ciphertext), /^[0-9a-f]{64}$/);
});

test('v2 file chunks match the published deterministic two-layer AES-GCM vector', async () => {
  const vector = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures/transfer-chunk-v2-vector.json'), 'utf8'));
  const metadata = { transferId: vector.metadata.transfer_id, senderUserId: vector.metadata.sender_user_id, senderDeviceId: vector.metadata.sender_device_id, recipientUserId: vector.metadata.recipient_user_id, recipientDeviceId: 'recipient-device-vector' };
  const fromHex = value => new Uint8Array(Buffer.from(value, 'hex'));
  const key1 = await deviceCrypto.importTransferKey(fromHex(vector.layer1_key_hex));
  const key2 = await deviceCrypto.importTransferKey(fromHex(vector.layer2_key_hex));
  const plain = textEncoder.encode(vector.plaintext_utf8);
  const encrypted = await deviceCrypto.encryptTransferChunkLayer2(key1, key2, plain, metadata, vector.index, vector.count,
    deviceCrypto.transferChunkIv(fromHex(vector.layer1_nonce_prefix_hex), vector.index),
    deviceCrypto.transferChunkIv(fromHex(vector.layer2_nonce_prefix_hex), vector.index));
  assert.equal(Buffer.from(encrypted.ciphertext).toString('hex'), vector.ciphertext_hex);
  const opened = await deviceCrypto.decryptTransferChunkLayer2(key1, key2, encrypted.iv1, encrypted.iv2, encrypted.ciphertext, metadata, vector.index, vector.count);
  assert.equal(new TextDecoder().decode(opened), vector.plaintext_utf8);
  await assert.rejects(deviceCrypto.decryptTransferChunkLayer2(key1, key2, encrypted.iv1, encrypted.iv2, encrypted.ciphertext, { ...metadata, recipientUserId: 'wrong-account' }, vector.index, vector.count));
  await assert.rejects(deviceCrypto.decryptTransferChunkLayer2(key1, key2, encrypted.iv1, encrypted.iv2, encrypted.ciphertext, metadata, vector.index + 1, vector.count));
  const corrupted = new Uint8Array(encrypted.ciphertext); corrupted[0] ^= 0x80;
  await assert.rejects(deviceCrypto.decryptTransferChunkLayer2(key1, key2, encrypted.iv1, encrypted.iv2, corrupted, metadata, vector.index, vector.count));
});

test('derived conversation keys are bound to the account/device pair context', async () => {
  const alice = await deviceCrypto.generateDeviceKeyPair();
  const bob = await deviceCrypto.generateDeviceKeyPair();
  const first = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'device-b');
  const wrongContext = await deriveOwnAndPeer(alice, 'account-a', 'device-a', bob, 'account-b', 'different-device');
  const iv = webcrypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await webcrypto.subtle.encrypt({ name: 'AES-GCM', iv }, first, textEncoder.encode('pair binding'));
  await assert.rejects(webcrypto.subtle.decrypt({ name: 'AES-GCM', iv }, wrongContext, ciphertext));
});

test('Android encrypted JSON rejects malformed UTF-8 rather than replacement-decoding authenticated bytes', () => {
  const androidCrypto = fs.readFileSync(path.join(__dirname, '../../../apps/android/app/src/main/java/io/serein/chat/SereinDeviceCrypto.java'), 'utf8');
  assert.match(androidCrypto, /newDecoder\(\)[\s\S]*?onMalformedInput\(CodingErrorAction\.REPORT\)[\s\S]*?onUnmappableCharacter\(CodingErrorAction\.REPORT\)/);
  assert.ok((androidCrypto.match(/decodeUtf8Strict\(/g) || []).length >= 6, 'saved key material and decrypted message/manifest JSON must use strict UTF-8');
  assert.match(androidCrypto, /xCoordinate\.compareTo\(prime\) >= 0 \|\| yCoordinate\.compareTo\(prime\) >= 0/);
  assert.match(androidCrypto, /if \(!lhs\.equals\(rhs\)\) throw new IllegalArgumentException\("P-256 public point is not on the curve\."\)/);
  const androidCryptoTest = fs.readFileSync(path.join(__dirname, '../../../apps/android/app/src/androidTest/java/io/serein/chat/SereinDeviceCryptoTest.java'), 'utf8');
  assert.match(androidCryptoTest, /testValidP256GeneratorPointIsAccepted/);
  assert.match(androidCryptoTest, /testOffCurveP256PointIsRejectedBeforeAgreement/);
  assert.match(androidCryptoTest, /testNativeEcdhAndNestedAesGcmRoundTripRejectsTampering/);
  assert.match(androidCryptoTest, /catch \(AEADBadTagException expected\)/);
  assert.match(androidCryptoTest, /testAuthenticatedPayloadMustBeValidUtf8/);
});

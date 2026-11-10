const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { webcrypto } = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname, '../device-crypto.js'), 'utf8');
const context = { crypto: webcrypto, TextEncoder, Uint8Array, ArrayBuffer, atob, btoa, window: {} };
vm.runInNewContext(source, context, { filename: 'device-crypto.js' });
const cryptoAdapter = context.window.SereinDeviceCrypto;

test('device signing key is purpose-separated, non-extractable, and emits interoperable DER ECDSA proof', async () => {
  const pair = await cryptoAdapter.generateSigningKeyPair();
  assert.equal(pair.privateKey.extractable, false);
  assert.equal(pair.publicJwk.crv, 'P-256');
  const user = '123e4567-e89b-12d3-a456-426614174000';
  const device = '123e4567-e89b-12d3-a456-426614174001';
  const oldFingerprint = 'a'.repeat(64);
  const newFingerprint = 'b'.repeat(64);
  const timestamp = 1_800_000_000;
  const proof = await cryptoAdapter.signDeviceKeyRotation(pair.privateKey, user, device, oldFingerprint, newFingerprint, timestamp, 2);
  assert.match(proof, /^[A-Za-z0-9_-]+$/);
  assert.equal(await cryptoAdapter.verifyDeviceKeyRotation(pair.publicJwk, user, device, oldFingerprint, newFingerprint, timestamp, 2, proof), true);
  assert.equal(await cryptoAdapter.verifyDeviceKeyRotation(pair.publicJwk, user, device, oldFingerprint, 'c'.repeat(64), timestamp, 2, proof), false);
  assert.equal(await cryptoAdapter.verifyDeviceKeyRotation(pair.publicJwk, user, device, oldFingerprint, newFingerprint, timestamp + 1, 2, proof), false);
  assert.equal(await cryptoAdapter.verifyDeviceKeyRotation(pair.publicJwk, user, device, oldFingerprint, newFingerprint, timestamp, 3, proof), false);
});

test('history-sync AES-GCM AAD has one compact cross-platform JSON byte representation', () => {
  const account = '123E4567-E89B-12D3-A456-426614174000';
  const main = '123e4567-e89b-12d3-a456-426614174001';
  const child = '123e4567-e89b-12d3-a456-426614174002';
  const request = '123e4567-e89b-12d3-a456-426614174003';
  const actual = new TextDecoder().decode(cryptoAdapter.historySyncAadBytes(account, main, child, request, 1, 2));
  assert.equal(actual, '["serein-history-sync-batch-v1","123e4567-e89b-12d3-a456-426614174000","123e4567-e89b-12d3-a456-426614174001","123e4567-e89b-12d3-a456-426614174002","123e4567-e89b-12d3-a456-426614174003",1,2,1]');
  assert.throws(() => cryptoAdapter.historySyncAadBytes(account, main, child, request, 2, 2));
});

test('main-to-child history sync keys are direction-independent, context-bound, and authenticated', async () => {
  const main = await cryptoAdapter.generateDeviceKeyPair();
  const child = await cryptoAdapter.generateDeviceKeyPair();
  const account = '123e4567-e89b-12d3-a456-426614174000';
  const mainId = '123e4567-e89b-12d3-a456-426614174001';
  const childId = '123e4567-e89b-12d3-a456-426614174002';
  const request = '123e4567-e89b-12d3-a456-426614174003';
  const senderKey = await cryptoAdapter.deriveHistorySyncKey(main.privateKey, account, mainId, childId, child.publicJwk, mainId, childId, request, 0, 1);
  const receiverKey = await cryptoAdapter.deriveHistorySyncKey(child.privateKey, account, childId, mainId, main.publicJwk, mainId, childId, request, 0, 1);
  const envelope = await cryptoAdapter.encryptHistorySyncBatch(senderKey, JSON.stringify({ schema_version: 1, messages: [] }), account, mainId, childId, request, 0, 1);
  const clear = await cryptoAdapter.decryptHistorySyncBatch(receiverKey, envelope, account, mainId, childId, request, 0, 1);
  assert.equal(new TextDecoder().decode(clear), '{"schema_version":1,"messages":[]}');
  await assert.rejects(cryptoAdapter.decryptHistorySyncBatch(receiverKey, envelope, account, mainId, childId, request, 0, 2));
});

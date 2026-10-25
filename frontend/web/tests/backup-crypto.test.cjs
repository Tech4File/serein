const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

global.crypto = webcrypto;
global.window = {};
const backupCrypto = require('../backup-crypto.js');

const alice = { accountId: '8ac15a50-267e-4d62-8e16-b0854d1c722d', username: 'alice' };
const bob = { accountId: 'dcd49674-a488-4b43-b209-b365ea140e49', username: 'bob' };
const LEGACY_V1 = 'U0VSRUlOQksAAAF8eyJmb3JtYXQiOiJTRVJFSU4tQkFDS1VQIiwidmVyc2lvbiI6MSwia2RmIjoiUEJLREYyLUhNQUMtU0hBMjU2IiwiaXRlcmF0aW9ucyI6NjAwMDAwLCJzYWx0IjoieGRkQkFYSnNWSkc5V29OVHBmWm5ZdyIsInNuYXBzaG90X2lkIjoiMTExMTExMTEtMTExMS00MTExLTgxMTEtMTExMTExMTExMTExIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTAtMjRUMDA6MDA6MDAuMDAwWiIsImNvbXByZXNzaW9uIjoiZGVmbGF0ZSIsImtleV93cmFwX2l2IjoiaU1UdV9YYW5QRUZzdkNONCIsIndyYXBwZWRfa2V5IjoiemFTcjdhQlk2V0htYTRaQTZkb21XRzBFLUQyYk1GNXlHNE5yZFNxX3RmalFUdkR1YUczdTdTYVNWSXJRcm5WNiIsInBheWxvYWRfaXYiOiJ1RXY3QkNwN3JETWlZSVJoIn03L0za/2w6pCFtVOgnfLy/SNYcCoJgXWp3/g9wKYW9ZBWTkm0FZ+jDR+IQCOmofREkCMGJB/JHbXlLG5V2kPX3yEHCQHlhqEc+BZC15bLx0Qfy5CfuCS6XG53otuOndy4UQVRyC6A6l3IWu3Otd1NBb6PDvP4WYxff7Yr8tz3D3pkMWniGlHi+2VcVf20zbBDDynhTxKGAEYM56zRror0rXljFsrsY3hGt6o7x8vGzy1wy/2G82lxDJ37xGWrL1xyqHyZYFkGMmYllJp+9K62OEdbL+kuLm5ndi262EuLmh+egRdS0yZGi72QlyVIKhClNKwqmLi/SJ9i70Q==';

function readHeader(bytes) {
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, false);
  return JSON.parse(new TextDecoder().decode(bytes.subarray(12, 12 + size)));
}
function replaceHeader(bytes, header) {
  const oldSize = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, false);
  const headerBytes = new TextEncoder().encode(JSON.stringify(header));
  const payloadStart = 12 + oldSize;
  const rebuilt = new Uint8Array(12 + headerBytes.length + bytes.length - payloadStart);
  rebuilt.set(bytes.subarray(0, 8), 0);
  new DataView(rebuilt.buffer).setUint32(8, headerBytes.length, false);
  rebuilt.set(headerBytes, 12);
  rebuilt.set(bytes.subarray(payloadStart), 12 + headerBytes.length);
  return rebuilt;
}

test('new backups use a stable account-specific key without asking for or storing a password', async () => {
  const snapshot = { messages: [{ id: 'm1', text: 'hello 🌧️', createdAt: '2026-10-25T00:00:00Z' }], trust: { peer: 'a'.repeat(64) } };
  const result = await backupCrypto.encrypt(alice, snapshot, { createdAt: '2026-10-25T04:30:00.000Z' });
  assert.ok(result.bytes instanceof Uint8Array);
  assert.match(result.filename, /^serein-backup-.*\.srbk$/);
  const inspected = backupCrypto.inspect(result.bytes);
  assert.equal(inspected.version, 2);
  assert.equal(inspected.createdAt, '2026-10-25T04:30:00.000Z');
  assert.ok(['deflate', 'none'].includes(inspected.compression));
  const header = readHeader(result.bytes);
  assert.equal(header.format, 'SEREIN-BACKUP');
  assert.equal(header.kdf, 'HKDF-SHA256-ACCOUNT-UUID');
  assert.equal(header.key_derivation_version, 1);
  assert.equal(Object.hasOwn(header, 'username'), false);
  assert.equal(Object.hasOwn(header, 'accountId'), false);
  assert.equal(Object.hasOwn(header, 'account_id'), false);
  const raw = new TextDecoder().decode(result.bytes);
  assert.equal(raw.includes(alice.accountId), false);
  assert.equal(raw.includes(alice.username), false);
  assert.deepEqual((await backupCrypto.decrypt(alice, result.bytes)).data, snapshot);
});

test('per-account key is stable across snapshots and username changes; each payload nonce is fresh', async () => {
  const first = await backupCrypto.encrypt(alice, { messages: [] });
  const second = await backupCrypto.encrypt(alice, { messages: [] });
  const renamed = await backupCrypto.decrypt({ ...alice, username: 'alice-renamed' }, first.bytes);
  assert.deepEqual(renamed.data, { messages: [] });
  const a = readHeader(first.bytes), b = readHeader(second.bytes);
  assert.notEqual(a.snapshot_id, b.snapshot_id);
  assert.notEqual(a.payload_iv, b.payload_iv);
  assert.equal(a.kdf, b.kdf);
  assert.equal(a.key_derivation_version, b.key_derivation_version);
});

test('another account cannot open the snapshot; header and ciphertext tampering are rejected', async () => {
  const result = await backupCrypto.encrypt(alice, { messages: [{ id: 'secret' }] });
  await assert.rejects(backupCrypto.decrypt(bob, result.bytes), /could not be opened/);
  const corruptedPayload = result.bytes.slice();
  corruptedPayload[corruptedPayload.length - 1] ^= 0x80;
  await assert.rejects(backupCrypto.decrypt(alice, corruptedPayload), /could not be opened/);
  const header = readHeader(result.bytes);
  header.created_at = '2026-10-24T04:30:00.000Z';
  await assert.rejects(backupCrypto.decrypt(alice, replaceHeader(result.bytes, header)), /could not be opened/);
});

test('legacy password-based version 1 files remain restorable, but wrong passwords and accounts fail', async () => {
  const bytes = Uint8Array.from(Buffer.from(LEGACY_V1, 'base64'));
  assert.equal(backupCrypto.inspect(bytes).version, 1);
  const restored = await backupCrypto.decrypt(alice, bytes, 'legacy-test-pass');
  assert.deepEqual(restored.data, { snapshot_version: 1, created_at: '2026-10-24T00:00:00.000Z', messages: [], contacts: [], media: { included: false, policy: 'references-only' } });
  await assert.rejects(backupCrypto.decrypt(alice, bytes, 'wrong-pass'), /could not be opened/);
  await assert.rejects(backupCrypto.decrypt(bob, bytes, 'legacy-test-pass'), /could not be opened/);
});

test('malformed containers and unsupported key-derivation versions are refused', async () => {
  assert.throws(() => backupCrypto.inspect(new Uint8Array([1, 2, 3])), /malformed|Serein/i);
  const result = await backupCrypto.encrypt(alice, { messages: [] });
  const header = readHeader(result.bytes);
  header.key_derivation_version = 99;
  assert.throws(() => backupCrypto.inspect(replaceHeader(result.bytes, header)), /unsafe backup format parameters/);
});

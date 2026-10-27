const test = require('node:test');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');

global.crypto = webcrypto;
global.window = {};
const backupCrypto = require('../backup-crypto.js');

const alice = { accountId: '8ac15a50-267e-4d62-8e16-b0854d1c722d', username: 'alice' };
const bob = { accountId: 'dcd49674-a488-4b43-b209-b365ea140e49', username: 'bob' };
const BACKUP_KEY = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
const LEGACY_V1 = 'U0VSRUlOQksAAAF8eyJmb3JtYXQiOiJTRVJFSU4tQkFDS1VQIiwidmVyc2lvbiI6MSwia2RmIjoiUEJLREYyLUhNQUMtU0hBMjU2IiwiaXRlcmF0aW9ucyI6NjAwMDAwLCJzYWx0IjoieGRkQkFYSnNWSkc5V29OVHBmWm5ZdyIsInNuYXBzaG90X2lkIjoiMTExMTExMTEtMTExMS00MTExLTgxMTEtMTExMTExMTExMTExIiwiY3JlYXRlZF9hdCI6IjIwMjYtMTAtMjRUMDA6MDA6MDAuMDAwWiIsImNvbXByZXNzaW9uIjoiZGVmbGF0ZSIsImtleV93cmFwX2l2IjoiaU1UdV9YYW5QRUZzdkNONCIsIndyYXBwZWRfa2V5IjoiemFTcjdhQlk2V0htYTRaQTZkb21XRzBFLUQyYk1GNXlHNE5yZFNxX3RmalFUdkR1YUczdTdTYVNWSXJRcm5WNiIsInBheWxvYWRfaXYiOiJ1RXY3QkNwN3JETWlZSVJoIn03L0za/2w6pCFtVOgnfLy/SNYcCoJgXWp3/g9wKYW9ZBWTkm0FZ+jDR+IQCOmofREkCMGJB/JHbXlLG5V2kPX3yEHCQHlhqEc+BZC15bLx0Qfy5CfuCS6XG53otuOndy4UQVRyC6A6l3IWu3Otd1NBb6PDvP4WYxff7Yr8tz3D3pkMWniGlHi+2VcVf20zbBDDynhTxKGAEYM56zRror0rXljFsrsY3hGt6o7x8vGzy1wy/2G82lxDJ37xGWrL1xyqHyZYFkGMmYllJp+9K62OEdbL+kuLm5ndi262EuLmh+egRdS0yZGi72QlyVIKhClNKwqmLi/SJ9i70Q==';
const enc = new TextEncoder();
const b64url = bytes => Buffer.from(bytes).toString('base64url');
function readHeader(bytes) {
  const size = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, false);
  return JSON.parse(new TextDecoder().decode(bytes.subarray(12, 12 + size)));
}
function replaceHeader(bytes, header) {
  const oldSize = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(8, false);
  const headerBytes = enc.encode(JSON.stringify(header));
  const payloadStart = 12 + oldSize;
  const rebuilt = new Uint8Array(12 + headerBytes.length + bytes.length - payloadStart);
  rebuilt.set(bytes.subarray(0, 8), 0);
  new DataView(rebuilt.buffer).setUint32(8, headerBytes.length, false);
  rebuilt.set(headerBytes, 12);
  rebuilt.set(bytes.subarray(payloadStart), 12 + headerBytes.length);
  return rebuilt;
}
async function makeV2File(identity, snapshot) {
  const created = '2026-10-25T04:30:00.000Z', snapshotId = '11111111-1111-4111-8111-111111111111';
  const payload = enc.encode(JSON.stringify({ format:'SEREIN-BACKUP', version:2, owner:{accountId:identity.accountId,username:identity.username}, created_at:created, snapshot_id:snapshotId, data:snapshot }));
  const compressed = new Uint8Array(await new Response(new Blob([payload]).stream().pipeThrough(new CompressionStream('deflate'))).arrayBuffer());
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const header = { format:'SEREIN-BACKUP', version:2, kdf:'HKDF-SHA256-ACCOUNT-UUID', key_derivation_version:1, snapshot_id:snapshotId, created_at:created, compression:'deflate', payload_iv:b64url(iv) };
  const idBytes = enc.encode(identity.accountId);
  const material = await crypto.subtle.importKey('raw', idBytes, 'HKDF', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt:enc.encode('Serein backup account key v2'),info:enc.encode('Serein backup stable key v1')},material,{name:'AES-GCM',length:256},false,['encrypt']);
  const aad = enc.encode(JSON.stringify(['serein-backup-payload-v2','SEREIN-BACKUP',2,identity.accountId,snapshotId,created,'deflate',header.kdf,1,header.payload_iv]));
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:aad,tagLength:128},key,compressed));
  const headerBytes = enc.encode(JSON.stringify(header)), packed = new Uint8Array(12 + headerBytes.length + ciphertext.length);
  packed.set(enc.encode('SEREINBK'),0);new DataView(packed.buffer).setUint32(8,headerBytes.length,false);packed.set(headerBytes,12);packed.set(ciphertext,12+headerBytes.length);return packed;
}

test('new v3 backups encrypt with a supplied random server backup key without embedding identity metadata', async () => {
  const snapshot = { messages: [{ id: 'm1', text: 'hello 🌧️', createdAt: '2026-10-25T00:00:00Z' }], trust: { peer: 'a'.repeat(64) } };
  const key = BACKUP_KEY.slice();
  const result = await backupCrypto.encrypt(alice, snapshot, key, { createdAt: '2026-10-25T04:30:00.000Z' });
  assert.ok(result.bytes instanceof Uint8Array);
  assert.match(result.filename, /^serein-backup-.*\.srbk$/);
  const inspected = backupCrypto.inspect(result.bytes);
  assert.equal(inspected.version, 3);
  assert.equal(inspected.createdAt, '2026-10-25T04:30:00.000Z');
  assert.equal(inspected.compression, 'deflate');
  const header = readHeader(result.bytes);
  assert.equal(header.format, 'SEREIN-BACKUP');
  assert.equal(header.kdf, 'HKDF-SHA256-SERVER-BACKUP-KEY');
  assert.equal(header.key_derivation_version, 1);
  assert.equal(Buffer.from(header.salt,'base64url').length,16);
  for (const field of ['username','accountId','account_id']) assert.equal(Object.hasOwn(header,field),false);
  const raw = new TextDecoder().decode(result.bytes);
  assert.equal(raw.includes(alice.accountId), false);
  assert.equal(raw.includes(alice.username), false);
  assert.deepEqual((await backupCrypto.decrypt(alice, result.bytes, '', key)).data, snapshot);
  assert.notEqual(key[0], 0, 'the crypto codec does not mutate the caller-owned key');
});

test('new backup creation fails closed rather than emitting an uncompressed file when DEFLATE is unavailable', async () => {
  const original = global.CompressionStream;
  try { global.CompressionStream = undefined; await assert.rejects(backupCrypto.encrypt(alice, { messages: [] }, BACKUP_KEY), /cannot create a compressed backup/i); }
  finally { global.CompressionStream = original; }
});

test('stable backup key works across snapshots and username changes; nonces and salts are fresh', async () => {
  const first = await backupCrypto.encrypt(alice, { messages: [] }, BACKUP_KEY);
  const second = await backupCrypto.encrypt(alice, { messages: [] }, BACKUP_KEY);
  const renamed = await backupCrypto.decrypt({ ...alice, username: 'alice-renamed' }, first.bytes, '', BACKUP_KEY);
  assert.deepEqual(renamed.data, { messages: [] });
  const a = readHeader(first.bytes), b = readHeader(second.bytes);
  assert.notEqual(a.snapshot_id, b.snapshot_id);
  assert.notEqual(a.payload_iv, b.payload_iv);
  assert.notEqual(a.salt, b.salt);
  assert.equal(a.kdf, b.kdf);
});

test('another account or wrong server key cannot open the snapshot; header and ciphertext tampering fail', async () => {
  const result = await backupCrypto.encrypt(alice, { messages: [{ id: 'secret' }] }, BACKUP_KEY);
  await assert.rejects(backupCrypto.decrypt(bob, result.bytes, '', BACKUP_KEY), /could not be opened/);
  await assert.rejects(backupCrypto.decrypt(alice, result.bytes, '', new Uint8Array(32).fill(9)), /could not be opened/);
  const corruptedPayload = result.bytes.slice();corruptedPayload[corruptedPayload.length - 1] ^= 0x80;
  await assert.rejects(backupCrypto.decrypt(alice, corruptedPayload, '', BACKUP_KEY), /could not be opened/);
  const header = readHeader(result.bytes);header.created_at = '2026-10-24T04:30:00.000Z';
  await assert.rejects(backupCrypto.decrypt(alice, replaceHeader(result.bytes, header), '', BACKUP_KEY), /could not be opened/);
});

test('legacy password-based v1 files remain restorable', async () => {
  const bytes = Uint8Array.from(Buffer.from(LEGACY_V1, 'base64'));
  assert.equal(backupCrypto.inspect(bytes).version, 1);
  const restored = await backupCrypto.decrypt(alice, bytes, 'legacy-test-pass');
  assert.deepEqual(restored.data, { snapshot_version: 1, created_at: '2026-10-24T00:00:00.000Z', messages: [], contacts: [], media: { included: false, policy: 'references-only' } });
  await assert.rejects(backupCrypto.decrypt(alice, bytes, 'wrong-pass'), /could not be opened/);
  await assert.rejects(backupCrypto.decrypt(bob, bytes, 'legacy-test-pass'), /could not be opened/);
});

test('legacy account-ID-derived v2 files remain restorable after the v3 migration', async () => {
  const snapshot={messages:[{id:'old-v2'}]};const bytes=await makeV2File(alice,snapshot);
  assert.equal(backupCrypto.inspect(bytes).version,2);
  assert.deepEqual((await backupCrypto.decrypt(alice,bytes)).data,snapshot);
  await assert.rejects(backupCrypto.decrypt(bob,bytes),/could not be opened/);
});

test('malformed containers, unsupported KDF versions, and missing keys are refused', async () => {
  assert.throws(() => backupCrypto.inspect(new Uint8Array([1,2,3])), /malformed|Serein/i);
  await assert.rejects(backupCrypto.encrypt(alice,{messages:[]}),/server backup key is unavailable/i);
  const result=await backupCrypto.encrypt(alice,{messages:[]},BACKUP_KEY);const header=readHeader(result.bytes);header.key_derivation_version=99;
  assert.throws(()=>backupCrypto.inspect(replaceHeader(result.bytes,header)),/unsafe backup format parameters/);
});

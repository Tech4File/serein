const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const web = fs.readFileSync(path.join(root, 'frontend/web/backup-crypto.js'), 'utf8');
const android = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinBackupStore.java'), 'utf8');
const ios = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinBackupStore.swift'), 'utf8');

test('all backup platforms use the same stable account-key HKDF context', () => {
  for (const source of [web, android, ios]) {
    assert.match(source, /HKDF-SHA256-ACCOUNT-UUID|hkdfDerivedKey/);
    assert.match(source, /Serein backup account key v2/);
    assert.match(source, /AES-GCM|AES\/GCM\/NoPadding|AES\.GCM/);
  }
  assert.match(web, /Serein backup stable key v\$\{KEY_DERIVATION_VERSION\}/);
  assert.match(android, /Serein backup stable key v1/);
  assert.match(ios, /Serein backup stable key v1/);
  assert.match(web, /KEY_DERIVATION_VERSION = 1/);
  assert.match(android, /KDF_VERSION\s*=\s*1/);
  assert.match(ios, /key_derivation_version.*1/);
});

test('all new v2 backup exports require zlib DEFLATE before AES-GCM', () => {
  assert.match(web, /CompressionStream/);
  assert.match(web, /compression:\s*'deflate'/);
  assert.match(android, /DeflaterOutputStream/);
  assert.match(android, /String compression="deflate"/);
  assert.doesNotMatch(android, /compressed=clear\.clone\(\)/);
  assert.match(ios, /compression_encode_buffer/);
  assert.match(ios, /COMPRESSION_ZLIB/);
  assert.match(ios, /"compression": "deflate"/);
});

test('v2 AAD domain and stable field ordering remain shared across the clients', () => {
  assert.match(web, /'serein-backup-payload-v2', FORMAT, VERSION, identity\.accountId,[\s\S]*header\.snapshot_id, header\.created_at, header\.compression,[\s\S]*header\.kdf, header\.key_derivation_version, header\.payload_iv/);
  assert.match(android, /array\("serein-backup-payload-v2",FORMAT,V2,id,h\.getString\("snapshot_id"\),h\.getString\("created_at"\),h\.getString\("compression"\),h\.getString\("kdf"\),h\.getInt\("key_derivation_version"\),h\.getString\("payload_iv"\)\)/);
  assert.match(ios, /\["serein-backup-payload-v2", format, 2, accountID, snapshot, created, compression, kdf, derivation, iv\]/);
});

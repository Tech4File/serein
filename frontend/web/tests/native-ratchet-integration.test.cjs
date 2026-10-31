const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');
const android = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
const androidRatchet = read('apps/android/app/src/main/java/io/serein/chat/SereinRatchetSession.java');
const androidCrypto = read('apps/android/app/src/main/java/io/serein/chat/SereinDeviceCrypto.java');
const androidStore = read('apps/android/app/src/main/java/io/serein/chat/SereinLocalStore.java');
const ios = read('apps/ios/SereinChat/SereinChatEngine.swift');
const iosRatchet = read('apps/ios/SereinChat/SereinLayeredRatchet.swift');
const iosCrypto = read('apps/ios/SereinChat/SereinDeviceCrypto.swift');
const iosStore = read('apps/ios/SereinChat/SereinLocalStore.swift');
const web = read('frontend/web/app.js');
const webCrypto = read('frontend/web/device-crypto.js');
const webRatchet = read('frontend/web/layered-ratchet.js');

test('all clients advertise v3 only when the shared core is active and route capable peers through crypto v3', () => {
  assert.match(android, /SereinCoreNative\.isLoaded\(\)\?3:2/);
  assert.match(android, /target\.ratchetVersion>=3&&SereinCoreNative\.isLoaded\(\)/);
  assert.match(android, /cryptoVersion=3/);
  assert.match(ios, /SereinCoreBridge\.version == "unavailable" \? 2 : 3/);
  assert.match(ios, /peer\.ratchetVersion >= 3 && SereinCoreBridge\.version != "unavailable"/);
  assert.match(ios, /encrypted\["crypto_version"\] = "3"/);
  assert.match(web, /ratchet_version:window\.SereinCore\?\.wasmActive\?3:2/);
});

test('Android, iOS, and browser use the same v3 bootstrap, session, and layered AAD domains', () => {
  for (const source of [androidCrypto, iosCrypto, webCrypto]) {
    assert.match(source, /symmetric-ratchet-salt\/v1/);
    assert.match(source, /symmetric-ratchet-bootstrap\/v1/);
  }
  for (const source of [androidRatchet, ios, web]) assert.match(source, /live-ratchet-session\/v1/);
  for (const source of [androidRatchet, iosRatchet, webRatchet]) {
    assert.match(source, /serein-message-v3-/);
    assert.match(source, /SRL1|0x53, 0x52, 0x4c, 0x31/);
  }
});

test('new file uploads use nested chunk crypto v2 across clients while v1 remains readable', () => {
  assert.ok(webCrypto.includes('serein-transfer-chunk-${layer}-v2'));
  assert.match(webCrypto, /transferChunkLayerAad\([^\n]*'layer1'\)/);
  assert.match(webCrypto, /transferChunkLayerAad\([^\n]*'layer2'\)/);
  assert.match(androidCrypto, /chunkLayerAad\("layer1"[\s\S]*chunkLayerAad\("layer2"/);
  assert.ok(iosCrypto.includes('serein-transfer-chunk-\\(layer)-v2'));
  assert.match(iosCrypto, /layer: "layer1"[\s\S]*layer: "layer2"/);
  assert.match(webCrypto, /encryptTransferChunkLayer2[\s\S]*decryptTransferChunkLayer2/);
  assert.match(androidCrypto, /encryptChunkLayer2[\s\S]*decryptChunkLayer2/);
  assert.match(iosCrypto, /encryptChunkLayer2[\s\S]*decryptChunkLayer2/);
  assert.match(web, /chunk_crypto_version:2/);
  assert.match(android, /put\("chunk_crypto_version",2\)/);
  assert.match(ios, /"chunk_crypto_version": 2/);
  assert.match(web, /decryptTransferChunk\(fileKey/);
  assert.match(android, /:SereinDeviceCrypto\.decryptChunk\(contentKey/);
  assert.match(ios, /SereinDeviceCrypto\.decryptChunk\(ciphertext/);
  assert.match(read('backend/src/main.rs'), /chunk_crypto_version SMALLINT NOT NULL DEFAULT 1/);
  assert.match(read('backend/src/main.rs'), /minimum_tag_bytes=match input\.chunk_crypto_version\{1=>16,2=>32/);
  assert.match(read('backend/migrations/0014_transfer_chunk_layer2.sql'), /DEFAULT 1/);
  assert.match(read('apps/android/app/src/androidTest/java/io/serein/chat/SereinDeviceCryptoTest.java'), /testLayeredTransferChunkMatchesSharedVector/);
  const vector = JSON.parse(read('frontend/web/tests/fixtures/transfer-chunk-v2-vector.json'));
  assert.equal(vector.version, 2);
  assert.equal(Buffer.from(vector.ciphertext_hex, 'hex').length, Buffer.from(vector.plaintext_utf8).length + 32);
});

test('ratchet snapshots and message commits share encrypted local storage and stay out of backups', () => {
  assert.match(androidStore, /saveRatchetMessage\(JSONObject message, java\.util\.Map<String, byte\[]> snapshots\)/);
  assert.match(android, /local\.saveRatchetMessage\(message,snapshots\)/);
  assert.match(iosStore, /save\(_ message: \[String: Any\], ratchetSnapshots: \[String: Data\]\)/);
  assert.match(ios, /local\.save\(row, ratchetSnapshots: session\.snapshots\(\)\)/);
  assert.match(androidStore, /backupMessages\(\)[\s\S]*root\.getJSONArray\("messages"\)/);
  assert.match(iosStore, /func backupMessages\(\)[\s\S]*root\["messages"\]/);
  assert.match(androidStore, /refusing to reset the session/);
});

test('native file manifests keep two-layer crypto-v2 compatibility with bounded transfer chunks', () => {
  assert.match(android, /encryptManifestLayer2\(target\.layer2Key/);
  assert.match(android, /new JSONObject\(\)\.put\("version",1\)\.put\("algorithm","AES-256-GCM"\)/);
  assert.match(android, /"crypto_version",2/);
  assert.match(ios, /encryptManifestLayer2\(inner, key: peer\.layer2Key/);
  assert.match(read('apps/ios/SereinChat/SereinDeviceCrypto.swift'), /"algorithm": "AES-256-GCM"/);
  assert.match(ios, /"crypto_version": 2/);
  assert.match(android, /manifest_crypto_version/);
  assert.match(ios, /manifest_crypto_version/);
});

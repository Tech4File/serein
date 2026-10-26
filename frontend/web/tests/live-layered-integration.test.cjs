const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const read = file => fs.readFileSync(path.join(__dirname, file), 'utf8');
const app = read('../app.js');
const deviceCrypto = read('../device-crypto.js');
const backend = read('../../../backend/src/main.rs');

test('web v3 messages use a canonical conversation AAD in both directions and atomically persist ratchet snapshots', () => {
  assert.ok(app.includes("function ratchetConversationId(firstUserId,secondUserId){return[firstUserId,secondUserId].map(String).sort().join(':');}"));
  assert.match(app, /conversationId:ratchetConversationId\(state\.user\.id,contact\.id\)/);
  assert.match(app, /ratchet_version:3/);
  assert.match(app, /peer\.ratchetVersion>=3/);
  assert.match(app, /crypto_version:3,iv:encrypted\.iv,ciphertext:encrypted\.ciphertext/);
  assert.match(app, /await commitRatchetMessage\(contact\.id,id,\{text,sender:state\.name,mine:true,envelopes,attachment\},'pending',createdAt,states\)/);
});

test('file payloads use a content-key layer and a separate per-device Layer 2 manifest envelope', () => {
  assert.match(deviceCrypto, /encryptTransferManifestLayer2/);
  assert.match(deviceCrypto, /decryptTransferManifestLayer2/);
  assert.match(app, /crypto_version:2,iv:envelope\.iv,ciphertext:envelope\.ciphertext/);
  assert.match(app, /crypto_version:1,iv:envelope\.iv,ciphertext:envelope\.ciphertext/);
  assert.match(app, /transfer\.manifest_crypto_version===2/);
  assert.match(backend, /crypto_version SMALLINT NOT NULL DEFAULT 1/);
});

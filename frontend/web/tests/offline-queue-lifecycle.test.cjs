const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const backend = fs.readFileSync(path.join(root, 'backend/src/main.rs'), 'utf8');
const android = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java'), 'utf8');
const ios = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinChatEngine.swift'), 'utf8');
const web = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');

test('mailbox pages contain only unacknowledged ciphertext and use an accurate bounded has_more flag', () => {
  const start = backend.indexOf('async fn list_messages(');
  const end = backend.indexOf('\nasync fn ack_message_api', start);
  assert.notEqual(start, -1);
  const body = backend.slice(start, end);
  assert.match(body, /delivered_at IS NULL/);
  assert.match(body, /\.bind\(limit\+1\)/);
  assert.match(body, /let has_more=rows\.len\(\) as i64>limit/);
  assert.match(body, /"has_more":has_more/);
});

test('ACK deletes only the recipient device copy; cleanup also hard-expires undelivered packets after 30 days', () => {
  assert.match(backend, /DELETE FROM queued_ciphertexts WHERE recipient_device_id=\$1 AND id=\$2/);
  assert.match(backend, /created_at<=now\(\)-interval '30 days'[\s\S]*LIMIT 500/);
  assert.match(backend, /queued_ciphertexts_delivered_cleanup ON queued_ciphertexts\(delivered_at,recipient_device_id,id\) WHERE delivered_at IS NOT NULL/);
  assert.match(backend, /legacy acknowledged ciphertext packets purged/);
  assert.match(backend, /expired ciphertext packets purged/);
});

test('Android waits for the server ACK after local encrypted-store commit', () => {
  const start = android.indexOf('private CompletableFuture<Void> processHistoryItem');
  const end = android.indexOf('\n    private synchronized void advance', start);
  const body = android.slice(start, end);
  assert.ok(body.indexOf('decryptAndStoreIncoming(peer,packet,id,senderDevice,created)') < body.lastIndexOf('api.acknowledgeFuture(id).get'));
  const commit = android.slice(android.indexOf('private JSONObject decryptAndStoreIncoming'), android.indexOf('private synchronized void advance'));
  assert.match(commit, /local\.saveRatchetMessage\(message,snapshots\)/);
  assert.match(commit, /local\.saveMessage\(message\)/);
  assert.match(body, /api\.acknowledgeFuture\(id\)\.get\(20,TimeUnit\.SECONDS\);advance\(created,id\)/);
});

test('iOS awaits ACK on both duplicate and newly committed local messages', () => {
  assert.match(ios, /if local\.contains\(messageID: id\) \{ try await api\.acknowledgeMessage\(id\); cursorTime = created; cursorID = id; continue \}/);
  assert.match(ios, /try decryptAndStoreIncoming\(peer: peer, packet: packet, messageID: id, senderDeviceID: senderDeviceID, createdAt: created, user: user, device: device\)\s*\n\s*try await api\.acknowledgeMessage\(id\)/);
  assert.match(ios, /try local\.save\(row, ratchetSnapshots: session\.snapshots\(\)\)/);
  assert.match(ios, /try local\.save\(incomingRow\(clear, messageID: messageID, senderDeviceID: senderDeviceID, createdAt: createdAt, user: user, device: device\)\)/);
});

test('web stores an incoming message locally before awaiting ACK', () => {
  const start = web.indexOf('async function processPacket(');
  const end = web.indexOf('\n  async function handlePacket', start);
  const body = web.slice(start, end);
  assert.ok(body.indexOf('await storeLocalMessage(') < body.lastIndexOf('await acknowledgeMessage(packet.id)'));
  assert.match(body, /if\(state\.seenIds\.has\(packet\.id\)\)\{await acknowledgeMessage\(packet\.id\);return true;\}/);
});

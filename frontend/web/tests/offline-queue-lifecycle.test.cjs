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
  assert.match(body, /let\s+has_more\s*=\s*rows\.len\(\)\s+as\s+i64\s*>\s*limit/);
  assert.match(body, /"has_more":has_more/);
});

test('ACK deletes only the recipient device copy; offline queue and signed-in sessions have 30-day expiry and bounded capacity', () => {
  assert.match(backend, /DELETE FROM queued_ciphertexts WHERE recipient_device_id=\$1 AND id=\$2/);
  assert.match(backend, /created_at<=now\(\)-interval '30 days'[\s\S]*LIMIT 500/);
  assert.match(backend, /const SESSION_SECONDS: i64 = 60 \* 60 \* 24 \* 30/);
  assert.match(backend, /const MAX_QUEUED_PER_DEVICE: i64 = 5_000/);
  assert.match(backend, /queued_ciphertexts_delivered_cleanup ON queued_ciphertexts\(delivered_at,recipient_device_id,id\) WHERE delivered_at IS NOT NULL/);
  assert.match(backend, /legacy acknowledged ciphertext packets purged/);
  assert.match(backend, /expired ciphertext packets purged/);
});

test('native clients retry durable pending sends while a conversation is open, with bounded retry cadence', () => {
  const activity = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java'), 'utf8');
  const product = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinProductView.swift'), 'utf8');
  assert.match(android, /PENDING_RETRY_INTERVAL_MS=30_000L/);
  assert.match(android, /void retryPending\(\)[\s\S]*?pendingRetryRunning\|\|now<nextPendingRetryAt/);
  assert.match(activity, /pollCounter%6==0\)\{engine\.retryPending\(\);/);
  assert.match(ios, /private let pendingRetryInterval: TimeInterval = 30/);
  assert.match(ios, /func retryPendingIfNeeded\(force: Bool = false\)[\s\S]*?pendingRetryRunning[\s\S]*?nextPendingRetryAt/);
  assert.match(product, /cycles % 6 == 0 \{ await engine\.retryPendingIfNeeded\(\)/);
  assert.match(web, /resendPendingMessages\(\)\.catch\(\(\)=>\{\}\)/);
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
  assert.match(body, /if\(state\.seenIds\.has\(packet\.id\)\)\{const knownConversation=.*?await acknowledgeMessage\(packet\.id\);.*?return true;\}/);
});

test('expired ciphertext is tombstoned atomically before deletion and surfaced to both parties for 90 days', () => {
  const migration = fs.readFileSync(path.join(root, 'backend/migrations/0017_message_expiry_tombstones.sql'), 'utf8');
  assert.match(migration, /ADD COLUMN IF NOT EXISTS expired_at TIMESTAMPTZ/);
  assert.match(migration, /expired_at IS NULL OR delivered_at IS NULL/);
  assert.match(backend, /WITH candidates AS MATERIALIZED[\s\S]*marked AS \(UPDATE message_receipts[\s\S]*deleted AS \(DELETE FROM queued_ciphertexts[\s\S]*RETURNING 1\)/);
  assert.match(backend, /EXPIRY_TOMBSTONE_TTL_DAYS: i64 = 90/);
  assert.match(backend, /DELETE FROM message_receipts WHERE expired_at<=now\(\)-make_interval\(days => \$1\)/);
  assert.match(backend, /async fn list_expired_messages[\s\S]*recipient_user_id=\$1 AND r\.recipient_device_id=\$2[\s\S]*expired_at IS NOT NULL/);
  assert.match(backend, /"expired_count":expired,"expired_at":expired_at/);
  assert.match(backend, /expired_at IS NULL/);
});

test('web, Android and iOS expose recipient expiry notices and explicit sender retry, never automatic expired resend', () => {
  const androidUi = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java'), 'utf8');
  const iosUi = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinProductView.swift'), 'utf8');
  assert.match(web, /async function syncExpiredNotices[\s\S]*\/api\/v1\/messages\/expiries/);
  assert.match(web, /item\.status==='expired'[\s\S]*Retry message/);
  assert.match(web, /sendMessage\(null,null,contact,null,\{text:item\.text,retryOf:item\.id\}\)/);
  assert.match(android, /refreshExpiredNotices\(\)/);
  assert.match(android, /expired>0\?"expired"/);
  assert.match(androidUi, /expired-notice|row\.optBoolean\("system"\)/);
  assert.match(androidUi, /"expired"\.equals\(row\.optString\("status"\)\)/);
  assert.match(ios, /private func refreshExpiredNotices\(\)/);
  assert.match(ios, /expired>0 \? "expired"/);
  assert.match(iosUi, /message\.status == "expired"/);
  assert.match(iosUi, /\$0\.isSystem \?/);
});

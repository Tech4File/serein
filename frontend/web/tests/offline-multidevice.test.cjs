const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const backend = fs.readFileSync(path.join(root, 'backend/src/main.rs'), 'utf8');
const web = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');
const android = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java'), 'utf8');
const androidActivity = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java'), 'utf8');
const iosProductView = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinProductView.swift'), 'utf8');
const ios = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinChatEngine.swift'), 'utf8');
const androidApi = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinApi.java'), 'utf8');
const iosApi = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinAPI.swift'), 'utf8');
const mobileMainMigration = fs.readFileSync(path.join(root, 'backend/migrations/0021_mobile_priority_main_device.sql'), 'utf8');

test('first main selection prefers the oldest active mobile, and all clients identify their platform explicitly', () => {
  assert.ok(backend.includes("ORDER BY CASE WHEN d.platform IN ('android','ios') THEN 0 ELSE 1 END,d.created_at ASC,d.id ASC"));
  assert.ok(backend.includes('an active iOS or Android device has main-device priority'));
  assert.match(mobileMainMigration, /main_device_designated/);
  assert.ok(mobileMainMigration.includes("ORDER BY CASE WHEN d.platform IN ('android','ios') THEN 0 ELSE 1 END"));
  assert.match(web, /device_platform:'web'/);
  assert.match(androidApi, /device_platform", "android"/);
  assert.match(iosApi, /device_platform": "ios"/);
  assert.match(web, /mainPlatform=directory\.main_device_platform/);
  assert.match(ios, /mainDevicePlatform=directory\["main_device_platform"\]/);
  assert.match(web, /historySyncRequest'\)\.hidden=!mainId/);
  assert.match(androidActivity, /if\(!mainId\.isEmpty\(\)\)\{labels\.add\("Request ‘Sync everything’ from main"\)/);
  assert.match(iosProductView, /if engine\.mainDeviceID != nil \{ Button\("Request/);
});

test('history relay is a short-lived encrypted transport with authenticated main-only access and quotas', () => {
  assert.match(backend, /main_device_id/);
  assert.match(backend, /history_sync_requests/);
  assert.match(backend, /expires_at[\s\S]*interval '24 hours'/);
  assert.match(backend, /MAX_HISTORY_SYNC_BATCH_BYTES: usize = 512 \* 1024/);
  assert.match(backend, /MAX_HISTORY_SYNC_BATCHES: i16 = 128/);
  assert.match(backend, /MAX_HISTORY_SYNC_ACCOUNT_BYTES: i64 = 256 \* 1024 \* 1024/);
  assert.match(backend, /main and requesting child must both be online during history sync/);
  assert.match(backend, /UPDATE accounts SET main_device_id=NULL WHERE main_device_id=\$1/);
  assert.match(backend, /UPDATE history_sync_requests SET status='cancelled' WHERE \(main_device_id=\$1 OR child_device_id=\$1\)/);
  assert.match(backend, /DELETE FROM history_sync_requests WHERE id IN/);
  assert.match(backend, /INSERT INTO history_sync_batches/);
  assert.match(backend, /ON CONFLICT\(request_id,batch_index\) DO UPDATE/);
  assert.match(backend, /main and requesting child must both be online during history sync/);
  assert.match(backend, /only the requesting child device can download/);
  assert.match(backend, /FROM history_sync_requests r JOIN accounts a ON a\.id=r\.user_id AND a\.main_device_id=r\.main_device_id/);
  assert.match(backend, /history-sync.*not an archive|main-device-only; no server history archive/);
});

test('each frontend has explicit main request/approval/import controls and does not transfer ratchets', () => {
  assert.match(web, /Request “Sync everything” from main/);
  assert.match(web, /Sync everything to this child device/);
  assert.match(web, /ratchet state was not changed/i);
  assert.match(android, /sendHistorySync\(/);
  assert.match(android, /receiveHistorySync\(/);
  assert.match(android, /requestHistorySync\(/);
  assert.match(android, /cancelHistorySync\(/);
  assert.match(ios, /func sendHistorySync\(/);
  assert.match(fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinProductView.swift'), 'utf8'), /confirmationDialog\("Send local history to this child\?/);
  assert.match(ios, /func receiveHistorySync\(/);
  assert.match(ios, /func requestHistorySync\(/);
});

test('history sync validates every local record and supports durable expiry notices across clients', () => {
  assert.match(web, /loadAccountLocalMessagesStrict/);
  assert.match(web, /validHistoryMessageId\(item\.id,item\.payload\)/);
  assert.match(android, /local message record failed history-sync validation/);
  assert.match(ios, /validHistoryTimestamp\(created\)/);
  assert.match(backend, /to_char\(r\.expired_at AT TIME ZONE 'UTC'/);
});

test('all clients retain separate signing identities and verify signed rotation chains locally', () => {
  assert.match(backend, /verify_device_key_rotation_signature/);
  assert.match(backend, /device_key_rotation_history/);
  assert.match(backend, /changed device key requires cryptographic continuity proof/);
  assert.match(web, /verifyDeviceKeyRotation/);
  assert.match(android, /verifyDeviceKeyRotation/);
  assert.match(ios, /verifyDeviceKeyRotation/);
  assert.match(web, /rotateCurrentDeviceKeys/);
  assert.match(android, /rotateDeviceKeys\(/);
  assert.match(ios, /rotateDeviceKeys\(/);
});

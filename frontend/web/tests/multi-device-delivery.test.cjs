const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

const web = read('frontend/web/app.js');
const androidActivity = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
const androidEngine = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
const iosApi = read('apps/ios/SereinChat/SereinAPI.swift');
const iosEngine = read('apps/ios/SereinChat/SereinChatEngine.swift');
const backend = read('backend/src/main.rs');

test('all clients register their own two-key device bundle at sign-in/session restore, not only on first chat open', () => {
  assert.match(web, /async function acceptAccount[\s\S]*?await ensureDeviceKeyEnrollment\(\)/);
  assert.match(androidActivity, /prepareSignedInDevice\(\(\)->\{renderMain\("Chats"\)/);
  assert.match(androidActivity, /SereinDeviceCrypto\.loadOrCreate\(this,userId,deviceId\)[\s\S]*?enrollDeviceKey/);
  assert.match(iosApi, /private func ensureDeviceKeyEnrollment\(\) async/);
  assert.match(iosApi, /await ensureDeviceKeyEnrollment\(\)[\s\S]*?await refreshAccountData\(\)/);
  assert.match(iosEngine, /func trustedTargets\(\) throws -> \[SereinPeerKey\]/);
});

test('web, Android, and iOS fan out a separately routed envelope to every active recipient device', () => {
  assert.match(web, /const targets=contact\.devices\.filter\(device=>device\.id!==state\.device\.id\)/);
  assert.match(web, /for\(const device of targets\)[\s\S]*?recipientDeviceId:device\.id/);
  assert.match(web, /envelopes\.push\(\{to:device\.id,crypto_version:/);
  const androidTargets = androidEngine.slice(androidEngine.indexOf('private List<Peer> trustedTargets()'), androidEngine.indexOf('private CompletableFuture<Void> deliver('));
  assert.match(androidTargets, /for\(int i=0;i<active\.length\(\);i\+\+\)/);
  assert.match(androidTargets, /targets\.add\(peer\)/);
  assert.match(androidEngine, /for\(Peer target:targets\)[\s\S]*?envelopes\.put\(new JSONObject\(\)\.put\("to",target\.deviceId\)/);
  const iosTargets = iosEngine.slice(iosEngine.indexOf('private func trustedTargets()'), iosEngine.indexOf('private func retryPending()'));
  assert.match(iosTargets, /for device in activeDevices/);
  assert.match(iosTargets, /result\.append\(peer\)/);
  assert.match(iosEngine, /for peer in targets \{[\s\S]*?recipientDeviceID: peer\.id/);
});

test('each open chat uses its own account UUID, device-key scope, local timeline, and sender route', () => {
  const openContact = web.slice(web.indexOf('async function openContact('), web.indexOf('async function sendMessage('));
  assert.match(openContact, /state\.selected=contact/);
  assert.match(openContact, /deriveCandidateConversationKeys\(contact\)/);
  assert.match(openContact, /if\(state\.selected\?\.id!==contact\.id\)return/);
  assert.match(openContact, /catch\(error\)\{if\(state\.selected\?\.id!==contact\.id\)return/);
  assert.match(web, /state\.conversationKeys\.get\(`\$\{contact\.id\}:\$\{device\.id\}`\)/);
  assert.match(web, /state\.messages\[contact\.id\]/);
  assert.match(web, /const contact=state\.contacts\.find\(item=>item\.devices\.some\(device=>device\.id===packet\.from\)\)/);
  assert.match(web, /content\.sender_user_id!==contact\.id[\s\S]*?content\.recipient_user_id!==state\.user\.id/);
  assert.match(androidEngine, /contactId=contact\.optString\("user_id"\)/);
  assert.match(androidEngine, /canonicalConversationId\(String first,String second\)/);
  assert.match(androidEngine, /!contactId\.equals\(content\.optString\("sender_user_id"\)\)/);
  assert.match(iosEngine, /contact\.user_id/);
  assert.match(iosEngine, /canonicalConversationID\(user\.id, contact\.user_id\)/);
  assert.match(iosEngine, /clear\["sender_user_id"\] as\? String == contact\.user_id/);
});

test('server accepts delivery only to a non-revoked device with at least one live session', () => {
  assert.match(backend, /SELECT d\.user_id FROM devices d WHERE d\.id=\$1 AND d\.revoked_at IS NULL AND EXISTS\(SELECT 1 FROM auth_sessions s WHERE s\.device_id=d\.id AND s\.user_id=d\.user_id AND s\.expires_at>now\(\)\)/);
  assert.match(backend, /input\.to==ctx\.device_id/);
  assert.match(backend, /recipient device not found/);
  assert.match(backend, /SELECT k\.device_id,k\.public_key,k\.layer2_public_key[\s\S]*?EXISTS\(SELECT 1 FROM auth_sessions/);
});

test('incoming packets are checked against the local device route and stored before ACK', () => {
  assert.match(web, /content\.recipient_device_id!==state\.device\.id/);
  assert.match(androidEngine, /recipient_device_id\"\)\)\)throw new SecurityException\("Encrypted message routing did not match this device/);
  assert.match(iosEngine, /clear\["recipient_device_id"\] as\? String == device\.id/);
  assert.match(web, /await storeLocalMessage\([\s\S]*?await acknowledgeMessage\(packet\.id\)/);
  assert.match(androidEngine, /decryptAndStoreIncoming\(peer,packet,id,senderDevice,created\)[\s\S]*?api\.acknowledgeFuture\(id\)/);
  assert.match(iosEngine, /try local\.save\(row, ratchetSnapshots: session\.snapshots\(\)\)[\s\S]*?try await api\.acknowledgeMessage\(id\)/);
});

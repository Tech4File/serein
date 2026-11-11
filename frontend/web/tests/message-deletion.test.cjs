const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (name) => fs.readFileSync(path.join(root, name), 'utf8');

test('backend persists bounded deletion tombstones and enforces sender-only everyone deletion', () => {
  const server = read('backend/src/main.rs');
  const migration = read('backend/migrations/0023_message_deletion_tombstones.sql');
  assert.match(server, /\/api\/v1\/messages\/deletions/);
  assert.match(server, /only the original sender can delete for everyone/);
  assert.match(server, /message_deletion_tombstones/);
  assert.match(server, /now\(\)\+interval '90 days'/);
  assert.match(server, /to_char\(expires_at AT TIME ZONE 'UTC'/);
  assert.match(server, /DELETE FROM encrypted_transfers WHERE id=ANY/);
  assert.match(migration, /scope IN \('me','everyone'\)/);
  assert.match(migration, /interval '90 days'/);
});

test('each client exposes selection, both allowed scopes, and transfer-ID-based app media cleanup', () => {
  const web = read('frontend/web/app.js');
  const webHtml = read('frontend/web/index.html');
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const androidStore = read('apps/android/app/src/main/java/io/serein/chat/SereinAttachmentStore.java');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  const iosStore = read('apps/ios/SereinChat/SereinAttachmentStore.swift');
  assert.match(web, /contextmenu/);
  assert.match(web, /event\.key==='ContextMenu'.*event\.key==='F10'/);
  assert.match(web, /selectMessageForDeletion\(row\.dataset\.messageId,true\)/);
  assert.match(webHtml, /messageSelectionCount.*aria-live="polite"/);
  assert.match(webHtml, /messageDeleteMe/);
  assert.match(webHtml, /messageDeleteEveryone/);
  assert.match(android, /setOnLongClickListener/);
  assert.match(android, /selectedMessageIds\.isEmpty\(\).*toggleSelectedMessage/);
  assert.match(android, /Delete for everyone/);
  assert.match(androidStore, /deleteTransfer\(Context context,String accountId,String transferId\)/);
  assert.match(ios, /onLongPressGesture/);
  assert.match(ios, /\.onTapGesture\{toggleMessageSelection\(message\.id\)\}/);
  assert.match(ios, /selectedMessagesAllMine/);
  assert.match(ios, /Delete for everyone/);
  assert.match(iosStore, /deleteTransfer\(accountID:String,transferID:String\)/);
});

test('web applies deletion metadata atomically with message-row removal across concurrent tabs', () => {
  const web = read('frontend/web/app.js');
  const apply = web.split('async function applyLocalMessageDeletionNow(records,accountId){')[1]?.split('\n')[0] || '';
  assert.match(apply, /transaction\(\['messages','meta'\],'readwrite'\)/);
  assert.match(apply, /request=meta\.get\(metaKey\)/);
  assert.match(apply, /request\.onsuccess/);
  assert.match(apply, /meta\.put\(\{key:metaKey,value:map\}\)/);
  assert.doesNotMatch(apply, /await localDeletionRecords\(\)/);
});

test('all clients apply deletion tombstones before accepting restored history and remove local message records', () => {
  const web = read('frontend/web/app.js');
  const androidStore = read('apps/android/app/src/main/java/io/serein/chat/SereinLocalStore.java');
  const iosStore = read('apps/ios/SereinChat/SereinLocalStore.swift');
  assert.match(web, /syncMessageDeletions/);
  assert.match(web, /isLocalMessageDeleted/);
  assert.match(androidStore, /deleteMessage\(String id,JSONArray transferIds\)/);
  assert.match(androidStore, /containsDeletedMessage/);
  assert.match(iosStore, /deleteMessage\(messageID:String,transferIDs:\[String\]=\[\],expiresAtMillis:Int64\?=nil\)/);
  assert.match(iosStore, /containsDeleted\(messageID:/);
  assert.match(androidStore, /expiresAtMillis/);
  assert.match(iosStore, /expiresAtMillis/);
  assert.match(read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java'), /row\.optString\("expires_at"/);
  assert.match(read('apps/ios/SereinChat/SereinChatEngine.swift'), /row\["expires_at"\]/);
});

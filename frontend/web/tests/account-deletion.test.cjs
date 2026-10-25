const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('account deletion is authenticated, password-confirmed, and returns a cleared session', () => {
  const backend = read('backend/src/main.rs');
  assert.match(backend, /\.route\("\/api\/v1\/me", get\(me\)\.delete\(delete_account\)\)/);
  assert.match(backend, /struct DeleteAccountInput \{ password: String \}/);
  assert.match(backend, /verify_password\(input\.password\.as_bytes\(\),&parsed\)/);
  assert.match(backend, /DELETE FROM accounts WHERE id=\$1/);
  assert.match(backend, /clear_session_cookie\(&mut response,state\.cookie_secure\)/);
  assert.match(backend, /SELECT to_regclass\('public\.offline_messages'\)/);
});

test('deleted contact rows become identity-bound archived tombstones, never active links', () => {
  const backend = read('backend/src/main.rs');
  const migration = read('backend/migrations/0011_account_deletion_tombstones.sql');
  assert.match(migration, /DROP CONSTRAINT IF EXISTS contacts_contact_id_fkey/);
  assert.match(migration, /contact_display_name TEXT/);
  assert.match(migration, /deleted_at TIMESTAMPTZ/);
  assert.match(backend, /contact_id UUID NOT NULL, contact_display_name TEXT NOT NULL/);
  assert.match(backend, /deleted_at=COALESCE\(deleted_at,now\(\)\)/);
  assert.match(backend, /contact_display_name\|\|' \(Deleted User\)'/);
  assert.match(backend, /contacts WHERE owner_id=\$1 AND contact_id=\$2 AND deleted_at IS NULL/);
  assert.match(backend, /contact_id UUID NOT NULL/);
});

test('deleted and recreated users stay in separate UUID conversations with lifecycle timestamps', () => {
  const backend = read('backend/src/main.rs');
  const web = read('frontend/web/app.js');
  assert.match(backend, /to_char\(c\.created_at AT TIME ZONE 'UTC'/);
  assert.match(backend, /to_char\(c\.deleted_at AT TIME ZONE 'UTC'/);
  assert.match(backend, /'incoming'::text/);
  assert.match(backend, /'sent'::text/);
  assert.match(backend, /INSERT INTO contacts\(owner_id,contact_id,contact_display_name\)/);
  assert.match(web, /You and \$\{baseName\} are now friends/);
  assert.match(web, /deleted his account\. No new messages are allowed/);
  assert.match(web, /!state\.selected\.deleted/);
  assert.match(web, /contact\?\.deleted\|\|contact\?\.historyOnly/);
});

test('web deletion removes only the current account local rows and offers explicit confirmation', () => {
  const web = read('frontend/web/app.js');
  const html = read('frontend/web/index.html');
  assert.match(web, /async function purgeDeletedAccountLocalData\(userId\)/);
  assert.match(web, /messageStore\.index\('accountKey'\)\.openCursor\(IDBKeyRange\.only\(userId\)\)/);
  assert.match(web, /serein:ecdh-p256:v1:\$\{userId\}:/);
  assert.match(web, /deleteAccountPhrase'\)\.value!=='DELETE'/);
  assert.match(html, /id="deleteAccountOpen"/);
  assert.match(html, /id="deleteAccountForm"/);
  assert.match(html, /pattern="DELETE"/);
  assert.match(html, /read-only archived copy/);
});

test('native account deletion and archived chats avoid active key lookup and sending', () => {
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  const iosEngine = read('apps/ios/SereinChat/SereinChatEngine.swift');
  const iosUI = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(android, /if\(contact\.optBoolean\("deleted"\)\)/);
  assert.match(android, /Archived conversation · this account was deleted · read-only/);
  assert.match(android, /latest\.optBoolean\("deleted"\)/);
  assert.match(iosEngine, /if contact\.isDeleted \{ loadMessages\(\); ready = true/);
  assert.match(iosEngine, /latest\["deleted"\] as\? Bool == true/);
  assert.match(iosEngine, /guard !contact\.isDeleted && !archived else/);
  assert.match(iosUI, /Permanently delete account/);
  assert.match(iosUI, /contact\.isDeleted \|\| engine\.archived \|\| draft/);
  const androidAttachments = read('apps/android/app/src/main/java/io/serein/chat/SereinAttachmentStore.java');
  const iosAttachments = read('apps/ios/SereinChat/SereinAttachmentStore.swift');
  assert.match(androidAttachments, /accountScope\(String accountId\)/);
  assert.match(androidAttachments, /deleteForAccount\(Context context,String accountId\)/);
  assert.match(iosAttachments, /func deleteForAccount\(_ accountID: String\)/);
  assert.match(iosAttachments, /serein-download-account-v1/);
});

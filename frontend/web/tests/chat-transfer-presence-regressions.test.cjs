const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const backend = read('backend/src/main.rs');
const html = read('frontend/web/index.html');
const app = read('frontend/web/app.js');
const confirm = read('frontend/web/components/confirm-dialog.js');
const css = read('frontend/web/experience.css');

test('transfer quota SUM(bigint) is clamped as numeric then decoded with the correct SQLx integer type', () => {
  const query = backend.slice(backend.indexOf('let usage=sqlx::query_as'), backend.indexOf('let(usage_sender', backend.indexOf('let usage=sqlx::query_as')));
  assert.equal((query.match(/LEAST\(COALESCE\(SUM\(total_ciphertext_bytes\),0\),\$3::numeric\)::bigint/g) || []).length, 2);
  assert.match(query, /\.bind\(ctx\.user_id\)\.bind\(input\.recipient_user_id\)\.bind\(MAX_ACTIVE_TRANSFER_BYTES_PER_ACCOUNT\)\.fetch_one/);
  assert.match(backend, /const MAX_ACTIVE_TRANSFER_BYTES_PER_ACCOUNT: i64 = 256 \* 1024 \* 1024/);
  assert.match(backend, /encrypted transfer quota usage query failed/);
  assert.match(backend, /transfer quota usage unavailable/);
  assert.match(backend, /active encrypted-transfer quota exceeded/);
});

test('GIFs, pasted files and chat-wide drops stage one attachment for preview before encrypted upload', () => {
  assert.match(html, /id="attachmentDraft"[^>]*hidden/);
  assert.match(html, /id="attachmentDraftPreview"/);
  assert.match(html, /id="attachmentDraftDiscard"/);
  assert.match(app, /async function stageComposerAttachment\(file\)/);
  assert.match(app, /URL\.createObjectURL\(file\)/);
  assert.match(app, /Only one attachment can be staged at a time/);
  assert.match(app, /\$\('conversation'\)\.addEventListener\('drop',handleComposerDrop\)/);
  assert.match(app, /if\(!attachment&&state\.pendingAttachment\)[\s\S]*?encryptAndUploadAttachment\(file\)/);
  assert.match(app, /window\.addEventListener\('serein:gif-selected',[\s\S]*?sendComposerFile\(event\.detail\.file\)/);
  assert.match(app, /if\(type\.startsWith\('image\/'\)\|\|isImageFile\(file\)\)/);
  assert.match(app, /type\.startsWith\('video\/'\)/);
  assert.match(app, /type\.startsWith\('audio\/'\)/);
  assert.match(app, /function attachmentUploadError\(error\)/);
  assert.match(app, /Check the backend log for “encrypted transfer quota usage query failed”/);
});

test('a reusable confirmation component handles both attachment discard and device sign-out', () => {
  assert.match(html, /components\/confirm-dialog\.js\?v=/);
  assert.match(confirm, /window\.SereinConfirmDialog\s*=\s*Object\.freeze\(\{\s*ask\s*\}\)/);
  assert.match(confirm, /byId\('confirmDialog'\)\?\.addEventListener\('close', finish\)/);
  assert.match(app, /const askConfirmation = confirmationDialog\.ask/);
  assert.match(app, /async function discardComposerAttachment\(\)[\s\S]*?await askConfirmation/);
  assert.match(app, /title:'Sign out of this device\?'/);
  assert.match(app, /confirmLabel:'Sign out',danger:true/);
});

test('presence metadata returns latest last-seen only when the contact permits presence visibility', () => {
  assert.match(backend, /last_seen_at: Option<String>/);
  assert.match(backend, /presence_visible: bool/);
  assert.match(backend, /CASE WHEN c\.deleted_at IS NULL AND COALESCE\(us\.settings->>'presence_visibility','contacts'\)<>'nobody' THEN \(SELECT to_char\(MAX\(d_seen\.last_seen_at\)/);
  assert.match(backend, /\(c\.deleted_at IS NULL AND COALESCE\(us\.settings->>'presence_visibility','contacts'\)<>'nobody'\)/);
  assert.match(backend, /contact\.last_seen_at\.as_ref\(\)\.is_none_or/);
  assert.match(app, /presenceVisible:c\.presence_visible!==false/);
  assert.match(app, /if\(hidden\)\{node\.hidden=true;node\.textContent='';/);
  assert.match(app, /hidePresence=!contact\.deleted&&\(contact\.presenceVisible===false\|\|contact\.historyOnly\)/);
  assert.match(app, /lastSeenAt:c\.last_seen_at\|\|''/);
  assert.match(html, /id="chatPresence" class="chat-presence"/);
  assert.match(app, /Last seen \$\{lastSeen\}/);
  assert.match(app, /node\.classList\.toggle\('is-online',online\)/);
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const androidMain = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
  const iosApi = read('apps/ios/SereinChat/SereinAPI.swift');
  const iosUi = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(android, /presenceSummary\(contact\)[\s\S]*?refreshContactPresence\(\)/);
  assert.match(android, /Last seen /);
  assert.match(android, /!row\.optBoolean\("presence_visible",true\)/);
  assert.match(androidMain, /presence_visible",true\)/);
  assert.match(iosApi, /let last_seen_at: String\?/);
  assert.match(iosApi, /let presence_visible: Bool\?/);
  assert.match(iosApi, /func refreshContactPresence\(\) async/);
  assert.match(iosUi, /private var presenceSummary: String/);
  assert.match(iosUi, /contact\.presence_visible == false \? "" :/);
  assert.match(iosUi, /Last seen /);
  assert.match(css, /\.chat-head-meta \.chat-presence\[hidden\][^}]*display: none/);
});

test('chat refinements use accessible server/back/logout icons, compact account footer and rounded focus states', () => {
  assert.match(html, /id="connectionOpen"[\s\S]*?class="server-icon"/);
  assert.match(html, /id="mobileBack"[\s\S]*?<svg viewBox="0 0 24 24"/);
  assert.match(html, /id="logout"[\s\S]*?<svg viewBox="0 0 24 24"/);
  assert.doesNotMatch(html, /brand-lockup compact[^<]*<\/div><\/div>[^<]*<span>ACCOUNT & DEVICES/);
  assert.match(css, /\.search-wrap:focus-within[^}]*border-radius: 15px;[^}]*box-shadow:/);
  assert.match(css, /input:focus-visible, textarea:focus-visible, select:focus-visible \{[^}]*border-radius: 12px/);
  assert.match(css, /\.sidebar-bottom \{ display: flex; min-height: 54px/);
});

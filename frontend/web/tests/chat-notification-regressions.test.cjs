const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const app = read('frontend/web/app.js');
const backend = read('backend/src/main.rs');
const html = read('frontend/web/index.html');
const css = read('frontend/web/experience.css');

test('device enrollment waits for the shared ratchet core and never publishes a temporary v2 downgrade', () => {
  const enroll = app.slice(app.indexOf('async function ensureDeviceKeyEnrollment()'), app.indexOf('async function deriveCandidateConversationKeys('));
  assert.match(enroll, /await window\.SereinCore\.ready/);
  assert.match(enroll, /if\(!coreReady\|\|!window\.SereinCore\.wasmActive\)throw/);
  assert.match(enroll, /ratchet_version:3/);
  assert.match(enroll, /Number\(reply\.ratchet_version\)!==3/);
  assert.match(backend, /old_ratchet>ratchet_version as i16/);
  assert.match(backend, /ratchet capability downgrade rejected/);
});

test('browser notices target incoming messages when the Serein tab is not active, without exposing message text', () => {
  const notify = app.slice(app.indexOf('function notifyIncomingMessage('), app.indexOf('function loadTheme('));
  assert.match(notify, /isConversationActivelyViewed\(contact\.id\)/);
  assert.match(notify, /new Notification\('New encrypted message'/);
  assert.match(notify, /body:'A new message is waiting in Serein\.'/);
  assert.match(notify, /silent:pageVisible\|\|!state\.settings\.notification_sound/);
  assert.match(notify, /notice\.onclick=\(\)=>\{window\.focus\(\)/);
  assert.match(html, /server-backed Web Push is not configured/);
});

test('tab title tracks total unread messages and CHATS badge has an independent local toggle', () => {
  assert.match(html, /id="chatsUnreadBadge"[^>]*aria-live="polite"/);
  assert.match(html, /id="unreadBadgeToggle"[^>]*aria-pressed="true"/);
  assert.match(app, /function syncUnreadIndicators\(\)[\s\S]*?state\.contacts\.reduce/);
  assert.match(app, /document\.title=count\?`\$\{count\} new message\$\{count===1\?'':'s'\} · Serein`:'Serein'/);
  assert.match(app, /localStorage\.setItem\(UNREAD_BADGE_KEY,String\(state\.unreadBadgeEnabled\)\)/);
  assert.match(app, /event\.key===UNREAD_BADGE_KEY/);
  assert.match(app, /syncUnreadIndicators\(\);const list=el\.contactList/);
});

test('notification tone is stronger, smoothly enveloped, previewable, and audio is warmed by a gesture', () => {
  assert.match(app, /envelope\.gain\.exponentialRampToValueAtTime\(\.18/);
  assert.match(app, /\[\[660,0,\.24\],\[880,\.095,\.27\]\]/);
  assert.match(html, /id="notificationSoundPreview"/);
  assert.match(app, /notificationSoundPreview'\)\.addEventListener\('click',playIncomingTone/);
  assert.match(app, /document\.addEventListener\('pointerdown',[\s\S]*?state\.notificationAudioContext\.resume\(\)/);
});

test('emoji selection keeps the picker open; outside click and Escape close it with a short exit animation', () => {
  const insert = app.slice(app.indexOf('function insertComposerEmoji('), app.indexOf('function renderEmojiChoices('));
  assert.match(insert, /input\.setRangeText\(emoji/);
  assert.doesNotMatch(insert, /setEmojiPickerOpen\(false\)/);
  assert.match(app, /picker\.classList\.add\('is-closing'\)/);
  assert.match(app, /pickerCloseTimer=setTimeout\(\(\)=>\{picker\.hidden=true/);
  assert.match(app, /if\(event\.key==='Escape'&&!\$\('emojiPicker'\)\.hidden\)/);
  assert.match(app, /picker\.contains\(event\.target\)/);
  assert.match(css, /\.emoji-picker\.is-closing[^}]*animation: picker-close-center 135ms/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\) \{ \.emoji-picker\.is-closing \{ animation: none/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('web composer uses consistent icon actions, a balanced text field, and a clear send control', () => {
  const html = read('frontend/web/index.html');
  const css = read('frontend/web/experience.css');
  assert.match(html, /class="composer-actions"[\s\S]*id="emojiToggle"[\s\S]*id="attachBtn"[\s\S]*id="messageInput"[\s\S]*id="sendButton"/);
  assert.match(html, /id="sendButton"[\s\S]*<svg[\s\S]*<path d="M5 12h14M13 6l6 6-6 6"/);
  assert.match(css, /\.composer\s*\{[^}]*display:\s*grid/);
  assert.match(css, /\.composer:focus-within/);
  assert.match(css, /\.send-btn\s*\{[^}]*width:\s*44px/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*\.composer\s*\{/);
  assert.match(css, /safe-area-inset-bottom/);
});

test('Android and iOS use aligned composer hit targets, attachment/emoji icons, and a distinct send action', () => {
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const androidUi = read('apps/android/app/src/main/java/io/serein/chat/SereinUi.java');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(androidUi, /composerIconButton\(Context c,int icon, String description, boolean primary\)/);
  assert.match(android, /ic_composer_emoji/);
  assert.match(android, /ic_composer_attach/);
  assert.match(android, /ic_composer_send/);
  assert.match(android, /EditorInfo\.IME_ACTION_SEND/);
  assert.match(ios, /Image\(systemName: "face\.smiling"\)/);
  assert.match(ios, /Image\(systemName: "paperclip"\)/);
  assert.match(ios, /Image\(systemName: "arrow\.up"\)/);
  assert.match(ios, /background\(Color\(uiColor: \.secondarySystemBackground\), in: RoundedRectangle\(cornerRadius: 19/);
  assert.doesNotMatch(ios, /Button\("Attach file"\)/);
});

test('security details show compact per-device statuses and hide fingerprints until opened', () => {
  const html = read('frontend/web/index.html');
  const app = read('frontend/web/app.js');
  const css = read('frontend/web/experience.css');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  assert.match(app, /document\.createElement\('details'\)/);
  assert.match(app, /peer-key-summary/);
  assert.match(css, /\.peer-key-summary/);
  assert.match(ios, /DisclosureGroup/);
  assert.match(android, /Show combined fingerprint/);
  assert.match(html, /first-use pinning is automatic/i);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('connection request dialog close and cancel bypass required-field validation', () => {
  const html = read('frontend/web/index.html');
  const js = read('frontend/web/app.js');
  const dialog = html.match(/<dialog id="contactDialog"[\s\S]*?<\/dialog>/)?.[0] || '';
  assert.ok(dialog);
  assert.match(dialog, /<form id="contactForm">/);
  assert.doesNotMatch(dialog, /<form[^>]*method="dialog"/);
  assert.match(dialog, /id="contactClose"[^>]*type="button"/);
  assert.match(dialog, /id="contactCancel"[^>]*type="button"/);
  assert.match(dialog, /<button class="btn btn-primary" type="submit">Send request<\/button>/);
  assert.match(js, /\$\('contactClose'\)\.addEventListener\('click',\(\)=>el\.contactDialog\.close\(\)\)/);
  assert.match(js, /\$\('contactCancel'\)\.addEventListener\('click',\(\)=>el\.contactDialog\.close\(\)\)/);
  assert.match(js, /async function addContact\(event\)\{event\.preventDefault\(\)/);
});

test('web notification control requests permission from an explicit user action and reports denied state', () => {
  const html = read('frontend/web/index.html');
  const js = read('frontend/web/app.js');
  assert.match(html, /id="notificationPermissionStatus"/);
  assert.match(html, /id="notificationToggle"[^>]*type="button"/);
  assert.match(js, /async function toggleBrowserNotifications\(\)/);
  assert.match(js, /Notification\.requestPermission\(\)/);
  assert.match(js, /permission==='denied'/);
  assert.match(js, /browser’s address bar or settings/);
  assert.match(js, /Notification\.permission==='granted'/);
  assert.match(html, /id="notificationSoundToggle"/);
  assert.match(js, /function playIncomingTone\(\)/);
  assert.match(js, /function notifyIncomingMessage\(contact\)/);
  assert.match(js, /if\(liveSocketPacket\)notifyIncomingMessage\(contact\)/);
});

test('Android requests runtime notification permission and exposes a real sound preference', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  const activity = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
  const engine = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  const notifications = read('apps/android/app/src/main/java/io/serein/chat/SereinNotifications.java');
  assert.match(manifest, /android\.permission\.POST_NOTIFICATIONS/);
  assert.match(activity, /requestPermissions\(new String\[\]\{Manifest\.permission\.POST_NOTIFICATIONS\}/);
  assert.match(activity, /notification_permission_asked/);
  assert.match(activity, /Play notification sound/);
  assert.match(engine, /SereinNotifications\.showIncoming/);
  assert.match(notifications, /CHANNEL_SOUND/);
  assert.match(notifications, /CHANNEL_SILENT/);
  assert.match(notifications, /permissionGranted\(Context context\)/);
});

test('iOS asks the system notification permission on enable and respects the sound choice', () => {
  const api = read('apps/ios/SereinChat/SereinAPI.swift');
  const view = read('apps/ios/SereinChat/SereinProductView.swift');
  const engine = read('apps/ios/SereinChat/SereinChatEngine.swift');
  assert.match(api, /requestAuthorization\(options: \[\.alert, \.sound, \.badge\]\)/);
  assert.match(api, /func setNotificationsEnabled\(_ enabled: Bool\)/);
  assert.match(api, /func notifyIncomingMessage\(\)/);
  assert.match(api, /serein\.notifications\.sound/);
  assert.match(view, /Section\("Notifications"\)/);
  assert.match(view, /tap Enable notifications to ask iOS/);
  assert.match(view, /Open iOS Settings/);
  assert.match(view, /Toggle\("Notification sound"/);
  assert.match(engine, /if notificationsArmed \{ api\.notifyIncomingMessage\(\) \}/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

const sharedSettings = [
  'theme', 'font_scale', 'reduce_motion', 'notifications',
  'presence_visibility', 'allow_contact_requests', 'discoverable_by_email',
];

test('backend and each client represent every shared account setting', () => {
  const backend = read('backend/src/main.rs');
  const web = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
  const androidChat = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const ios = read('apps/ios/SereinChat/SereinAPI.swift');
  const androidApi = read('apps/android/app/src/main/java/io/serein/chat/SereinApi.java');
  for (const field of sharedSettings) {
    assert.match(backend, new RegExp(`\\b${field}\\b`), `backend missing ${field}`);
    assert.match(web, new RegExp(`\\b${field}\\b`), `web missing ${field}`);
    assert.match(android, new RegExp(`\\b${field}\\b`), `Android missing ${field}`);
    assert.match(ios, new RegExp(`\\b${field}\\b`), `iOS missing ${field}`);
  }
  assert.ok(backend.includes('.route("/api/v1/settings", get(get_settings).put(put_settings))'));
  assert.ok(androidApi.includes('request("PUT", "/api/v1/settings", patch, cb)'));
  assert.ok(ios.includes('request("/api/v1/settings", method: "PUT"'));
  assert.ok(web.includes("api('/api/v1/settings',{method:'PUT',body:JSON.stringify(patch)})"));
  assert.match(android, /private void syncAccountPreferences\(\)/);
  assert.match(android, /putString\("theme",theme\).*putString\("font_scale",scale\).*putBoolean\("reduce_motion",reduced\)/s);
  assert.match(android, /syncAccountPreferences\(\)/);
  assert.match(android, /setWindowAnimations\(enabled\?0:defaultWindowAnimations\)/);
  assert.match(androidChat, /setWindowAnimations\(reduced\?0:defaultWindowAnimations\)/);
  assert.match(ios, /func savePreferences\(\) async/);
  assert.match(read('apps/ios/SereinChat/SereinProductView.swift'), /transaction\.disablesAnimations = true/);
  assert.match(read('frontend/web/app.js'), /classList\.toggle\('reduce-motion'/);
});

test('notification sound default is consistent and remains device-local', () => {
  const web = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(web, /notification_sound:true/);
  assert.match(web, /let sound=true/);
  assert.match(android, /getBoolean\("notification_sound",true\)/);
  assert.match(ios, /@AppStorage\("serein\.notifications\.sound"\) private var notificationSound = true/);
  assert.doesNotMatch(read('backend/src/main.rs'), /notification_sound/);
});

test('notification permission status refreshes after returning from system settings', () => {
  const web = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(web, /window\.addEventListener\('focus',syncNotificationControls\)/);
  assert.match(android, /onResume\(\).*renderMain\("Settings"\)/);
  assert.match(ios, /onChange\(of: scenePhase\).*refreshNotificationStatus/s);
});

test('mobile manifests request no camera or microphone permission', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  const iosSources = [
    read('apps/ios/SereinChat/SereinProductView.swift'),
    read('apps/ios/SereinChat/SereinAPI.swift'),
    read('apps/ios/SereinChat/SereinChatEngine.swift'),
  ].join('\n');
  assert.doesNotMatch(manifest, /CAMERA|RECORD_AUDIO|READ_MEDIA|READ_EXTERNAL_STORAGE/);
  assert.doesNotMatch(iosSources, /AVCaptureDevice|AVAudioSession|requestRecordPermission|NSCameraUsageDescription|NSMicrophoneUsageDescription/);
  assert.match(manifest, /android\.permission\.POST_NOTIFICATIONS/);
});

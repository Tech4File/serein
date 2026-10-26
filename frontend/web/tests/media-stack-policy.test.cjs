const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('approved media direction remains first-party Rust QUIC/MOQT plus PQC, with WebRTC prohibited', () => {
  const plan = read('docs/MEDIA_STACK_EVALUATION.md');
  assert.match(plan, /first-party, Rust-centric transport/);
  assert.match(plan, /no-new-third-party-runtime-dependency/);
  assert.match(plan, /WebRTC/);
  assert.match(plan, /ML-KEM/);
  assert.match(plan, /not implemented/);
});

test('no WebRTC or RTC-adjacent implementation/dependency is introduced into application code', () => {
  const files = [
    'Cargo.toml', 'Cargo.lock', 'crates/serein-moq-engine/Cargo.toml',
    'apps/android/app/build.gradle', 'apps/android/app/src/main/AndroidManifest.xml',
    'apps/ios/SereinChat.xcodeproj/project.pbxproj', 'frontend/web/index.html',
    'frontend/web/app.js', '.github/workflows/ci.yml',
  ];
  for (const file of files) {
    assert.doesNotMatch(read(file), /RTCPeerConnection|org\.webrtc|google-webrtc|libwebrtc|webrtc-rs|srtp/i, `${file} must not add a prohibited RTC stack`);
  }
  assert.match(read('apps/android/app/build.gradle'), /dependencies\s*\{\s*\}/);
  assert.match(read('crates/serein-moq-engine/Cargo.toml'), /\[dependencies\]\s*$/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('CI invokes repository shell scripts through bash regardless of executable-bit metadata', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /run: bash scripts\/test_core_ffi\.sh/);
  assert.match(ci, /ANDROID_NDK_HOME=.*bash scripts\/build_native_core\.sh android/);
  assert.match(ci, /run: bash scripts\/build_native_core\.sh ios/);
  assert.doesNotMatch(ci, /run: scripts\/(?:test_core_ffi|build_native_core)\.sh/);
  assert.match(ci, /bash -euo pipefail -c '[\s\S]*?connectedDebugAndroidTest[\s\S]*?android-instrumented-\$\{API_LEVEL\}\.log/);
  assert.doesNotMatch(ci, /^\s+set -o pipefail$/m);
  assert.match(ci, /android-instrumented-\*\.log/);
});

test('Android instrumentation can compile the app BuildConfig version assertion under AGP 8', () => {
  const gradle = read('apps/android/app/build.gradle');
  const androidTest = read('apps/android/app/src/androidTest/java/io/serein/chat/SereinCoreLinkTest.java');
  assert.match(gradle, /buildFeatures\s*\{\s*buildConfig\s+true\s*\}/);
  assert.match(androidTest, /BuildConfig\.VERSION_NAME/);
});

test('RustSec audit is explicitly manual-only', () => {
  const audit = read('.github/workflows/security-audit.yml');
  assert.match(audit, /\bon:\s*\n\s+workflow_dispatch:\s*\n/);
  assert.doesNotMatch(audit, /^\s+(?:push|pull_request|schedule):/m);
});

test('iOS simulator CI installs the selected Xcode-matched runtime when it is missing', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /Ensure the selected Xcode simulator runtime is installed/);
  assert.match(ci, /generic\/platform=iOS Simulator/);
  assert.match(ci, /grep -Fxq 'Xcode 16\.3'/);
  assert.match(ci, /IOS_SIM_RUNTIME_AVAILABLE/);
  assert.match(ci, /xcodebuild -downloadPlatform iOS -exportPath/);
  assert.match(ci, /xcodebuild -importPlatform/);
  assert.match(ci, /--show-sdk-version/);
  const adhoc = read('.github/workflows/ios-adhoc-test.yml');
  assert.match(adhoc, /Verify installed iOS SDK/);
  assert.doesNotMatch(adhoc, /xcodebuild\s+-downloadPlatform/);
});

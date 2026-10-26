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
  assert.match(ci, /set -o pipefail[\s\S]*?connectedDebugAndroidTest[\s\S]*?android-instrumented-\$\{API_LEVEL\}\.log/);
  assert.match(ci, /android-instrumented-\*\.log/);
});

test('RustSec audit is explicitly manual-only', () => {
  const audit = read('.github/workflows/security-audit.yml');
  assert.match(audit, /\bon:\s*\n\s+workflow_dispatch:\s*\n/);
  assert.doesNotMatch(audit, /^\s+(?:push|pull_request|schedule):/m);
});

test('iOS simulator build uses installed SDK and does not block compilation on Xcode platform downloads', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /Check preinstalled iOS simulator runtime/);
  assert.match(ci, /generic\/platform=iOS Simulator/);
  assert.match(ci, /IOS_SIM_RUNTIME_AVAILABLE/);
  assert.doesNotMatch(ci, /xcodebuild\s+-downloadPlatform/);
  const adhoc = read('.github/workflows/ios-adhoc-test.yml');
  assert.match(adhoc, /Verify installed iOS SDK/);
  assert.doesNotMatch(adhoc, /xcodebuild\s+-downloadPlatform/);
});

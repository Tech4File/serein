const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const gradle = fs.readFileSync(path.join(root, 'apps/android/app/build.gradle'), 'utf8');
const xcode = fs.readFileSync(path.join(root, 'apps/ios/SereinChat.xcodeproj/project.pbxproj'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
const androidTest = fs.readFileSync(path.join(root, 'apps/android/app/src/androidTest/java/io/serein/chat/SereinBackupCompatibilityTest.java'), 'utf8');

test('minimum supported OS floors are exercised by native CI rather than only documented', () => {
  assert.match(gradle, /minSdk\s+26/);
  assert.match(gradle, /testInstrumentationRunner\s+'android\.test\.InstrumentationTestRunner'/);
  assert.match(xcode, /IPHONEOS_DEPLOYMENT_TARGET = 15\.0/);
  assert.match(workflow, /api-level: \[26, 35\]/);
  assert.match(workflow, /connectedDebugAndroidTest/);
  assert.match(workflow, /Upload Android instrumentation results/);
  assert.match(workflow, /Launch the built app in an available iOS simulator/);
});

test('mobile core targets are cross-compiled in CI, with native linking still explicit as a separate gate', () => {
  assert.match(workflow, /aarch64-linux-android/);
  assert.match(workflow, /aarch64-apple-ios/);
  assert.match(workflow, /aarch64-apple-ios-sim/);
  assert.match(workflow, /cargo check --manifest-path crates\/serein-core\/Cargo.toml --target/);
});

test('Android minimum-API instrumentation tests exercise backup, identity binding, and idempotent restore', () => {
  assert.match(androidTest, /testV2RoundTripAndAccountBinding/);
  assert.match(androidTest, /testLocalRestoreMergeIsIdempotentAndKeepsExistingRows/);
  assert.match(androidTest, /testMalformedTimestampAndDuplicateBackupIdsAreRejected/);
});

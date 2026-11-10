const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const gradle = fs.readFileSync(path.join(root, 'apps/android/app/build.gradle'), 'utf8');
const xcode = fs.readFileSync(path.join(root, 'apps/ios/SereinChat.xcodeproj/project.pbxproj'), 'utf8');
const workflow = fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8');
const androidTest = fs.readFileSync(path.join(root, 'apps/android/app/src/androidTest/java/io/serein/chat/SereinBackupCompatibilityTest.java'), 'utf8');

test('Android minimum API is exercised in CI and iOS simulator app CI is intentionally absent', () => {
  assert.match(gradle, /minSdk\s+26/);
  assert.match(gradle, /testInstrumentationRunner\s+'android\.test\.InstrumentationTestRunner'/);
  assert.match(xcode, /IPHONEOS_DEPLOYMENT_TARGET = 15\.0/);
  assert.match(workflow, /api-level: \[26, 35\]/);
  assert.match(workflow, /connectedDebugAndroidTest/);
  assert.match(workflow, /Upload Android instrumentation results/);
  assert.doesNotMatch(workflow, /^  ios-simulator:/m);
  const adhoc = fs.readFileSync(path.join(root, '.github/workflows/ios-adhoc-test.yml'), 'utf8');
  assert.match(adhoc, /IPHONEOS_DEPLOYMENT_TARGET|generic\/platform=iOS/);
});

test('mobile Rust core is cross-checked and native link configuration remains while iOS app CI is omitted', () => {
  assert.match(workflow, /aarch64-linux-android/);
  assert.match(workflow, /aarch64-apple-ios/);
  assert.match(workflow, /aarch64-apple-ios-sim/);
  assert.match(workflow, /cargo check --manifest-path crates\/serein-core\/Cargo.toml --target/);
  assert.match(workflow, /scripts\/build_native_core\.sh android/);
  assert.doesNotMatch(workflow, /scripts\/build_native_core\.sh ios/);
  assert.doesNotMatch(workflow, /^  ios-simulator:/m);
  assert.match(gradle, /externalNativeBuild/);
  assert.match(xcode, /SereinCore\.xcframework in Frameworks/);
});

test('Android minimum-API instrumentation tests exercise backup, identity binding, and idempotent restore', () => {
  assert.match(androidTest, /testV3RoundTripAndAccountBinding/);
  assert.doesNotMatch(androidTest, /testV2RoundTripAndAccountBinding/);
  assert.match(androidTest, /testLocalRestoreMergeIsIdempotentAndKeepsExistingRows/);
  assert.match(androidTest, /testMalformedTimestampAndDuplicateBackupIdsAreRejected/);
});

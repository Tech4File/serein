const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../../apps/ios/SereinChat');
const codec = fs.readFileSync(path.join(root, 'SereinBackupStore.swift'), 'utf8');
const local = fs.readFileSync(path.join(root, 'SereinLocalStore.swift'), 'utf8');
const onboarding = fs.readFileSync(path.join(root, 'SereinBackupRestoreOnboarding.swift'), 'utf8');
const view = fs.readFileSync(path.join(root, 'SereinProductView.swift'), 'utf8');
const project = fs.readFileSync(path.join(root, '../SereinChat.xcodeproj/project.pbxproj'), 'utf8');

test('iOS portable codec uses stable account-ID v2 HKDF and restore-only legacy v1 PBKDF2', () => {
  assert.match(codec, /HKDF-SHA256-ACCOUNT-UUID/);
  assert.match(codec, /Serein backup account key v2/);
  assert.match(codec, /Serein backup stable key v1/);
  assert.match(codec, /PBKDF2|pbkdf2/);
  assert.match(codec, /legacyIterations = 600_000/);
  assert.match(codec, /compression_decode_buffer/);
  assert.match(codec, /compression_encode_buffer/);
  assert.match(codec, /"compression": "deflate"/);
  assert.match(codec, /maximumBytes = 64 \* 1024 \* 1024/);
  assert.match(codec, /static func create\(accountID:/);
  assert.match(codec, /static func open\(accountID:/);
});

test('iOS setup prompt uses file import, explicit permanent skip, and duplicate-safe chronological local merge', () => {
  assert.match(onboarding, /fileImporter/);
  assert.match(onboarding, /Skip permanently/);
  assert.match(onboarding, /offer restore later in Settings/i);
  assert.match(onboarding, /mergeBackupMessages/);
  assert.match(onboarding, /Media bytes are not included/);
  assert.match(local, /func mergeBackupMessages/);
  assert.match(local, /seen\.insert\(id\)\.inserted/);
  assert.match(local, /existing\.sort/);
  assert.doesNotMatch(local, /messages\.count > 1000/);
});

test('iOS Settings exposes encrypted export only and Xcode includes both backup source files', () => {
  assert.match(view, /Section\("Encrypted backups"\)/);
  assert.match(view, /fileExporter/);
  assert.match(view, /Restore is only offered during initial authenticated setup/);
  assert.match(project, /SereinBackupStore\.swift in Sources/);
  assert.match(project, /SereinBackupRestoreOnboarding\.swift in Sources/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const read = relative => fs.readFileSync(path.join(__dirname, '..', '..', '..', relative), 'utf8');

test('mobile clients complete login-purpose OTP without persisting the password', () => {
  const backend = read('backend/src/main.rs');
  const androidApi = read('apps/android/app/src/main/java/io/serein/chat/SereinApi.java');
  const androidUi = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
  const iosApi = read('apps/ios/SereinChat/SereinAPI.swift');
  const iosUi = read('apps/ios/SereinChat/SereinProductView.swift');
  const securityPage = read('frontend/web/security.html');

  assert.match(backend, /\/api\/v1\/auth\/verify-login/);
  assert.match(backend, /struct LoginInput \{ identity: String, password: String \}/);
  assert.match(backend, /deny_unknown_fields/);
  assert.match(backend, /"native_clients": "source_implemented_unverified"/);
  assert.match(securityPage, /Android and iOS chat source is not fully device\/live-tested/);
  assert.doesNotMatch(securityPage, /Android\/iOS message clients are not connected/);

  assert.match(androidApi, /void verifyLogin\(String identity, String password, String code, Callback cb\)/);
  assert.match(androidApi, /\/api\/v1\/auth\/verify-login/);
  assert.match(androidUi, /verification\.optString\("purpose"/);
  assert.match(androidUi, /api\.verifyLogin\(retainedIdentity,pendingPassword\[0\],code,callback\)/);
  assert.match(androidUi, /pendingPassword\[0\]=""/);

  assert.match(iosApi, /@Published var verificationPurpose = "email"/);
  assert.match(iosApi, /pendingLoginPassword/);
  assert.match(iosApi, /\/api\/v1\/auth\/verify-login/);
  assert.match(iosApi, /func cancelVerification\(\)/);
  assert.match(iosUi, /api\.verificationPurpose == "login"/);
  assert.match(iosUi, /api\.cancelVerification\(\)/);
});

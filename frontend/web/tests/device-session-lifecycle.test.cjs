const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const backend = read('backend/src/main.rs');
const web = read('frontend/web/app.js');
const androidApi = read('apps/android/app/src/main/java/io/serein/chat/SereinApi.java');
const androidMain = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
const iosApi = read('apps/ios/SereinChat/SereinAPI.swift');

test('sign-out atomically revokes the device and every session, then removes its public key registration', () => {
  const logout = backend.slice(backend.indexOf('async fn logout('), backend.indexOf('\nasync fn me('));
  assert.match(logout, /let mut tx=match state\.db\.begin\(\)/);
  assert.match(logout, /SELECT id FROM devices WHERE id=\$1 FOR UPDATE/);
  assert.match(logout, /DELETE FROM auth_sessions WHERE device_id=\$1/);
  assert.doesNotMatch(logout, /SELECT EXISTS\(SELECT 1 FROM auth_sessions/);
  assert.match(logout, /UPDATE devices SET revoked_at=COALESCE\(revoked_at,now\(\)\)/);
  assert.match(logout, /None=>return api_error\(StatusCode::UNAUTHORIZED,"sign in required"\)/);
  assert.match(logout, /DELETE FROM device_public_keys WHERE device_id=\$1/);
  assert.match(logout, /state\.peers\.remove\(&device_id\)/);
  assert.match(logout, /device_revoked.*true/);
  const createSession = backend.slice(backend.indexOf('async fn create_device_session('), backend.indexOf('async fn register('));
  assert.match(createSession, /WHERE id=\$1 FOR UPDATE/);
  assert.match(createSession, /Some\(_\)=>\{device_id=Uuid::new_v4\(\)/, 'a later sign-in must get a new identity after revocation');
});

test('device, contact-key, and message directories expose only devices with a live session', () => {
  const sessionExists = /EXISTS\(SELECT 1 FROM auth_sessions s WHERE s\.device_id=d\.id AND s\.user_id=d\.user_id AND s\.expires_at>now\(\)\)/;
  assert.match(backend.slice(backend.indexOf('async fn list_contacts('), backend.indexOf('async fn get_settings(')), sessionExists);
  assert.match(backend.slice(backend.indexOf('async fn list_contact_device_public_keys('), backend.indexOf('async fn require_user(')), sessionExists);
  assert.match(backend.slice(backend.indexOf('async fn list_devices('), backend.indexOf('async fn revoke_device(')), sessionExists);
  assert.match(backend.slice(backend.indexOf('async fn send_message_api('), backend.indexOf('async fn ws_handler(')), /EXISTS\(SELECT 1 FROM auth_sessions s WHERE s\.device_id=d\.id AND s\.user_id=d\.user_id AND s\.expires_at>now\(\)\)/);
  assert.match(backend.slice(backend.indexOf('async fn ws_handler(')), sessionExists);
  const revokeOne = backend.slice(backend.indexOf('async fn revoke_device('), backend.indexOf('async fn revoke_other_devices('));
  const revokeOthers = backend.slice(backend.indexOf('async fn revoke_other_devices('), backend.indexOf('async fn ws_handler('));
  assert.match(revokeOne, /DELETE FROM device_public_keys WHERE device_id=\$1 AND user_id=\$2/);
  assert.match(revokeOthers, /DELETE FROM device_public_keys WHERE user_id=\$1 AND device_id<>\$2/);
});

test('clients remain signed in locally if server-side device revocation cannot be confirmed', () => {
  const disconnect = web.slice(web.indexOf('async function disconnect('), web.indexOf('\n  function setSessionRestoreNotice('));
  assert.match(web, /disconnect\(\{requireServerRevocation:true\}\)/);
  assert.match(disconnect, /result\?\.ok===true&&result\?\.device_revoked===true/);
  assert.match(disconnect, /if\(requireServerRevocation&&!serverRevoked\)\{state\.signingOut=false;return false;\}/);
  assert.ok(disconnect.indexOf('if(requireServerRevocation&&!serverRevoked)') < disconnect.indexOf('clearInterval(state.resendTimer)'), 'failed revocation must return before clearing sign-in timers');
  assert.match(androidApi, /logout\(Callback cb\).*if\(error==null\)sessionVault\.clear\(\)/);
  assert.match(androidMain, /if\(e!=null\)\{signout\.setEnabled\(true\)/);
  const signOut = iosApi.slice(iosApi.indexOf('func signOut()'), iosApi.indexOf('\n    private func request('));
  assert.match(signOut, /catch \{ errorMessage = error\.localizedDescription; return false \}/);
  assert.ok(signOut.indexOf('return false') < signOut.indexOf('user = nil'));
});

test('device-management copy labels signed-in devices and explains sign-out revocation', () => {
  const html = read('frontend/web/index.html');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(html, /SIGNED-IN DEVICES/);
  assert.match(html, /Signing out revokes that device session and removes its public-key registration/);
  assert.match(ios, /Section\("Signed-in devices"\)/);
});

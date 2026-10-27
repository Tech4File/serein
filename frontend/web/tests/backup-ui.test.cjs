const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');

test('web settings expose manual encrypted backup and restore controls with correct script order', () => {
  const required = ['createBackupOpen', 'restoreBackupOpen', 'backupStatus', 'backupDialog', 'backupForm', 'backupFileInput', 'backupPassword', 'backupDialogSubmit'];
  for (const id of required) assert.match(html, new RegExp(`id=["']${id}["']`), `missing backup UI control ${id}`);
  assert.match(html, /data-panel="storage"[\s\S]*?createBackupOpen[\s\S]*?restoreBackupOpen/);
  const backupScript = html.indexOf('src="backup-crypto.js"');
  const appScript = html.indexOf('src="app.js"');
  assert.ok(backupScript >= 0 && appScript > backupScript, 'backup crypto adapter must load before the application');
  assert.match(html, /\.srbk/);
  assert.match(html, /Automatic scheduling[\s\S]*?not wired yet/);
  assert.match(html, /random, stable backup-only key[\s\S]*service stores that key encrypted at rest/);
  assert.match(html, /Legacy version 1 files still require the password/);
  const app = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  assert.match(app, /SereinBackupCrypto\.legacyVersion/);
  assert.match(app, /SereinBackupCrypto\.encrypt\(identity,snapshot,backupKey\)/);
  assert.match(app, /SereinBackupCrypto\.decrypt\(identity,fileBytes,legacyPassword,backupKey\)/);
  assert.match(app, /api\('\/api\/v1\/backups\/key-envelope'/);
  assert.match(app, /serein-backup-key-envelope-kdf-v1/);
  assert.match(app, /generateKey\(\{name:'ECDH',namedCurve:'P-256'\},false,\['deriveBits'\]\)/);
  assert.match(app, /backupKey\?\.fill\(0\)/);
});

test('verified sign-in requires OTP before returning the account UUID to the client', () => {
  const backend = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'backend', 'src', 'main.rs'), 'utf8');
  const app = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  assert.match(backend, /\/api\/v1\/auth\/verify-login/);
  assert.match(backend, /verification_login_response\(&email,message,delivery\)/);
  assert.match(backend, /struct VerifyLoginInput \{ identity: String, password: String, code: String/);
  assert.match(backend, /email_verification_challenges SET expires_at=now\(\),resend_after=now\(\),attempt_count=5/);
  assert.match(app, /loginVerification\?['"]\/api\/v1\/auth\/verify-login/);
  assert.match(app, /password:\$\('accountPassword'\)\.value/);
});

test('restore exposes in-app progress and media-type preview controls', () => {
  const app = fs.readFileSync(path.join(__dirname, '..', 'app.js'), 'utf8');
  for (const id of ['restoreProgressBanner', 'restoreProgressBar', 'attachmentPreviewDialog', 'attachmentPreviewImage', 'attachmentPreviewVideo', 'attachmentPreviewAudio']) {
    assert.match(html, new RegExp(`id=["']${id}["']`), `missing restore/media UI ${id}`);
  }
  assert.match(app, /const batchSize=250/);
  assert.match(app, /onProgress\(Math\.min\(offset\+batch\.length,messages\.length\),messages\.length,imported,addedItems\)/);
  assert.match(app, /insertRestoredMessages\(addedItems\)/);
  assert.match(app, /unique\.has\(item\.id\).*duplicate message IDs/);
  assert.match(app, /function attachmentKind\(/);
  assert.match(app, /function messageDayLabel\(/);
  assert.match(app, /appendMessageDaySeparator\(createdAt\)/);
  assert.match(app, /file removed or not available/);
  assert.match(app, /renderSelectedConversation\(\)/);
});

test('web backup UI does not expose a direct cloud provider or auto-schedule as active', () => {
  const storagePanel = html.match(/<section class="settings-section hidden" data-panel="storage">([\s\S]*?)<\/section>/)?.[1] || '';
  assert.ok(storagePanel.includes('not wired yet'));
  assert.ok(!/Google Drive|OneDrive|Run backup daily/.test(storagePanel));
});

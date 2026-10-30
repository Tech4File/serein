const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const web = fs.readFileSync(path.join(root, 'frontend/web/backup-crypto.js'), 'utf8');
const webApp = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');
const android = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinBackupStore.java'), 'utf8');
const androidApp = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/MainActivity.java'), 'utf8');
const androidApi = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinApi.java'), 'utf8');
const ios = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinBackupStore.swift'), 'utf8');
const iosApi = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinAPI.swift'), 'utf8');

test('all platforms use the same v3 backup-key salt, payload HKDF info, AAD domain, and key version', () => {
  for (const source of [web, android, ios]) {
    assert.match(source, /HKDF-SHA256-SERVER-BACKUP-KEY/);
    assert.match(source, /Serein backup payload v3/);
    assert.match(source, /serein-backup-payload-v3/);
    assert.match(source, /key_derivation_version/);
  }
  assert.match(web, /deriveServerBackupKey\(backupKeyBytes, identity\.accountId/);
  assert.match(android, /deriveServerBackupKey\(backupKey,id,salt\)/);
  assert.match(ios, /hkdfDerivedKey\(using: SHA256\.self, salt: salt, sharedInfo: Data\("Serein backup payload v3/);
  const backend = fs.readFileSync(path.join(root, 'backend/src/main.rs'), 'utf8');
  const cargo = fs.readFileSync(path.join(root, 'backend/Cargo.toml'), 'utf8');
  assert.doesNotMatch(backend, /SEREIN_BACKUP_KEY_ENCRYPTION_KEY/);
  assert.match(backend, /CREATE TABLE IF NOT EXISTS account_backup_keys/);
  assert.match(backend, /\/api\/v1\/backups\/key-envelope/);
  assert.match(backend, /"backup-key-envelope",10/);
  assert.match(backend, /INSERT INTO account_backup_keys[\s\S]*ON CONFLICT\(user_id\) DO NOTHING/);
  assert.match(backend, /key_material BYTEA/);
  assert.match(backend, /ensure_account_backup_key\(&state\.db,ctx\.user_id\)/);
  assert.match(backend, /ensure_account_backup_key\(&state\.db,user_id\)/);
  assert.match(backend, /serein-backup-key-envelope-kdf-v2/);
  assert.match(backend, /serein-backup-key-envelope-aad-v2/);
  assert.match(backend, /normalise_username\(&ctx\.username\)/);
  assert.match(backend, /envelope_version=input\.envelope_version\.unwrap_or\(1\)/);
  const migration = fs.readFileSync(path.join(root, 'backend/migrations/0016_per_account_backup_key_material.sql'), 'utf8');
  assert.match(migration, /key_material BYTEA/);
  assert.match(migration, /at_rest_version = 1 AND key_material IS NULL/);
  assert.match(migration, /at_rest_version = 2 AND key_material IS NOT NULL/);
  const envExample = fs.readFileSync(path.join(root, '.env.example'), 'utf8');
  assert.doesNotMatch(envExample, /SEREIN_BACKUP_KEY_ENCRYPTION_KEY/);
  assert.match(webApp, /envelope_version:2/);
  assert.match(androidApi, /put\("envelope_version",2\)/);
  assert.match(iosApi, /"envelope_version": 2/);
  assert.match(webApp, /updateBackupProgress\('Creating account backup key'/);
  assert.match(androidApp, /showBackupProgressDialog\(\)/);
  const androidNotifications = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinNotifications.java'), 'utf8');
  assert.match(androidNotifications, /showBackupProgress\(/);
  const iosProduct = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinProductView.swift'), 'utf8');
  assert.match(iosProduct, /beginBackgroundTask\(withName: "SereinEncryptedBackup"/);
  assert.match(iosProduct, /postBackupNotification\(/);
  assert.match(cargo, /p256 = .*features = \["ecdh"\]/);
  assert.match(cargo, /aes-gcm/);
  assert.match(webApp, /serein-backup-key-envelope-kdf-v2/);
  assert.match(android, /serein-backup-key-envelope-kdf-v2/);
  assert.match(iosApi, /serein-backup-key-envelope-kdf-v2/);
  assert.match(androidApi, /\/api\/v1\/backups\/key-envelope/);
  assert.match(iosApi, /\/api\/v1\/backups\/key-envelope/);
  assert.match(webApp, /\/api\/v1\/backups\/key-envelope/);
});

test('new v3 exports require DEFLATE before AES-GCM, while all clients preserve v1/v2 restore paths', () => {
  assert.match(web, /CompressionStream/);
  assert.match(web, /compression:\s*'deflate'/);
  assert.match(android, /DeflaterOutputStream/);
  assert.match(android, /String compression="deflate"/);
  assert.match(ios, /compression_encode_buffer/);
  assert.match(ios, /COMPRESSION_ZLIB/);
  assert.match(ios, /"compression": "deflate"/);
  for (const source of [web, android, ios]) {
    assert.match(source, /version.?2|PREVIOUS_VERSION|V2|expectedV2|v2KDF/);
    assert.match(source, /version.?1|LEGACY_VERSION|V1|expectedV1|v1KDF/);
    assert.match(source, /PBKDF2|PBEKeySpec|pbkdf2/);
  }
  assert.match(web, /header\.version === PREVIOUS_VERSION/);
  assert.match(android, /if\(h\.getInt\("version"\)==V2\)return openV2/);
  assert.match(ios, /parsed\.info\.version == 2/);
});

test('v2 AAD remains unchanged for old files and v3 AAD fields are ordered consistently', () => {
  assert.match(web, /'serein-backup-payload-v2', FORMAT, PREVIOUS_VERSION, identity\.accountId/);
  assert.match(android, /array\("serein-backup-payload-v2",FORMAT,V2,id,h\.getString\("snapshot_id"\)/);
  assert.match(ios, /\["serein-backup-payload-v2", format, 2, accountID/);
  assert.match(web, /'serein-backup-payload-v3', FORMAT, VERSION, identity\.accountId,[\s\S]*header\.salt, header\.payload_iv/);
  assert.match(android, /array\("serein-backup-payload-v3",FORMAT,V3,id[\s\S]*h\.getString\("salt"\),h\.getString\("payload_iv"\)\)/);
  assert.match(ios, /\["serein-backup-payload-v3", format, 3, accountID[\s\S]*derivation, salt, iv\]/);
});

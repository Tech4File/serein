const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../../apps/android/app/src/main/java/io/serein/chat');
const codec = fs.readFileSync(path.join(root, 'SereinBackupStore.java'), 'utf8');
const local = fs.readFileSync(path.join(root, 'SereinLocalStore.java'), 'utf8');
const activity = fs.readFileSync(path.join(root, 'MainActivity.java'), 'utf8');

test('Android creates v3 backups from the server key and keeps v1/v2 restore compatibility', () => {
  assert.match(codec, /HKDF-SHA256-SERVER-BACKUP-KEY/);
  assert.match(codec, /HKDF-SHA256-ACCOUNT-UUID/, 'account-ID keying is restore-only v2 compatibility');
  assert.match(codec, /private static JSONObject openV2/);
  assert.match(codec, /private static JSONObject openV1/);
  assert.match(codec, /PBKDF2WithHmacSHA256/);
  assert.match(codec, /V1_ITERATIONS\s*=\s*600_000/);
  assert.match(codec, /static byte\[\] create\(String accountId,String username,byte\[\] backupKey/);
  assert.match(codec, /static JSONObject open\(String accountId/);
  assert.match(codec, /String compression="deflate"/);
  assert.match(codec, /DeflaterOutputStream/);
  assert.doesNotMatch(codec, /compressed=clear\.clone\(\)/, 'new Android backups must not fall back to uncompressed data');
});

test('Android restore prompt is post-auth, one-time, explicit about final skip, and uses system document pickers', () => {
  assert.match(activity, /maybeOfferNativeRestore/);
  assert.match(activity, /ACTION_OPEN_DOCUMENT/);
  assert.match(activity, /ACTION_CREATE_DOCUMENT/);
  assert.match(activity, /restore_prompt_done/);
  assert.match(activity, /Skip restore/);
  assert.match(activity, /restore will not be available later in Settings/);
  assert.match(activity, /Merge messages/);
});

test('Android merge keeps existing IDs, orders records, and exposes bounded reference-only snapshots', () => {
  assert.match(local, /mergeBackupMessages/);
  assert.match(local, /if\(!byId\.containsKey\(id\)\)/);
  assert.match(local, /rows\.sort\(\(left,right\)->/);
  assert.doesNotMatch(local, /while\(next\.length\(\)>1000\)/);
  assert.match(local, /MAX_LOCAL_HISTORY_BYTES\s*=\s*64L\s*\*\s*1024\s*\*\s*1024/);
  assert.match(activity, /"policy","references-only"/);
  assert.match(activity, /100000/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.window = {};
require('../session-restore.js');
const { fetchAccount, hasSavedSession } = global.window.SereinSessionRestore;

const immediate = async () => {};

test('a session check is eligible only when a successful sign-in marker matches the selected API origin', () => {
  const values = new Map([['serein.saved-session-origin.v1', 'https://api.example.test']]);
  const storage = { getItem: key => values.get(key) ?? null };
  assert.equal(hasSavedSession(storage, 'serein.saved-session-origin.v1', 'https://api.example.test'), true);
  assert.equal(hasSavedSession(storage, 'serein.saved-session-origin.v1', 'https://other.example.test'), false);
  assert.equal(hasSavedSession({ getItem: () => null }, 'serein.saved-session-origin.v1', 'https://api.example.test'), false);
  assert.equal(hasSavedSession({ getItem: () => { throw new Error('storage blocked'); } }, 'serein.saved-session-origin.v1', 'https://api.example.test'), false);
});

test('session restore retries a transient service error and succeeds without prompting sign-in', async () => {
  let calls = 0;
  const retries = [];
  const account = await fetchAccount(async () => {
    calls += 1;
    if (calls < 3) throw new Error('temporary network failure');
    return { user: { id: 'user-1' }, device: { id: 'device-1' } };
  }, { wait: immediate, onRetry: attempt => retries.push(attempt) });

  assert.equal(account.user.id, 'user-1');
  assert.equal(calls, 3);
  assert.deepEqual(retries, [1, 2]);
});

test('only a confirmed unauthorized response ends session restoration without retries', async () => {
  let calls = 0;
  const error = Object.assign(new Error('sign in required'), { status: 401 });
  await assert.rejects(fetchAccount(async () => {
    calls += 1;
    throw error;
  }, { wait: immediate }), caught => caught === error);
  assert.equal(calls, 1);
});

test('transient failures remain distinguishable from signed-out state after bounded retries', async () => {
  let calls = 0;
  const failure = new Error('service unavailable');
  await assert.rejects(fetchAccount(async () => {
    calls += 1;
    throw failure;
  }, { wait: immediate }), caught => caught === failure);
  assert.equal(calls, 3);
});

test('web session restore exposes connection failure and retry rather than silently showing sign-in', () => {
  const root = path.resolve(__dirname, '..');
  const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');
  const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
  const androidMain = fs.readFileSync(path.resolve(root, '../../apps/android/app/src/main/java/io/serein/chat/MainActivity.java'), 'utf8');
  const androidApi = fs.readFileSync(path.resolve(root, '../../apps/android/app/src/main/java/io/serein/chat/SereinApi.java'), 'utf8');
  const iosApi = fs.readFileSync(path.resolve(root, '../../apps/ios/SereinChat/SereinAPI.swift'), 'utf8');
  assert.match(html, /id="restoreSessionRetry"/);
  assert.match(html, /Sign in to Serein/);
  assert.match(app, /if\(!hasSavedSessionHint\(\)\)[\s\S]*?return;/);
  assert.match(app, /rememberSavedSession\(\)/);
  assert.match(app, /if\(error\?\.status===401\)\{forgetSavedSession\(\)/);
  assert.match(app, /SereinSessionRestore\.fetchAccount\(\(\)=>api\('\/api\/v1\/me',\{cache:'no-store'\}\)/);
  assert.match(app, /Your session has not been cleared/);
  assert.match(androidApi, /boolean hasSavedSession\(\)[\s\S]*?sessionVault\.load/);
  assert.match(androidMain, /if\(!api\.hasSavedSession\(\)\)return;[\s\S]*?api\.me\(/);
  assert.match(iosApi, /func restoreSession\(\) async[\s\S]*?cookies\(for: root\)\?\.contains\(where: \{ \$0\.name == "serein_session" \}\) == true else \{ return \}/);
});

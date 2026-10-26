const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

global.window = {};
require('../session-restore.js');
const { fetchAccount } = global.window.SereinSessionRestore;

const immediate = async () => {};

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
  assert.match(html, /id="restoreSessionRetry"/);
  assert.match(app, /SereinSessionRestore\.fetchAccount\(\(\)=>api\('\/api\/v1\/me',\{cache:'no-store'\}\)/);
  assert.match(app, /Your session has not been cleared/);
  assert.match(app, /error\?\.status===401/);
});

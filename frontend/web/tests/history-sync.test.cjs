const test = require('node:test');
const assert = require('node:assert/strict');

global.window = {};
require('../history-sync.js');
const { processPage } = global.window.SereinHistorySync;

const items = [
  { id: 'message-1', created_at: '2026-01-01T00:00:00Z' },
  { id: 'message-2', created_at: '2026-01-01T00:00:01Z' },
  { id: 'message-3', created_at: '2026-01-01T00:00:02Z' },
];

test('a bad history item does not prevent later messages on the page from being processed or acknowledged', async () => {
  const processed = [];
  const persisted = [];
  const result = await processPage(items, null, async item => {
    processed.push(item.id);
    if (item.id === 'message-2') throw new Error('simulated decrypt failure');
    return true;
  }, async cursor => persisted.push(cursor), () => {});

  assert.deepEqual(processed, ['message-1', 'message-2', 'message-3']);
  assert.deepEqual(persisted.map(cursor => cursor.after_id), ['message-1']);
  assert.deepEqual(result.cursor, { after_created_at: items[0].created_at, after_id: 'message-1' });
  assert.equal(result.blocked, true);
  assert.equal(result.failed, 1);
});

test('a later retry advances the durable history cursor once the previously failing item succeeds', async () => {
  const processed = [];
  const persisted = [];
  const result = await processPage(items.slice(1), { after_created_at: items[0].created_at, after_id: 'message-1' }, async item => {
    processed.push(item.id);
    return true;
  }, async cursor => persisted.push(cursor));

  assert.deepEqual(processed, ['message-2', 'message-3']);
  assert.deepEqual(persisted.map(cursor => cursor.after_id), ['message-2', 'message-3']);
  assert.equal(result.cursor.after_id, 'message-3');
  assert.equal(result.blocked, false);
});

test('an explicit unprocessed result blocks cursor advancement but does not starve later items', async () => {
  const processed = [];
  const persisted = [];
  const result = await processPage(items, null, async item => {
    processed.push(item.id);
    return item.id !== 'message-1';
  }, async cursor => persisted.push(cursor));

  assert.deepEqual(processed, ['message-1', 'message-2', 'message-3']);
  assert.equal(persisted.length, 0);
  assert.equal(result.cursor, null);
  assert.equal(result.blocked, true);
});

test('cursor persistence failure blocks skipping but history processing continues', async () => {
  const processed = [];
  let failureCount = 0;
  const result = await processPage(items, null, async item => {
    processed.push(item.id);
    return true;
  }, async cursor => {
    if (cursor.after_id === 'message-1') throw new Error('simulated IndexedDB failure');
  }, () => failureCount++);

  assert.deepEqual(processed, ['message-1', 'message-2', 'message-3']);
  assert.equal(result.cursor, null);
  assert.equal(result.blocked, true);
  assert.equal(failureCount, 1);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const webRoot = path.resolve(__dirname, '..');
const app = fs.readFileSync(path.join(webRoot, 'app.js'), 'utf8');
const html = fs.readFileSync(path.join(webRoot, 'index.html'), 'utf8');

test('the history retry helper loads before the chat client', () => {
  assert.match(html, /message-limits\.js"><\/script><script src="history-sync\.js"><\/script><script src="session-restore\.js"><\/script>(?:<script src="gif-picker\.js"><\/script>)?<script src="app\.js">/);
});

test('incoming delivery ACK waits for the authenticated server ACK endpoint', () => {
  const start = app.indexOf('async function acknowledgeMessage(id)');
  const end = app.indexOf('\n  }', start);
  assert.notEqual(start, -1);
  const body = app.slice(start, end);
  assert.match(body, /await api\(`\/api\/v1\/messages\/\$\{encodeURIComponent\(id\)\}\/ack`/);
  assert.doesNotMatch(body, /socket\.send/);
});

test('history sync isolates per-message processing failures and keeps the retry cursor safe', () => {
  assert.match(app, /SereinHistorySync\.processPage\(items,cursor/);
  assert.match(app, /if\(result\.blocked\|\|!page\.has_more\)break/);
});

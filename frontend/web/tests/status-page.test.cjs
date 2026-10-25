const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const vm = require('node:vm');
const path = require('node:path');

const html = fs.readFileSync(path.join(__dirname, '../status.html'), 'utf8');
const script = fs.readFileSync(path.join(__dirname, '../status.js'), 'utf8');

function runStatus(fetchImpl) {
  const elements = new Map();
  for (const id of ['summary','overall','checkedAt','api','database','frontend','email','messaging','transfers','calls','background','refresh']) {
    elements.set(id, { textContent: '', className: '', dataset: {}, addEventListener() {} });
  }
  const context = { document: { getElementById: id => elements.get(id) }, fetch: fetchImpl, Date, Promise, console };
  vm.runInNewContext(script, context, { filename: 'status.js' });
  return elements;
}

test('status page contains all IDs consumed by its script and distinguishes health from feature status', () => {
  for (const id of ['summary','overall','checkedAt','api','database','frontend','email','messaging','transfers','calls','background','refresh']) {
    assert.match(html, new RegExp(`id=["']${id}["']`));
  }
  assert.match(html, /FEATURE IMPLEMENTATION STATUS · NOT LIVE QA/);
  assert.match(html, /Signaling and QUIC media transport are not implemented/);
  assert.match(html, /Remote push delivery is not configured/);
});

test('status page reports capability endpoint values conservatively', async () => {
  const paths = [];
  const elements = runStatus(async url => {
    paths.push(url);
    if (url === '/healthz') return { ok: true, json: async () => ({ status: 'ready', components: { api: 'ready', database: 'ready', frontend: 'available', email_delivery: 'disabled' } }) };
    return { ok: true, json: async () => ({ messaging_enabled: true, e2ee: { message_delivery: 'enabled' }, file_transfers: { server_chunk_store: 'source_implemented_unverified' }, calls: { quic_media_transport: 'not_implemented', session_signaling: 'not_implemented' } }) };
  });
  await new Promise(resolve => setImmediate(resolve));
  assert.deepEqual(paths.sort(), ['/api/v1/security/capabilities','/healthz']);
  assert.equal(elements.get('overall').textContent, 'Core service is operational');
  assert.equal(elements.get('messaging').textContent, 'Enabled · not live-validated');
  assert.equal(elements.get('transfers').textContent, 'Source present · unverified');
  assert.equal(elements.get('calls').textContent, 'Not implemented');
  assert.equal(elements.get('background').textContent, 'Not configured');
  assert.equal(elements.get('email').textContent, 'Not configured');
});

test('status page fails closed when the capability API or health check cannot be reached', async () => {
  const elements = runStatus(async () => { throw new Error('offline'); });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(elements.get('overall').textContent, 'Status check unavailable');
  assert.equal(elements.get('messaging').textContent, 'Unknown');
  assert.equal(elements.get('calls').textContent, 'Unknown');
  assert.equal(elements.get('background').textContent, 'Unknown');
});

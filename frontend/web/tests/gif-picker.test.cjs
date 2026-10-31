const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const pickerSource = fs.readFileSync(path.resolve(__dirname, '../gif-picker.js'), 'utf8');
const html = fs.readFileSync(path.resolve(__dirname, '../index.html'), 'utf8');

class FakeClassList {
  constructor() { this.values = new Set(); }
  add(name) { this.values.add(name); }
  remove(name) { this.values.delete(name); }
  toggle(name, force) {
    const next = force === undefined ? !this.values.has(name) : Boolean(force);
    next ? this.add(name) : this.remove(name);
    return next;
  }
  contains(name) { return this.values.has(name); }
}
class FakeElement {
  constructor(id = '') {
    this.id = id; this.listeners = new Map(); this.children = []; this.attributes = {};
    this.classList = new FakeClassList(); this.hidden = false; this.disabled = false;
    this.value = ''; this.textContent = ''; this.scrollTop = 0; this.clientHeight = 200; this.scrollHeight = 200;
  }
  addEventListener(type, callback) {
    if (!this.listeners.has(type)) this.listeners.set(type, []);
    this.listeners.get(type).push(callback);
  }
  async emit(type, event = {}) {
    event.currentTarget ||= this;
    for (const callback of this.listeners.get(type) || []) await callback(event);
    return event;
  }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; }
  setAttribute(key, value) { this.attributes[key] = String(value); }
}
function response(payload, { status = 200, headers = {} } = {}) {
  return {
    ok: status >= 200 && status < 300, status,
    headers: { get: key => headers[key.toLowerCase()] || null },
    async json() { return payload; },
    async blob() { return { size: 512, type: 'image/gif', payload: 'gif-bytes' }; },
  };
}
function makeHarness(fetchImpl) {
  const ids = new Map();
  for (const id of ['gifSearchButton', 'gifSearch', 'gifSearchClear', 'gifResults', 'gifLoadMore', 'gifStatus', 'gifCategories']) ids.set(id, new FakeElement(id));
  const calls = [];
  const dispatched = [];
  let now = 10_000, nextTimer = 1;
  const timers = new Map();
  const FakeDate = class extends Date { static now() { return now; } };
  const sandbox = {
    document: { getElementById: id => ids.get(id) || null, createElement: () => new FakeElement() },
    window: { dispatchEvent: event => dispatched.push(event) },
    URL, URLSearchParams, AbortController,
    Date: FakeDate,
    setTimeout(callback, delay = 0) { const id = nextTimer++; timers.set(id, { at: now + delay, callback }); return id; },
    clearTimeout(id) { timers.delete(id); },
    fetch: async (input, options = {}) => {
      calls.push({ url: new URL(String(input)), options });
      return fetchImpl(new URL(String(input)), options);
    },
    crypto: { randomUUID: () => 'test-gif-id' },
    File: class { constructor(parts, name, options) { this.parts = parts; this.name = name; Object.assign(this, options); } },
    CustomEvent: class { constructor(type, options) { this.type = type; this.detail = options.detail; } },
  };
  vm.runInNewContext(pickerSource, sandbox, { filename: 'gif-picker.js' });
  async function flush() { await Promise.resolve(); await Promise.resolve(); await new Promise(resolve => setImmediate(resolve)); }
  async function advance(ms) {
    now += ms;
    let turns = 0;
    while (turns++ < 20) {
      const due = [...timers.entries()].filter(([, timer]) => timer.at <= now).sort((a, b) => a[1].at - b[1].at);
      if (!due.length) break;
      for (const [id, timer] of due) { timers.delete(id); timer.callback(); }
      await flush();
    }
    await flush();
  }
  return { ids, calls, dispatched, timers, advance, flush, api: sandbox.window.SereinGifPicker };
}
const endpointPayload = { hug: { format: 'gif' }, pat: { format: 'gif' }, neko: { format: 'png' } };
const rows = (names, category = 'hug') => ({ results: names.map((name, index) => ({ anime_name: name, url: `https://nekos.best/api/v2/${category}/test-${index}.gif` })) });

async function openAndLoad(harness) {
  harness.api.open();
  await harness.flush();
  await harness.flush();
}

test('opening the GIF tab discovers categories, shows featured GIFs, and dispatches a selected GIF file', async () => {
  const h = makeHarness(async url => {
    if (url.pathname.endsWith('/endpoints')) return response(endpointPayload);
    if (url.pathname.endsWith('/hug')) return response({ results: [
      { anime_name: 'InuYasha', url: 'https://nekos.best/api/v2/hug/inuyasha.gif' },
      { anime_name: 'Chobits', url: 'https://nekos.best/api/v2/hug/chobits.gif' },
      { anime_name: 'untrusted', url: 'https://evil.example/hug.gif' },
    ] });
    return response({ results: [] });
  });
  await openAndLoad(h);
  assert.ok(h.calls.some(call => call.url.pathname.endsWith('/endpoints')));
  const featured = h.calls.find(call => call.url.pathname.endsWith('/hug'));
  assert.ok(featured, 'requests a default featured category without waiting for a search');
  assert.equal(featured.url.searchParams.get('amount'), '12');
  const tiles = h.ids.get('gifResults').children.filter(item => item.className === 'gif-result');
  assert.deepEqual(tiles.map(item => item.children[1].textContent), ['InuYasha', 'Chobits']);
  assert.deepEqual(h.ids.get('gifCategories').children.map(item => item.textContent), ['Hugs', 'Pats']);
  await tiles[0].emit('click'); await h.flush();
  assert.equal(h.dispatched[0].type, 'serein:gif-selected');
  assert.equal(h.dispatched[0].detail.file.name, 'nekos-test-gif-id.gif');
  assert.equal(h.dispatched[0].detail.file.type, 'image/gif');
});

test('typing searches dynamically after debounce; Enter and Search click use the same API route', async () => {
  const h = makeHarness(async url => url.pathname.endsWith('/endpoints') ? response(endpointPayload) : response(rows(['Happy Sugar Life', 'Anne Happy'], 'stare')));
  await openAndLoad(h);
  const input = h.ids.get('gifSearch'); input.value = 'happy';
  await input.emit('input');
  const before = h.calls.length;
  await h.advance(719);
  assert.equal(h.calls.length, before, 'waits for the debounce interval');
  await h.advance(1);
  const liveSearch = h.calls.find(call => call.url.pathname.endsWith('/search'));
  assert.ok(liveSearch, 'typing launches a search without form submission');
  assert.equal(liveSearch.url.searchParams.get('query'), 'happy');
  assert.equal(liveSearch.url.searchParams.get('type'), '2');
  assert.equal(liveSearch.url.searchParams.get('amount'), '12');
  assert.deepEqual(h.ids.get('gifResults').children.filter(item => item.className === 'gif-result').map(item => item.children[1].textContent), ['Happy Sugar Life', 'Anne Happy']);

  input.value = 'hug'; let prevented = false;
  await input.emit('keydown', { key: 'Enter', preventDefault() { prevented = true; } });
  await h.advance(750);
  assert.equal(prevented, true);
  assert.ok(h.calls.some(call => call.url.pathname.endsWith('/search') && call.url.searchParams.get('query') === 'hug'));
});

test('category discovery failure falls back to the known hug endpoint; no-results state stays in-app', async () => {
  const h = makeHarness(async url => {
    if (url.pathname.endsWith('/endpoints')) return response({}, { status: 503 });
    if (url.pathname.endsWith('/hug')) return response(rows(['Featured hug']));
    return response({ results: [] });
  });
  await openAndLoad(h);
  assert.ok(h.calls.some(call => call.url.pathname.endsWith('/hug')));
  assert.equal(h.ids.get('gifResults').children.filter(item => item.className === 'gif-result').length, 1);
  h.ids.get('gifSearch').value = 'unlikely-match';
  await h.ids.get('gifSearchButton').emit('click');
  await h.flush();
  assert.ok(h.ids.get('gifStatus').textContent.includes('No GIFs found'));
  assert.equal(h.calls.at(-1).url.pathname.endsWith('/search'), true);
});

test('picker is not a GET form, exposes close/search/category controls, and keeps local file selection separate', () => {
  assert.match(html, /id="emojiPicker"[^>]*role="dialog"/);
  assert.match(html, /id="emojiCategories"/);
  assert.match(html, /id="emojiSearch"/);
  assert.match(html, /id="gifSearchButton"[^>]*type="button"/);
  assert.match(html, /id="emojiPickerClose"/);
  assert.doesNotMatch(html, /id="gifSearchForm"|id="emojiGifBtn"|>Attach a file<\/button>/);
  assert.match(html, /id="attachBtn"[^>]*Send an encrypted file/);
  assert.doesNotMatch(html, /<form[^>]*gifSearch/);
});

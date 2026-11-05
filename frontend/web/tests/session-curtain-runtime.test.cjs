const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const source = fs.readFileSync(path.resolve(__dirname, '../components/session-curtain.js'), 'utf8');

function makeClassList(initial = []) {
  const values = new Set(initial);
  return {
    add: (...names) => names.forEach(name => values.add(name)),
    remove: (...names) => names.forEach(name => values.delete(name)),
    contains: name => values.has(name),
  };
}

function loadComponent(reducedMotion = true) {
  const rightLeaf = { addEventListener() {}, removeEventListener() {} };
  const curtain = {
    hidden: true,
    inert: true,
    classList: makeClassList(['hidden']),
    attributes: new Map([['aria-hidden', 'true']]),
    querySelector: selector => selector === '.curtain-right' ? rightLeaf : null,
    setAttribute(name, value) { this.attributes.set(name, value); },
  };
  const login = { inert: false };
  const app = { inert: false };
  const title = { textContent: '' };
  const message = { textContent: '' };
  const nodes = { sessionCurtain: curtain, login, app, curtainTitle: title, curtainMessage: message };
  const timers = new Map();
  let nextTimer = 0;
  const context = vm.createContext({
    document: {
      getElementById: id => nodes[id] || null,
      documentElement: { classList: { contains: () => false } },
    },
    window: {},
    matchMedia: () => ({ matches: reducedMotion }),
    getComputedStyle: () => ({ transitionDuration: '540ms' }),
    setTimeout: callback => { const id = ++nextTimer; timers.set(id, callback); return id; },
    clearTimeout: id => timers.delete(id),
  });
  vm.runInContext(source, context);
  return { api: context.window.SereinSessionCurtain, nodes, timers };
}

test('loading layer opens without reflow, suspends the underlying views, and restores them after close', () => {
  const { api, nodes } = loadComponent(true);
  api.show('Preparing Serein', 'Checking secure session');
  assert.equal(nodes.sessionCurtain.hidden, false);
  assert.equal(nodes.sessionCurtain.inert, false);
  assert.equal(nodes.sessionCurtain.classList.contains('hidden'), false);
  assert.equal(nodes.sessionCurtain.attributes.get('aria-hidden'), 'false');
  assert.equal(nodes.login.inert, true);
  assert.equal(nodes.app.inert, true);
  assert.equal(nodes.curtainTitle.textContent, 'Preparing Serein');
  assert.equal(nodes.curtainMessage.textContent, 'Checking secure session');

  api.hide();
  assert.equal(nodes.sessionCurtain.hidden, true);
  assert.equal(nodes.sessionCurtain.classList.contains('hidden'), true);
  assert.equal(nodes.sessionCurtain.attributes.get('aria-hidden'), 'true');
  assert.equal(nodes.login.inert, false);
  assert.equal(nodes.app.inert, false);
});

test('reopening during a close animation keeps the page suspended until the final close', () => {
  const { api, nodes, timers } = loadComponent(false);
  api.show();
  api.hide();
  assert.equal(nodes.login.inert, true);
  api.show('Still loading', 'Retrying the saved session');
  assert.equal(nodes.sessionCurtain.classList.contains('is-ready'), false);
  assert.equal(nodes.sessionCurtain.hidden, false);
  assert.equal(nodes.login.inert, true);
  api.hide();
  const [timerId, finish] = timers.entries().next().value;
  timers.delete(timerId);
  finish();
  assert.equal(nodes.sessionCurtain.hidden, true);
  assert.equal(nodes.login.inert, false);
});

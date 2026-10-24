'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const limits = require('../message-limits.js');

test('shared 4000-code-point limit and 90 percent warning threshold', () => {
  assert.equal(limits.maxCharacters(), 4000);
  assert.deepEqual(limits.counter('x'.repeat(3599)), {
    count: 3599, remaining: 401, warning: false, critical: false, visible: false, text: '3599 / 4000',
  });
  assert.deepEqual(limits.counter('x'.repeat(3600)), {
    count: 3600, remaining: 400, warning: true, critical: false, visible: true, text: '400 characters left',
  });
  assert.deepEqual(limits.counter('x'.repeat(3920)), {
    count: 3920, remaining: 80, warning: true, critical: true, visible: true, text: '80 characters left',
  });
});

test('counts Unicode scalar values consistently and truncates without splitting UTF-16 pairs', () => {
  const value = 'a😀e\u0301';
  assert.equal(limits.characterCount(value), 4);
  assert.equal(limits.characterCount('😀'.repeat(4001)), 4001);
  assert.equal(limits.truncate('😀'.repeat(4001)), '😀'.repeat(4000));
  assert.equal(limits.characterCount(limits.truncate('😀'.repeat(4001))), 4000);
});

test('uses shared-core count and limit when available', () => {
  const oldCore = globalThis.SereinCore;
  globalThis.SereinCore = { maxMessageCharacters: 3, messageCharacterCount: value => [...value].length };
  try {
    assert.equal(limits.maxCharacters(), 3);
    assert.equal(limits.counter('abc').remaining, 0);
    assert.equal(limits.truncate('abcd'), 'abc');
  } finally {
    if (oldCore === undefined) delete globalThis.SereinCore;
    else globalThis.SereinCore = oldCore;
  }
});

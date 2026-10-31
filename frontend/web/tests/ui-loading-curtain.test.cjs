const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'experience.css'), 'utf8');
const app = fs.readFileSync(path.join(root, 'app.js'), 'utf8');

test('session loading is a transparent overlay with two moving curtains that reveal the current page', () => {
  assert.match(html, /id="sessionCurtain"/);
  assert.match(html, /class="curtain-leaf curtain-left"/);
  assert.match(html, /class="curtain-leaf curtain-right"/);
  assert.match(css, /\.curtain-leaf\s*\{[\s\S]*transition:\s*transform\s+820ms/);
  assert.match(css, /\.session-curtain\.is-ready\s+\.curtain-left\s*\{\s*transform:\s*translateX\(-102%\)/);
  assert.match(css, /\.session-curtain\.is-ready\s+\.curtain-right\s*\{\s*transform:\s*translateX\(102%\)/);
  assert.match(css, /\.session-curtain\s*\{[\s\S]*background:\s*transparent/);
  assert.doesNotMatch(css, /\.curtain-leaf\s*\{\s*display:\s*none/);
  assert.match(app, /curtain\.querySelector\('\.curtain-right'\)/);
  assert.match(app, /transitionend/);
  assert.match(app, /curtainHideTimer=setTimeout\(finish,1000\)/);
});

test('emoji and GIF picker is centered and its tabs and filter chips use shared button geometry', () => {
  assert.match(css, /\.emoji-picker\s*\{[\s\S]*top:\s*50%;\s*left:\s*50%/);
  assert.match(css, /transform:\s*translate\(-50%, -50%\)/);
  assert.match(css, /\.picker-chip\s*\{[\s\S]*min-height:\s*var\(--component-chip-height, 36px\)/);
  assert.match(css, /\.picker-tabs button\[aria-selected="true"\]/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const css = fs.readFileSync(path.resolve(__dirname, '..', 'style.css'), 'utf8');

test('chat redesign keeps a split-pane desktop layout with clearer conversation surfaces', () => {
  assert.match(css, /@media\(min-width:681px\)/);
  assert.match(css, /\.sidebar\{width:clamp\(300px,27vw,360px\)/);
  assert.match(css, /--chat-own:#075e54/);
  assert.match(css, /\.attachment-card\{min-width:min\(100%,390px\)/);
});

test('mobile chat is edge-to-edge, safe-area aware, and uses a compact composer', () => {
  assert.match(css, /@media\(max-width:680px\)/);
  assert.match(css, /\.app\.chat-open \.main-panel\{position:fixed;inset:0/);
  assert.match(css, /padding-bottom:env\(safe-area-inset-bottom\)/);
  assert.match(css, /\.composer textarea\{min-height:40px;max-height:120px/);
});

test('chat UI retains user theme choice and readable text sizing', () => {
  assert.match(css, /:root\[data-theme="dark"\]\{--chat-bg/);
  assert.match(css, /font-size:max\(15px,calc\(15px \* var\(--font-scale,1\)\)\)/);
  assert.match(css, /@media\(prefers-reduced-motion:reduce\)/);
});

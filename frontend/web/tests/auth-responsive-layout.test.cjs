const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'auth-responsive.css'), 'utf8');

test('loading mark and card scale within the available screen width and height', () => {
  assert.match(html, /class="curtain-mark"/);
  assert.match(css, /\.curtain-mark\s*\{[^}]*width:\s*clamp\([^}]*min\(10vw,\s*9dvh\)/s);
  assert.match(css, /\.curtain-card\s*\{[^}]*width:\s*min\(100%,\s*clamp\(/s);
  assert.match(css, /\.curtain-card\s*\{[^}]*max-height:\s*calc\(100dvh/s);
  assert.match(css, /\.curtain-card b\s*\{[^}]*font-size:\s*clamp\(/s);
});

test('login layout stays within narrow devices and typography grows fluidly on wide screens', () => {
  assert.match(css, /\.auth-shell\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*\.92fr\)\s+minmax\(0,\s*1\.08fr\)/s);
  assert.match(css, /@media\s*\(max-width:\s*760px\)\s*\{[\s\S]*?\.auth-shell\s*\{\s*display:\s*block/s);
  assert.match(css, /\.auth-card\s*,\s*\.auth-top\s*,\s*\.auth-legal\s*\{\s*width:\s*min\(100%,\s*clamp\(/);
  assert.match(css, /@media\s*\(min-width:\s*1200px\)[\s\S]*?\.auth-card h2\s*\{[^}]*font-size:\s*clamp\(/s);
  assert.match(css, /\.auth-card input,\s*\.auth-card select\s*\{[^}]*min-height:\s*clamp\(/s);
  assert.match(css, /var\(--font-scale,\s*1\)/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(root, 'index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'auth-responsive.css'), 'utf8');
const experienceCss = fs.readFileSync(path.join(root, 'experience.css'), 'utf8');
const curtainCss = fs.readFileSync(path.join(root, 'components/session-curtain.css'), 'utf8');

test('standalone loading curtain stays viewport-bounded without changing auth layout', () => {
  assert.match(html, /class="curtain-mark"/);
  assert.match(curtainCss, /\.curtain-mark\s*\{[^}]*width:\s*clamp\([^}]*min\(12vw,\s*8dvh\)/s);
  assert.match(curtainCss, /\.curtain-card\s*\{[^}]*width:\s*min\(340px,\s*100%\)/s);
  assert.match(curtainCss, /\.curtain-card\s*\{[^}]*max-height:\s*calc\(100dvh/s);
  assert.match(curtainCss, /\.curtain-card b\s*\{[^}]*font-size:\s*clamp\(/s);
  assert.doesNotMatch(css + experienceCss, /\.session-curtain\s*\{|\.curtain-card\s*\{/);
});

test('server connection is presented as an accessible bordered chip', () => {
  assert.match(html, /id="authConnectionOpen" class="connection-chip"[^>]*aria-haspopup="dialog"[^>]*aria-controls="connectionDialog"/);
  assert.match(experienceCss, /\.connection-chip\s*\{[\s\S]*border:\s*1px solid var\(--border-strong\)/);
  assert.match(experienceCss, /\.connection-chip:focus-visible\s*\{[^}]*outline:/);
  assert.match(experienceCss, /@media\s*\(max-width:\s*420px\)[\s\S]*?\.connection-chip\s*\{/);
});

test('login layout stays within narrow devices and typography grows fluidly on wide screens', () => {
  assert.match(css, /\.auth-shell\s*\{[^}]*grid-template-columns:\s*minmax\(0,\s*\.92fr\)\s+minmax\(0,\s*1\.08fr\)/s);
  assert.match(css, /@media\s*\(max-width:\s*760px\)\s*\{[\s\S]*?\.auth-shell\s*\{\s*display:\s*block/s);
  assert.match(css, /\.auth-card\s*,\s*\.auth-top\s*,\s*\.auth-legal\s*\{\s*width:\s*min\(100%,\s*clamp\(/);
  assert.match(css, /@media\s*\(min-width:\s*1200px\)[\s\S]*?\.auth-card h2\s*\{[^}]*font-size:\s*clamp\(/s);
  assert.match(css, /\.auth-card input,\s*\.auth-card select\s*\{[^}]*min-height:\s*clamp\(/s);
  assert.match(css, /var\(--font-scale,\s*1\)/);
});

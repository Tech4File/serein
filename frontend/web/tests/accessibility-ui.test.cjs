const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('large text presets use shared scales and lift tiny-text floors', () => {
  const css = read('style.css');
  assert.match(css, /data-font-scale="large"\]\{--font-scale:var\(--type-scale-large,1\.15\)\}/);
  assert.match(css, /data-font-scale="extra_large"\]\{--font-scale:var\(--type-scale-extra-large,1\.3\)\}/);
  assert.ok(!/max\(0?\.(?:625|6875)rem,/.test(css), 'small text must not retain the old 10–11px floor');
  assert.match(css, /var\(--type-size-floor,0\.8125rem\)/);
  assert.match(css, /\.logout-btn[^}]*font-size:[^}]*var\(--font-scale/);
  assert.match(css, /\.settings-nav button[^}]*font-size:[^}]*var\(--font-scale/);
  assert.match(css, /\.auth-card input[^}]*font-size:[^}]*var\(--font-scale/);
});

test('font-size preference persists locally before login and is reused on security page', () => {
  const app = read('app.js');
  const security = read('security.js');
  assert.match(app, /const FONT_SCALE_KEY='serein\.font-scale\.v1'/);
  assert.match(app, /function loadFontScale\(\)/);
  assert.match(app, /localStorage\.getItem\(FONT_SCALE_KEY\)/);
  assert.match(app, /applyFontScale\(state\.settings\.font_scale\)/);
  assert.match(security, /localStorage\.getItem\('serein\.font-scale\.v1'\)/);
  assert.match(security, /dataset\.fontScale = \['system', 'large', 'extra_large'\]/);
  assert.match(read('security.html'), /--font-scale:var\(--type-scale-large,1\.15\)/);
  assert.match(read('security.html'), /--font-scale:var\(--type-scale-extra-large,1\.3\)/);
});

test('native dialog backdrop clicks dismiss but respect backup-operation lock', () => {
  const app = read('app.js');
  assert.match(app, /function enableBackdropDismissal\(\)/);
  assert.match(app, /event\.target!==dialog/);
  assert.match(app, /dialog\.id==='backupDialog'&&\$\('backupDialogSubmit'\)\.disabled/);
  assert.match(app, /dialog\.close\(\)/);
});

test('security fallback shows a labeled implementation snapshot rather than all unknown', () => {
  const security = read('security.js');
  const html = read('security.html');
  assert.match(security, /const sourceSnapshot = \{/);
  assert.match(security, /renderCapabilities\(sourceSnapshot\)/);
  assert.match(security, /bundled source snapshot shown/i);
  assert.match(security, /Bundled source snapshot/);
  assert.match(security, /android_native: false, ios_native: false/);
  assert.match(html, /bundled repository source snapshot/);
  assert.match(html, /--font-scale/);
});

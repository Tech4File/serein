const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const html = read('index.html');
const css = read('components/session-curtain.css');
const js = read('components/session-curtain.js');
const app = read('app.js');
const legacyCss = ['style.css', 'auth-responsive.css', 'experience.css'].map(read).join('\n');
const androidMain = read('../../apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
const iosProduct = read('../../apps/ios/SereinChat/SereinProductView.swift');
const iosApi = read('../../apps/ios/SereinChat/SereinAPI.swift');

test('session loading is a standalone, initially hidden full-screen layer, not auth-page content', () => {
  assert.match(html, /<div id="sessionCurtain" class="session-curtain hidden"[^>]*aria-hidden="true" hidden inert>/);
  assert.match(html, /<\/div>\s*<div id="login"/);
  assert.match(css, /\.session-curtain\s*\{[\s\S]*position:\s*fixed;[\s\S]*z-index:\s*2000;[\s\S]*inset:\s*0;/);
  assert.match(css, /\.session-curtain\[hidden\][\s\S]*display:\s*none\s*!important/);
  assert.match(css, /\.session-curtain\.is-ready \.curtain-left\s*\{\s*transform:\s*translateX\(-102%\)/);
  assert.match(css, /\.session-curtain\.is-ready \.curtain-right\s*\{\s*transform:\s*translateX\(102%\)/);
  assert.doesNotMatch(legacyCss, /\.session-curtain\s*\{|\.curtain-card\s*\{|\.curtain-mark\s*\{/);
});

test('curtain visibility, page inertness, cleanup and reduced motion live in the component module', () => {
  assert.match(html, /components\/session-curtain\.css/);
  assert.match(html, /components\/session-curtain\.js[\s\S]*app\.js/);
  assert.match(js, /window\.SereinSessionCurtain = Object\.freeze\(\{ show, hide \}\)/);
  assert.match(js, /layer\.hidden = false/);
  assert.match(js, /layer\.hidden = true/);
  assert.match(js, /element\.inert = true/);
  assert.match(js, /restoreUnderlyingPage\(\)/);
  assert.match(js, /transitionend/);
  assert.match(js, /durationMs \+ 220/);
  assert.match(js, /prefers-reduced-motion: reduce/);
  assert.match(app, /sessionCurtain\.show/);
  assert.match(app, /sessionCurtain\.hide/);
  assert.doesNotMatch(app, /function showSessionCurtain|function hideSessionCurtain/);
});

test('a curtain opens only for a saved session and reveals the resulting page', () => {
  assert.match(app, /if\(!hasSavedSessionHint\(\)\)\{[\s\S]*?return;/);
  assert.match(app, /state\.sessionRestoreInProgress=true;sessionCurtain\.show\(\)/);
  assert.match(css, /background:\s*transparent/);
  assert.match(css, /\.session-curtain\.is-ready \.curtain-card[\s\S]*opacity:\s*0/);
});

test('Android and iOS use the same session-only curtain palette and reveal behavior', () => {
  assert.match(androidMain, /if\(!api\.hasSavedSession\(\)\)return;[\s\S]*?showStartupCurtain\(\)/);
  assert.match(androidMain, /stage\.setBackgroundColor\(Color\.TRANSPARENT\)/);
  assert.match(androidMain, /SereinTokens\.LOADING_BACKGROUND/);
  assert.match(androidMain, /SereinTokens\.LOADING_CURTAIN_DURATION_MS/);
  assert.match(iosProduct, /SereinStartupCurtain\(isReady: api\.startupReady/);
  assert.match(iosProduct, /Image\("SereinMark"\)/);
  assert.match(iosProduct, /SereinTokens\.loadingPanel/);
  assert.match(iosApi, /startupReady = !hasSavedSession/);
  assert.match(iosApi, /cookies\(for: origin\)[\s\S]*serein_session/);
});

test('loading visual tokens and reduced-motion overrides have a single generated source', () => {
  const tokens = JSON.parse(read('../../design/tokens.json'));
  const webTokens = read('tokens.css');
  const androidTokens = read('../../apps/android/app/src/main/java/io/serein/chat/SereinTokens.java');
  const iosTokens = read('../../apps/ios/SereinChat/SereinTokens.swift');
  assert.equal(tokens.loading.background, '#0D1915');
  assert.match(webTokens, /--token-loading-background:#0d1915/);
  assert.match(androidTokens, /LOADING_BACKGROUND = 0xFF0D1915/);
  assert.match(iosTokens, /loadingBackground = Color\(/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
});

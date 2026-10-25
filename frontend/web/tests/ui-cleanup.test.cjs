const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');

test('typography scales and readable floors come from generated design tokens', () => {
  const tokens = JSON.parse(read('design/tokens.json')).typography;
  assert.equal(tokens.scale.system, 1);
  assert.equal(tokens.scale.large, 1.15);
  assert.equal(tokens.scale.extra_large, 1.3);
  assert.equal(tokens.minimum_web_rem, 0.8125);
  assert.equal(tokens.minimum_android_sp, 12);
  assert.match(read('frontend/web/tokens.css'), /--type-scale-large:1\.15/);
  assert.match(read('frontend/web/tokens.css'), /--type-scale-extra-large:1\.3/);
  assert.match(read('frontend/web/tokens.css'), /--type-size-floor:0\.8125rem/);
  assert.match(read('apps/android/app/src/main/java/io/serein/chat/SereinTokens.java'), /FONT_SCALE_LARGE = 1\.15f/);
  assert.match(read('apps/android/app/src/main/java/io/serein/chat/SereinTokens.java'), /FONT_SCALE_EXTRA_LARGE = 1\.3f/);
  assert.match(read('apps/android/app/src/main/java/io/serein/chat/SereinTokens.java'), /MIN_FONT_SIZE_SP = 12f/);
  assert.match(read('apps/ios/SereinChat/SereinTokens.swift'), /fontScaleLargeMinimum: DynamicTypeSize = \.xLarge/);
  assert.match(read('apps/ios/SereinChat/SereinTokens.swift'), /fontScaleExtraLargeMinimum: DynamicTypeSize = \.xxLarge/);
});

test('web and security-page typography use the shared scales and floor', () => {
  const css = read('frontend/web/style.css');
  const securityCss = read('frontend/web/security.html');
  const securityJs = read('frontend/web/security.js');
  assert.match(css, /--font-scale:var\(--type-scale-large,1\.15\)/);
  assert.match(css, /--font-scale:var\(--type-scale-extra-large,1\.3\)/);
  assert.match(css, /var\(--type-size-floor,0\.8125rem\)/);
  assert.match(securityCss, /font-size:calc\(100% \* var\(--font-scale,1\)\)/);
  assert.match(securityCss, /max\(var\(--type-size-floor,0\.8125rem\),\.875rem\)/);
  const securityIds = new Set([...securityCss.matchAll(/\bid="([^"]+)"/g)].map((match) => match[1]));
  for (const [, id] of securityJs.matchAll(/setStatus\('([^']+)'/g)) assert.ok(securityIds.has(id), `security status target #${id} must exist`);
  assert.match(securityJs, /dataset\.fontScale/);
  assert.match(read('frontend/web/status.js'), /dataset\.fontScale/);
  assert.match(read('frontend/web/status.html'), /--font-scale:var\(--type-scale-large,1\.15\)/);
  assert.match(read('frontend/web/status.html'), /--font-scale:var\(--type-scale-extra-large,1\.3\)/);
  assert.doesNotMatch(`${css}\n${securityJs}`, /--font-scale:1\.45|--font-scale:1\.8|\? 1\.45|\? 1\.8/);
});

test('nonfunctional call preflight and echo demo are retired from application code', () => {
  const web = `${read('frontend/web/index.html')}\n${read('frontend/web/app.js')}\n${read('frontend/web/style.css')}`;
  const android = `${read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java')}\n${read('apps/android/app/src/main/AndroidManifest.xml')}`;
  const ios = `${read('apps/ios/SereinChat/SereinProductView.swift')}\n${read('apps/ios/SereinChat.xcodeproj/project.pbxproj')}`;
  for (const source of [web, android, ios]) {
    assert.doesNotMatch(source, /callPermissions|callDialog|SereinNativeCalls|CALL_PERMISSION|RECORD_AUDIO|NSMicrophoneUsageDescription|NSCameraUsageDescription/);
  }
  assert.doesNotMatch(read('frontend/web/security.js'), /call-permissions|permission_preflight/);
  assert.match(read('frontend/web/security.html'), /Calling<\/b><small>Not implemented/);
  assert.equal(fs.existsSync(path.join(root, 'media-transport-spike')), false);
  for (const source of [read('Cargo.toml'), read('Cargo.lock'), read('.github/workflows/ci.yml'), read('scripts/check_versions.py'), read('scripts/sync_versions.py')]) {
    assert.doesNotMatch(source, /media-transport-spike|serein-wt-spike/);
  }
});

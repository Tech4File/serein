const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('iOS simulator app build is deliberately excluded from recurring CI after Xcode crashes', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.doesNotMatch(ci, /^  ios-simulator:/m);
  assert.match(ci, /target: aarch64-apple-ios\n/);
  assert.match(ci, /target: aarch64-apple-ios-sim\n/);
  assert.match(ci, /cargo check --manifest-path crates\/serein-core\/Cargo.toml --target/);
  const adhoc = read('.github/workflows/ios-adhoc-test.yml');
  assert.match(adhoc, /workflow_dispatch:/);
  assert.match(adhoc, /Verify installed iOS SDK/);
  assert.match(adhoc, /generic\/platform=iOS/);
  assert.doesNotMatch(adhoc, /xcodebuild -downloadPlatform iOS/);
});

test('browser DOM references resolve and local preferences fail gracefully when storage is blocked', () => {
  const html = read('frontend/web/index.html');
  const app = read('frontend/web/app.js');
  const ids = new Set([...html.matchAll(/\bid=["']([^"']+)/g)].map((match) => match[1]));
  const references = new Set([...app.matchAll(/\$\(['"]([^'"]+)['"]\)/g)].map((match) => match[1]));
  for (const id of references) assert.ok(ids.has(id), `Missing #${id} referenced from app.js`);
  assert.match(app, /function loadTheme\(\)\{let saved='system';try\{saved=localStorage\.getItem/);
  assert.match(app, /function saveContacts\(\)[\s\S]*?try\{localStorage\.setItem/);
  assert.match(app, /try\{localStorage\.setItem\('serein\.stable-device-id\.v1',account\.device\.id\);\}catch\{\}/);
});

test('source archive excludes common credential paths and tests do not widen archive contents', () => {
  const archive = read('scripts/create_source_archive.py');
  assert.match(archive, /EXCLUDED_NAMES\s*=\s*\{[^}]*\.netrc[^}]*\.git-credentials/s);
  assert.match(archive, /\.ssh/);
  assert.match(archive, /relative\.name in EXCLUDED_NAMES/);
  assert.match(archive, /if any\(part in EXCLUDED_COMPONENTS for part in relative\.parts\)/);
  assert.match(read('scripts/check_versions.py'), /text=True,\s*cwd=ROOT/);
});

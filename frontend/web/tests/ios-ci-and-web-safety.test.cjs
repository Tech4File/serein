const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('iOS CI explicitly installs and verifies simulator SDK/runtime before building', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /runs-on: macos-15/);
  assert.match(ci, /test "\$\(uname -m\)" = "arm64"/);
  assert.match(ci, /xcodebuild -downloadPlatform iOS/);
  assert.match(ci, /grep -Eiq 'iOS Simulator'/);
  assert.ok(ci.includes("grep -Eiq 'iOS.*\\(available\\)'"));
  assert.match(ci, /Preflight Xcode project resolution[\s\S]*?Build iOS simulator app/);
  assert.match(ci, /build_status=\$\{PIPESTATUS\[0\]\}/);
  for (const file of ['.github/workflows/release.yml', '.github/workflows/ios-adhoc-test.yml']) {
    assert.match(read(file), /xcodebuild -downloadPlatform iOS/);
  }
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

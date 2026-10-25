const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = (relative) => fs.readFileSync(path.join(root, relative), 'utf8');
const version = read('VERSION').trim();
const escapedVersion = version.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

test('VERSION is the sole editable product version; platform values are generated mirrors', () => {
  assert.match(read('Cargo.toml'), new RegExp(`^version = "${escapedVersion}"$`, 'm'));
  for (const manifest of ['backend/Cargo.toml', 'crates/serein-core/Cargo.toml', 'crates/serein-moq-engine/Cargo.toml']) {
    assert.match(read(manifest), /^version\.workspace = true$/m);
  }
  assert.match(read('frontend/web/config.js'), new RegExp(`version: "${escapedVersion}"`));
  const iosProject = read('apps/ios/SereinChat.xcodeproj/project.pbxproj');
  assert.equal((iosProject.match(/INFOPLIST_KEY_SereinVersion = /g) || []).length, 2);
  assert.equal((iosProject.match(new RegExp(`INFOPLIST_KEY_SereinVersion = "${escapedVersion}"`, 'g')) || []).length, 2);
  assert.match(read('scripts/sync_versions.py'), /VERSION_FILE\s*=\s*ROOT\s*\/\s*"VERSION"/);
  assert.match(read('scripts/check_versions.py'), /scripts\/sync_versions\.py/);
});

test('CI syncs version mirrors in each build workflow before checks/builds', () => {
  for (const workflow of ['.github/workflows/ci.yml', '.github/workflows/release.yml', '.github/workflows/ios-adhoc-test.yml']) {
    assert.match(read(workflow), /\.\/\.github\/actions\/sync-version/);
  }
  assert.match(read('.github/actions/sync-version/action.yml'), /scripts\/sync_versions\.py/);
});

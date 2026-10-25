const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('Android declares adaptive launcher icons and compiles platform instrumentation APIs', () => {
  const manifest = read('apps/android/app/src/main/AndroidManifest.xml');
  const appBuild = read('apps/android/app/build.gradle');
  const icon = read('apps/android/app/src/main/res/mipmap-anydpi-v26/ic_launcher.xml');
  const roundIcon = read('apps/android/app/src/main/res/mipmap-anydpi-v26/ic_launcher_round.xml');
  assert.match(manifest, /android:icon="@mipmap\/ic_launcher"/);
  assert.match(manifest, /android:roundIcon="@mipmap\/ic_launcher_round"/);
  assert.match(icon, /<adaptive-icon/);
  assert.match(icon, /<monochrome android:drawable="@drawable\/ic_launcher_monochrome"/);
  assert.match(roundIcon, /<adaptive-icon/);
  assert.match(appBuild, /useLibrary 'android\.test\.base'/);
});

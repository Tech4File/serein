const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('Android contact profile helper methods have explicit bodies so Java compilation reaches the UI logic', () => {
  const conversation = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  assert.match(conversation, /private LinearLayout viewAllMediaTile\([^)]*\)\s*\{/);
  assert.match(conversation, /private void showMediaLibrary\([^)]*\)\s*\{/);
});

test('Android Java sources import the referenced APIs and use the media tile return type', () => {
  const conversation = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const api = read('apps/android/app/src/main/java/io/serein/chat/SereinApi.java');
  assert.ok(conversation.includes('import android.widget.FrameLayout;'));
  assert.ok(conversation.includes('import java.nio.charset.StandardCharsets;'));
  assert.ok(conversation.includes('LinearLayout viewAll=viewAllMediaTile('));
  assert.ok(api.includes('import org.json.JSONArray;'));
});

test('Android media preview lambdas capture a final view and transfer cleanup avoids shadowed lambda names', () => {
  const conversation = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const engine = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  assert.match(conversation, /final View previewContent=content/);
  assert.match(conversation, /setOnDismissListener\(dialog->\{if\(previewContent instanceof android\.widget\.VideoView\)/);
  assert.match(engine, /thenComposeAsync\(ignored->CompletableFuture\.runAsync/);
  assert.match(engine, /catch\(Throwable abortError\)\{\}throw new java\.util\.concurrent\.CompletionException/);
});

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

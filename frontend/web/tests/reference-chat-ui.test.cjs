const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = relative => fs.readFileSync(path.join(root, relative), 'utf8');

test('web conversation follows the supplied dark-mobile and split-pane desktop visual direction', () => {
  const css = read('frontend/web/style.css');
  assert.match(css, /--chat-bg:#0b141a/);
  assert.match(css, /--chat-own:#075e54/);
  assert.match(css, /--chat-incoming:#202c33/);
  assert.match(css, /chat-wallpaper-dark\.svg/);
  assert.match(css, /chat-wallpaper-light\.svg/);
  assert.match(css, /@media\(min-width:681px\)[\s\S]*?\.sidebar\{[\s\S]*?\.main-panel/);
  assert.match(css, /@media\(max-width:680px\)[\s\S]*?\.app\.chat-open \.main-panel/);
  for (const file of ['frontend/web/chat-wallpaper-dark.svg', 'frontend/web/chat-wallpaper-light.svg']) {
    assert.match(read(file), /<svg[\s\S]*<path/);
  }
});

test('Android conversation has theme-aware split message bubbles and a local wallpaper', () => {
  const ui = read('apps/android/app/src/main/java/io/serein/chat/SereinUi.java');
  const conversation = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  assert.match(ui, /chatIncoming\(Context c\)/);
  assert.match(ui, /chatOutgoing\(Context c\)/);
  assert.match(conversation, /line\.setGravity\(mine\?Gravity\.END:Gravity\.START\)/);
  assert.match(conversation, /new SereinChatWallpaper\(this\)/);
  assert.match(read('apps/android/app/src/main/java/io/serein/chat/SereinChatWallpaper.java'), /class SereinChatWallpaper extends Drawable/);
});

test('iOS conversation aligns sent and received bubbles with a native, theme-aware wallpaper', () => {
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(ios, /private struct SereinConversationWallpaper: View/);
  assert.match(ios, /if message\.mine \{ Spacer\(minLength:/);
  assert.match(ios, /if !message\.mine \{ Spacer\(minLength:/);
  assert.match(ios, /\.background\(SereinConversationWallpaper\(\)\)/);
  assert.match(ios, /private var outgoingBubble: Color/);
});

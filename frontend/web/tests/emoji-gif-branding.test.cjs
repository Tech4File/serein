const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');

test('all clients expose an emoji composer and preserve Unicode emoji text', () => {
  const web = read('frontend/web/index.html');
  const webJs = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(web, /id="emojiToggle"/);
  assert.match(web, /id="emojiPicker"/);
  assert.match(webJs, /setRangeText\(emoji/);
  assert.match(android, /insertEmoji\(String emoji\)/);
  assert.match(ios, /Image\(systemName: "face\.smiling"\)/);
  assert.match(ios, /private func insertEmoji\(_ emoji: String\)/);
});

test('keyboard, paste, and drag-in images route through encrypted attachment transfers', () => {
  const web = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(web, /addEventListener\('paste',handleComposerPaste\)/);
  assert.match(web, /encryptAndUploadAttachment\(file\)/);
  assert.match(android, /attrs\.contentMimeTypes=new String\[\]\{"image\/gif","image\/\*"\}/);
  assert.match(android, /commitContent\(InputContentInfo content,int flags,Bundle opts\)/);
  assert.match(android, /engine\.uploadAttachment\(file,name,type\)/);
  assert.match(ios, /override func paste\(_ sender: Any\?\)/);
  assert.match(ios, /UTType\.gif\.identifier/);
  assert.match(ios, /engine\.sendFile\(url: url, filename: filename, contentType: mime\)/);
});

test('Serein app icons use shared web/iOS assets and a valid Android adaptive-icon background', () => {
  const html = read('frontend/web/index.html');
  const manifest = JSON.parse(read('frontend/web/manifest.webmanifest'));
  const project = read('apps/ios/SereinChat.xcodeproj/project.pbxproj');
  const icon = JSON.parse(read('apps/ios/SereinChat/Assets.xcassets/AppIcon.appiconset/Contents.json'));
  const colors = read('apps/android/app/src/main/res/values/colors.xml');
  const webIcon = read('frontend/web/icons/app-icon.svg');
  assert.match(html, /rel="icon"[^>]+app-icon\.svg/);
  assert.equal(manifest.icons.some((entry) => entry.sizes === '512x512'), true);
  assert.equal(icon.images[0].filename, 'SereinAppIcon.png');
  assert.match(project, /ASSETCATALOG_COMPILER_APPICON_NAME = AppIcon/);
  assert.match(project, /Assets\.xcassets in Resources/);
  const launcherBackground = colors.match(/<color name="ic_launcher_background">\s*(#[0-9a-f]{6})\s*<\/color>/i);
  assert.ok(launcherBackground, 'Android launcher must declare a valid six-digit background color');
  assert.match(manifest.theme_color, /^#[0-9a-f]{6}$/i);
  assert.match(webIcon, new RegExp(`fill="${manifest.theme_color}"`, 'i'));
});

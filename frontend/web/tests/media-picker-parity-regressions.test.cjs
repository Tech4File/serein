const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('frontend/web/app.js');
const html = read('frontend/web/index.html');
const css = read('frontend/web/experience.css');
const android = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
const ios = read('apps/ios/SereinChat/SereinProductView.swift');

test('Web GIF chat item omits redundant attachment metadata card, plays twice, and opens browser-managed viewer details', () => {
  assert.match(web, /const attachment=item\.attachment,kind=attachmentKind\(attachment\),gif=kind==='image'&&isGifAttachment\(attachment\)/);
  assert.match(web, /if\(!gif\)\{const card=document\.createElement\('div'\);card\.className='attachment-card'/);
  assert.match(web, /if\(gif\)\{preview\.addEventListener\('click',\(\)=>openAttachmentItem\(item\)\)/);
  assert.match(web, /attachTwoPassPlayback\(\{image:media,canvas,sourceUrl:cached\.url,durationMs,onComplete:\(\)=>state\.completedGifAutoplay\.add\(item\.id\)\}\)/);
  assert.match(web, /Stored in browser-managed data; filesystem path unavailable/);
  assert.match(html, /id="attachmentPreviewDetails"/);
});

test('Android displays local animated GIFs inline with two passes and exposes path, filename and byte size in viewer', () => {
  assert.match(android, /if\(gif\)\{String filename/);
  assert.match(android, /new GifMovieView\(this,saved,2,inlineGifAutoplayed\.contains\(transferId\)/);
  assert.match(android, /private final int autoplayLoops/);
  assert.match(android, /elapsed>=duration\*\(long\)autoplayLoops/);
  assert.match(android, /mime\+" · "\+formatBytes\(file\.length\(\)\)\+"\\n"\+file\.getAbsolutePath\(\)/);
  assert.match(android, /loadVisibleInlineGifs\(\)/);
});

test('iOS lazily loads animated GIFs for visible chat rows, stops after two loops, and reports the native file path', () => {
  assert.match(ios, /SereinInlineGIFView\(url: url\)/);
  assert.match(ios, /\.task\(id: attachment\.transferID\) \{ await loadInlineGIF\(attachment\) \}/);
  assert.match(ios, /view\.animationRepeatCount = 1/);
  assert.match(ios, /Text\(item\.url\.path\)/);
  assert.match(ios, /SereinInlineGIFView\(url:item\.url\)/);
});

test('picker is bounded and proportionally scaled while category chips scroll horizontally without overscroll capture', () => {
  assert.match(css, /width: min\(560px, calc\(100% - 24px\)\)/);
  assert.match(css, /min-width: min\(480px, calc\(100% - 24px\)\)/);
  assert.match(css, /flex-wrap: nowrap;[^}]*overflow-x: auto;[^}]*overflow-y: hidden/);
  assert.match(css, /overscroll-behavior-x: auto/);
  assert.match(css, /font-size: clamp\(22px, 5\.6cqi, 27px\)/);
  assert.match(android, /int panelWidth=Math\.min\(getResources\(\)\.getDisplayMetrics\(\)\.widthPixels-dp\(24\),dp\(560\)\)/);
  assert.match(android, /option\.setTextSize\(SereinUi\.fontSize\(this,23\)\)/);
  assert.match(ios, /frame\(maxWidth: 560\)/);
  assert.match(ios, /ScrollView\(\.horizontal, showsIndicators: false\)/);
});

test('all clients add a centered accessible jump-to-latest control and use an arrow for shared-media View all', () => {
  assert.match(html, /id="jumpToLatest"[^>]*aria-label="Jump to latest messages"/);
  assert.match(web, /function updateJumpToLatest\(\)/);
  assert.match(css, /\.jump-to-latest \{ position: absolute; z-index: 12; top: 50%; left: 50%/);
  assert.match(android, /Button jumpLatest=SereinUi\.button\(this,"↓"/);
  assert.match(android, /Gravity\.CENTER\);chatArea\.addView\(jumpLatest/);
  assert.match(ios, /if showJumpToLatest/);
  assert.match(ios, /accessibilityLabel\("Jump to latest messages"\)/);
  assert.match(web, /profile-view-all-arrow/);
  assert.match(android, /TextView arrow=SereinUi\.text\(this,"→",42/);
  assert.match(ios, /Image\(systemName: "arrow\.right"\)/);
});

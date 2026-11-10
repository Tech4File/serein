const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const app = read('frontend/web/app.js');
const html = read('frontend/web/index.html');
const css = read('frontend/web/experience.css');
const playback = require('../media-playback.js');

test('GIF duration parser uses frame delays and safely falls back for malformed input', () => {
  const oneFrameGif = Buffer.from([
    0x47,0x49,0x46,0x38,0x39,0x61, 1,0, 1,0, 0,0,0,
    0x21,0xf9,0x04,0x00,0x32,0x00,0x00,0x00,
    0x2c,0,0,0,0,1,0,1,0,0, 0x02,0x02,0x44,0x01,0x00, 0x3b,
  ]);
  assert.equal(playback.gifDurationMs(oneFrameGif), 500);
  assert.equal(playback.gifDurationMs(Buffer.from('not a gif')), 1000);
});

test('chat GIFs preload only in view, play two passes, replay on first tap and open on the next tap', () => {
  assert.match(app, /function queueChatAttachmentPreview/);
  assert.match(app, /IntersectionObserver\(entries=>/);
  assert.match(app, /durationMs,onOpen:\(\)=>openAttachmentItem\(item\)/);
  assert.match(app, /item\.attachment\?\.size>8\*1024\*1024/);
  assert.match(playback.attachTwoPassPlayback.toString(), /durationMs \* 2/);
  assert.match(playback.attachTwoPassPlayback.toString(), /pendingSecondTap/);
  assert.match(playback.attachTwoPassPlayback.toString(), /onOpen\?\.\(\)/);
  assert.match(html, /media-playback\.js\?v=/);
});

test('attachment captions render with the file/media in one chat bubble and older filename labels are not shown as captions', () => {
  assert.match(app, /function attachmentCaption\(item\)/);
  assert.match(app, /caption===`📎 \$\{item\.attachment\.filename\}`\?'':caption/);
  assert.match(app, /captionNode\.className='attachment-caption'/);
  assert.match(app, /bubble\.append\(card\);const caption=attachmentCaption\(item\)/);
  assert.match(css, /\.attachment-caption\s*\{[^}]*white-space:\s*pre-wrap/);
});

test('attachment modal removes hidden utility classes before displaying decrypted image, video, audio, or document', () => {
  const clear = app.slice(app.indexOf('function clearAttachmentPreview()'), app.indexOf('async function openEncryptedAttachment('));
  assert.match(clear, /node\.classList\.add\('hidden'\)/);
  assert.match(clear, /node\.classList\.remove\('hidden'\)/);
  assert.match(clear, /video\.autoplay=false/);
  assert.match(clear, /video\.controls=true/);
  assert.match(html, /id="attachmentPreviewVideo"[^>]*controls playsinline hidden/);
});

test('emoji picker keeps the composer focused by default, exposes an accessible delete key, and is viewport bounded', () => {
  assert.match(app, /function setEmojiPickerOpen\(open\)[\s\S]*?el\.messageInput\.focus\(\{preventScroll:true\}\)/);
  assert.match(app, /function deletePreviousComposerCharacter\(\)/);
  assert.match(app, /emojiBackspace'\)\.addEventListener\('click',deletePreviousComposerCharacter/);
  assert.match(app, /e\.key==='Tab'&&!e\.shiftKey&&!\$\('emojiPicker'\)\.hidden/);
  assert.match(html, /id="emojiBackspace"[^>]*aria-controls="messageInput"/);
  assert.match(css, /max-height:\s*min\(54dvh,\s*430px,\s*calc\(100dvh - 118px/);
});

test('presence is refreshed while visible and immediately when the web client regains focus', () => {
  assert.match(app, /setInterval\(\(\)=>\{if\(state\.user&&document\.visibilityState==='visible'\)refreshContacts\(\)\.catch\(\(\)=>\{\}\);\},8000\)/);
  assert.match(app, /window\.addEventListener\('focus',[\s\S]*?refreshContacts\(\)\.catch\(\(\)=>\{\}\)/);
  assert.match(app, /renderSelectedContactProfilePresence\(next\)/);
  assert.match(app, /contact-presence-dot/);
});

test('message tone awaits resumed audio after a suspended tab and can be previewed', () => {
  const tone = app.slice(app.indexOf('async function playIncomingTone()'), app.indexOf('function notifyIncomingMessage('));
  assert.match(tone, /context\.state==='closed'/);
  assert.match(tone, /await context\.resume\(\)/);
  assert.match(tone, /context\.state!=='running'/);
  assert.match(app, /notificationSoundPreview'\)\.addEventListener\('click',playIncomingTone/);
});

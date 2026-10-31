const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const html = read('frontend/web/index.html');
const css = read('frontend/web/experience.css');
const app = read('frontend/web/app.js');
const androidUi = read('apps/android/app/src/main/java/io/serein/chat/SereinUi.java');
const androidConversation = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
const iosDesign = read('apps/ios/SereinChat/SereinDesign.swift');
const iosProduct = read('apps/ios/SereinChat/SereinProductView.swift');

test('loading curtain scales its mark to the viewport and honors reduced motion', () => {
  assert.match(html, /curtain-mark-stage/);
  assert.match(html, /curtain-loading-indicator/);
  assert.match(css, /width:\s*clamp\(156px, min\(38vw, 34dvh\), 276px\)/);
  assert.match(css, /prefers-reduced-motion:\s*reduce/);
  assert.match(css, /\.session-curtain\.is-ready/);
});

test('short auth view can scroll while respecting safe areas and mobile sizing', () => {
  assert.match(css, /html\.auth-visible, body\.auth-visible[\s\S]*overflow-y:\s*auto/);
  assert.match(css, /@media\s*\(max-height:\s*760px\)/);
  assert.match(css, /env\(safe-area-inset-top\)/);
  assert.match(app, /auth-visible/);
});

test('contact profile is a responsive pane/page and media filters preserve the return path', () => {
  assert.match(html, /id="contactProfilePanel"[^>]*aria-hidden="true"[^>]*inert/);
  assert.match(css, /\.app\.profile-open\s*\{\s*grid-template-columns/);
  assert.match(css, /@media\s*\(max-width:\s*680px\)\s*\{[\s\S]*\.contact-profile-panel\s*\{\s*position:\s*fixed/);
  assert.match(html, /id="mediaLibraryDialog"[\s\S]*data-library-filter="image"[\s\S]*data-library-filter="video"/);
  assert.match(app, /function openMediaLibrary\(fromProfile=true\)/);
  assert.match(app, /mediaLibraryReturnToProfile/);
  assert.match(app, /mediaLibraryDialog'\)\.addEventListener\('close'/);
  assert.match(app, /loadProfileThumbnail\(item,image\)/);
});

test('app automatically pins first-seen dual-key bundles while keeping restore and destructive actions explicit', () => {
  assert.match(html, /id="confirmDialog"[\s\S]*id="confirmDialogAccept"/);
  assert.match(css, /\.confirm-dialog\.is-danger/);
  assert.match(app, /function askConfirmation\(/);
  assert.match(app, /source:'app-first-use'/);
  assert.match(app, /fingerprintDeviceKeyBundle\(entry\.public_key,entry\.layer2_public_key\)/);
  assert.match(html, /first-use pinning is automatic/i);
  assert.doesNotMatch(app, /I compared this fingerprint|Trust this key/);
  assert.match(app, /title:'Merge backup messages\?'/);
  assert.match(app, /danger:true/);
  assert.doesNotMatch(app, /\bconfirm\(/);
});

test('generated native and web primitives use the same shared component tokens', () => {
  const tokens = JSON.parse(read('design/tokens.json')).components;
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinTokens.java');
  const ios = read('apps/ios/SereinChat/SereinTokens.swift');
  const webTokens = read('frontend/web/tokens.css');
  assert.match(android, new RegExp(`BUTTON_HEIGHT_DP = ${tokens.button_height_dp}`));
  assert.match(android, new RegExp(`ICON_BUTTON_SIZE_DP = ${tokens.icon_button_size_dp}`));
  assert.match(android, new RegExp(`CHIP_HEIGHT_DP = ${tokens.chip_height_dp}`));
  assert.match(ios, new RegExp(`buttonHeight: CGFloat = ${tokens.button_height_dp}`));
  assert.match(ios, new RegExp(`iconButtonSize: CGFloat = ${tokens.icon_button_size_dp}`));
  assert.match(ios, new RegExp(`chipHeight: CGFloat = ${tokens.chip_height_dp}`));
  assert.match(webTokens, new RegExp(`--component-button-height:\\s*${tokens.button_height_dp}px`));
  assert.match(webTokens, new RegExp(`--component-chip-height:\\s*${tokens.chip_height_dp}px`));
});

test('native profile and media surfaces use shared chips, full-screen presentation, and aligned icon controls', () => {
  assert.match(androidUi, /static Button iconButton\(/);
  assert.match(androidUi, /static View lockIconButton\(/);
  assert.match(androidUi, /static Button chip\(/);
  assert.match(androidUi, /showStyledDialog\(AlertDialog dialog,boolean destructive\)/);
  assert.match(androidUi, /SereinTokens\.DIALOG_RADIUS_DP/);
  assert.match(androidConversation, /SereinUi\.showStyledDialog\(confirm,true\)/);
  assert.match(androidConversation, /private void showContactProfile\(\)/);
  assert.match(androidConversation, /profile\.getWindow\(\)\.setLayout\(-1,-1\)/);
  assert.match(androidConversation, /library\.setOnDismissListener\(dialog->\{if\(!isFinishing\(\)\)showContactProfile\(\);\}\)/);
  assert.match(iosDesign, /struct SereinChip: View/);
  assert.match(iosProduct, /\.fullScreenCover\(isPresented: \$showProfile\)/);
  assert.match(iosProduct, /\.confirmationDialog\("Block @\\\(contact\.username\)/);
});

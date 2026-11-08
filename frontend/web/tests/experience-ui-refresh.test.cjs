const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = (file) => fs.readFileSync(path.join(root, file), 'utf8');
const html = read('frontend/web/index.html');
const css = read('frontend/web/experience.css');
const app = read('frontend/web/app.js');
const curtainCss = read('frontend/web/components/session-curtain.css');
const curtainJs = read('frontend/web/components/session-curtain.js');
const confirmDialog = read('frontend/web/components/confirm-dialog.js');
const androidUi = read('apps/android/app/src/main/java/io/serein/chat/SereinUi.java');
const androidMain = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
const androidConversation = read('apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java');
const iosDesign = read('apps/ios/SereinChat/SereinDesign.swift');
const iosProduct = read('apps/ios/SereinChat/SereinProductView.swift');

test('loading curtain is a polished full-screen reveal component using the shared visual tokens', () => {
  assert.match(html, /class="curtain-mark"/);
  assert.match(curtainCss, /position:\s*fixed;[\s\S]*z-index:\s*2000;[\s\S]*inset:\s*0;/);
  assert.match(curtainCss, /--token-loading-panel/);
  assert.match(curtainCss, /translateX\(-102%\)/);
  assert.match(curtainCss, /translateX\(102%\)/);
  assert.match(curtainCss, /prefers-reduced-motion:\s*reduce/);
  assert.match(curtainJs, /transitionend/);
  assert.match(curtainJs, /matchMedia\('\(prefers-reduced-motion: reduce\)'\)/);
  assert.match(app, /sessionCurtain\.show/);
  assert.match(app, /sessionCurtain\.hide/);
});

test('first-visit auth is separate and inertness is scoped to the temporary full-screen curtain', () => {
  assert.match(html, /id="sessionCurtain" class="session-curtain hidden"[^>]*hidden inert/);
  assert.match(html, /<\/div>\s*<div id="login"/);
  assert.match(app, /if\(!hasSavedSessionHint\(\)\)\{[\s\S]*?return;/);
  assert.match(app, /state\.sessionRestoreInProgress=true;sessionCurtain\.show\(\)/);
  assert.match(curtainCss, /\.session-curtain\[hidden\][\s\S]*display:\s*none\s*!important/);
  assert.match(curtainJs, /element\.inert = true/);
  assert.match(curtainJs, /restoreUnderlyingPage/);
});

test('web and native sign-in make server connection an obvious bordered control', () => {
  assert.match(html, /id="authConnectionOpen" class="connection-chip"/);
  assert.match(css, /\.connection-chip\s*\{[\s\S]*border:\s*1px solid var\(--border-strong\)/);
  assert.match(androidMain, /SereinUi\.chip\(this,"↗  Server connection",true\)/);
  assert.match(iosProduct, /Label\("Server connection", systemImage: "network"\)[\s\S]*Capsule\(\)\.stroke/);
  assert.match(iosProduct, /RoundedRectangle\(cornerRadius: 11\)\.stroke/);
});

test('contact-profile header aligns navigation and title, with modern SVG action buttons and restrained palette', () => {
  assert.match(html, /id="profileBack"[^>]*aria-label="Back to conversation"[\s\S]*?<svg/);
  assert.match(html, /id="profileClose"[^>]*aria-label="Close contact profile"[\s\S]*?<svg/);
  assert.match(html, /id="profileAudio" class="profile-action"[^>]*disabled[\s\S]*?<svg/);
  assert.match(html, /id="profileVideo" class="profile-action"[^>]*disabled[\s\S]*?<svg/);
  assert.match(css, /\.profile-screen-head\s*\{\s*display:\s*flex;\s*flex: 0 0 auto;\s*flex-direction:\s*row/);
  assert.match(css, /\.profile-quick-actions\s*\{\s*display:\s*grid;\s*grid-template-columns:\s*repeat\(3/);
  assert.match(css, /\.profile-action-icon svg\s*\{[^}]*stroke:/);
  assert.match(css, /\.profile-media-strip\s*\{[^}]*scroll-snap-type:\s*x mandatory/);
  assert.match(iosProduct, /NavigationLink\(isActive: \$showMediaLibrary\)/);
  assert.match(androidConversation, /R\.drawable\.ic_nav_back_24/);
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
  assert.match(html, /id="mediaLibraryView"[\s\S]*data-library-filter="image"[\s\S]*data-library-filter="video"/);
  assert.doesNotMatch(html, /id="mediaLibraryDialog"/);
  assert.match(app, /function openMediaLibrary\(\)[\s\S]*?panel\.classList\.add\('media-library-open'\)/);
  assert.match(app, /function closeMediaLibrary\(\{restoreFocus=true\}={}\)/);
  assert.match(app, /profileHeaderTitle/);
  assert.match(app, /loadProfileThumbnail\(item,image\)/);
});

test('app automatically pins first-seen dual-key bundles while keeping restore and destructive actions explicit', () => {
  assert.match(html, /id="confirmDialog"[\s\S]*id="confirmDialogAccept"/);
  assert.match(css, /\.confirm-dialog\.is-danger/);
  assert.match(app, /const askConfirmation = confirmationDialog\.ask/);
  assert.match(confirmDialog, /function ask\(/);
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
  assert.match(androidConversation, /private void switchProfilePage\(Dialog dialog,View outgoing,View incoming,boolean forward\)/);
  assert.match(androidConversation, /R\.drawable\.ic_nav_back_24/);
  assert.match(androidConversation, /R\.drawable\.ic_nav_close_24/);
  assert.match(androidConversation, /R\.drawable\.ic_action_message_24/);
  assert.match(androidConversation, /R\.drawable\.ic_action_phone_24/);
  assert.match(iosProduct, /profileAction\("Audio", systemImage: "phone\.fill", enabled: false\)/);
  assert.match(iosProduct, /profileAction\("Video", systemImage: "video\.fill", enabled: false\)/);
  assert.match(iosDesign, /struct SereinChip: View/);
  assert.match(iosProduct, /\.fullScreenCover\(isPresented: \$showProfile\)/);
  assert.match(iosProduct, /\.confirmationDialog\("Block @\\\(contact\.username\)/);
});

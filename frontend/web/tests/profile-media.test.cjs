const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const web = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'frontend/web/index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'frontend/web/experience.css'), 'utf8');
const android = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java'), 'utf8');
const ios = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinProductView.swift'), 'utf8');

test('contact profiles show ten newest media previews and append an equal-size View all tile', () => {
  assert.match(web, /function renderProfileMedia\(\)[\s\S]*?all\.slice\(0,10\)/);
  assert.match(web, /profileAttachments\(contactId=state\.selected\?\.id\)[\s\S]*sort\(\(a,b\)=>b\.createdAt\.localeCompare\(a\.createdAt\)/);
  assert.match(web, /profileMediaGrid/);
  assert.match(web, /profile-view-all-tile/);
  assert.match(html, /class="profile-media-strip"[^>]*aria-label="Latest shared files"/);
  assert.doesNotMatch(html, /id="profileMediaSeeAll"|id="mediaLibraryDialog"/);
  assert.match(css, /\.profile-media-strip\s*\{[^}]*grid-auto-flow:\s*column[^}]*overflow-x:\s*auto/s);
  assert.match(css, /\.profile-view-all-tile\s*\{[\s\S]*border-style:\s*dashed/);
  assert.match(android, /Math\.min\(10,attachments\.size\(\)\)/);
  assert.match(android, /viewAllMediaTile\(attachments\.size\(\),profile,page,libraryOpen,libraryPage\)/);
  assert.match(ios, /latestTen: \[SereinChatMessage\] \{ Array\(allAttachments\.prefix\(10\)\) \}/);
  assert.match(ios, /ForEach\(latestTen\)/);
  assert.match(ios, /Button \{ showMediaLibrary=true \} label:/);
});

test('View all navigates within the current profile surface instead of opening a second modal', () => {
  assert.match(web, /function openMediaLibrary\(\)[\s\S]*?panel\.classList\.add\('media-library-open'\)/);
  assert.match(web, /function closeMediaLibrary\(\{restoreFocus=true\}={}\)[\s\S]*?panel\.classList\.remove\('media-library-open'\)/);
  assert.match(web, /#mediaLibraryView/);
  assert.doesNotMatch(html, /<dialog id="mediaLibraryDialog"/);
  assert.match(android, /private void showMediaLibrary\(Dialog profile,View profilePage,boolean\[\] libraryOpen,View\[\] libraryPage\)/);
  assert.match(android, /switchProfilePage\(profile,profilePage,root,true\)/);
  assert.doesNotMatch(android, /Dialog library=new Dialog\(this\)/);
  assert.match(ios, /NavigationLink\(isActive: \$showMediaLibrary\)/);
  assert.doesNotMatch(ios, /fullScreenCover\(isPresented: \$showMediaLibrary\)/);
});

test('profile previews open authenticated attachment bytes in media viewers, with documents routed to OS viewers', () => {
  assert.match(web, /openAttachmentItem\(item\).*showAttachmentPreview/);
  assert.match(web, /attachmentPreviewDialog/);
  assert.match(android, /engine\.downloadAttachment\(attachment\)/);
  assert.match(android, /private void showAttachmentViewer\(/);
  assert.match(android, /SereinAttachmentStore\.open\(this,file,type\)/);
  assert.match(ios, /engine\.download\(attachment\)/);
  assert.match(ios, /SereinDirectMediaViewer\(item:item\)/);
  assert.match(ios, /SereinQuickLookDocument\(url:item\.url\)/);
});

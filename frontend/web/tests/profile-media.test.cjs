const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const web = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'frontend/web/index.html'), 'utf8');
const android = fs.readFileSync(path.join(root, 'apps/android/app/src/main/java/io/serein/chat/SereinConversationActivity.java'), 'utf8');
const ios = fs.readFileSync(path.join(root, 'apps/ios/SereinChat/SereinProductView.swift'), 'utf8');

test('contact profiles cap the preview at four recent files and expose a separate Media/Documents library', () => {
  assert.match(web, /profileAttachments\(contact\.id\);[^\n]*all\.slice\(0,4\)/);
  assert.match(android, /for\(int i=0;i<Math\.min\(4,attachments\.size\(\)\);i\+=2\)/);
  assert.match(ios, /Array\(allAttachments\.prefix\(4\)\)/);
  assert.match(html, /id="profileMediaSeeAll"/);
  assert.match(html, /data-library-tab="media"/);
  assert.match(html, /data-library-tab="documents"/);
  assert.match(web, /function renderMediaLibrary\(\)/);
  assert.match(android, /private void showMediaLibrary\(\)/);
  assert.match(ios, /private struct SereinMediaLibrary: View/);
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

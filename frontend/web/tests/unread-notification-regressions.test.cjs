const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const app = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');

test('mobile back leaves the conversation instead of keeping a stale selected contact', () => {
  const leave = app.slice(app.indexOf('function leaveConversation('), app.indexOf('async function openContact('));
  assert.match(leave, /state\.drafts\[contact\.id\]=el\.messageInput\.value/);
  assert.match(leave, /state\.selected=null/);
  assert.match(leave, /state\.conversationKeys\.clear\(\)/);
  assert.match(leave, /\$\('conversation'\)\.classList\.add\('hidden'\)/);
  assert.match(app, /\$\('mobileBack'\)\.addEventListener\('click',leaveConversation\)/);
});

test('unread state and in-app sound depend on the visible foreground conversation, not only selection', () => {
  assert.match(app, /function isConversationActivelyViewed\(contactId\)\{return !!contactId&&document\.visibilityState==='visible'&&state\.selected\?\.id===contactId&&!\$\('app'\)\.classList\.contains\('hidden'\)&&!\$\('conversation'\)\.classList\.contains\('hidden'\);\}/);
  const notify = app.slice(app.indexOf('function notifyIncomingMessage('), app.indexOf('function loadTheme('));
  assert.match(notify, /viewed=isConversationActivelyViewed\(contact\.id\)/);
  assert.match(notify, /state\.settings\.notification_sound&&!viewed\)playIncomingTone\(\)/);
  const process = app.slice(app.indexOf('async function processPacket('), app.indexOf('async function handlePacket('));
  assert.match(process, /if\(isConversationActivelyViewed\(contact\.id\)\)contact\.unread=0;else\{contact\.unread\+\+;/);
  assert.match(process, /if\(isConversationActivelyViewed\(contact\.id\)\)await markMessageRead\(packet\.id\)/);
});

test('returning to a visible chat clears unread counts accumulated in Settings or a background tab', () => {
  assert.match(app, /function markSelectedConversationViewed\(\)[\s\S]*?contact\.unread=0;saveContacts\(\)[\s\S]*?markConversationMessagesRead\(contact\.id\)/);
  assert.match(app, /\$\('settingsBack'\)\.addEventListener\('click',[\s\S]*?markSelectedConversationViewed\(\)/);
  assert.match(app, /document\.addEventListener\('visibilitychange',[\s\S]*?document\.visibilityState==='visible'[\s\S]*?markSelectedConversationViewed\(\)/);
  assert.match(app, /window\.addEventListener\('focus',[\s\S]*?markSelectedConversationViewed\(\)/);
});

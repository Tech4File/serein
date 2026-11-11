const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const app = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');
const html = fs.readFileSync(path.join(root, 'frontend/web/index.html'), 'utf8');
const css = fs.readFileSync(path.join(root, 'frontend/web/experience.css'), 'utf8');

test('contact profile closes through the existing animated path when leaving its chat or opening another area', () => {
  assert.match(app, /if\(state\.selected\?\.id!==contact\.id&&isContactProfileOpen\(\)\)closeContactProfilePanel\(\{restoreFocus:false\}\)/);
  assert.match(app, /function showSettings\(section='profile'\)\{if\(isContactProfileOpen\(\)\)closeContactProfilePanel\(\{restoreFocus:false\}\)/);
  assert.match(app, /function leaveConversation\(\)\{if\(isContactProfileOpen\(\)\)closeContactProfilePanel\(\{restoreFocus:false\}\)/);
  assert.match(app, /const openContactDialog=\(\)=>\{if\(isContactProfileOpen\(\)\)closeContactProfilePanel\(\{restoreFocus:false\}\)/);
  assert.match(app, /requestsOpen'\)\.addEventListener\('click',\(\)=>\{if\(isContactProfileOpen\(\)\)closeContactProfilePanel\(\{restoreFocus:false\}\)/);
  assert.match(app, /function closeContactProfilePanel\(\{restoreFocus=true,clear=true\}=\{\}\)[\s\S]*?panel\.classList\.remove\('is-open'\)/);
  assert.match(css, /\.contact-profile-panel\.is-open \{ transform: translateX\(0\); visibility: visible/);
});

test('account sidebar reports relay online/reconnecting state instead of the ambiguous Account ready tagline', () => {
  assert.match(html, /id="accountPresence" class="account-presence-label">Connecting…/);
  assert.doesNotMatch(html, /Account ready/);
  assert.match(app, /accountOnline=!!state\.user&&active/);
  assert.match(app, /accountPresence\.textContent=accountOnline\?'Online':state\.user\?'Reconnecting…':'Offline'/);
  assert.match(css, /\.profile-meta \.account-presence-dot\.is-offline/);
});

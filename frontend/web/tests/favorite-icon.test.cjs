const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const html = fs.readFileSync(path.join(root, 'frontend/web/index.html'), 'utf8');
const app = fs.readFileSync(path.join(root, 'frontend/web/app.js'), 'utf8');

test('chat favorite action is an accessible star toggle, not a more-options ellipsis', () => {
  assert.match(html, /id="chatMenu"[^>]*favorite-toggle[^>]*aria-label="Add to favorites"[^>]*aria-pressed="false"[^>]*disabled>☆<\/button>/);
  assert.doesNotMatch(html, /id="chatMenu"[^>]*>•••<\/button>/);
  assert.match(app, /button\.textContent=favorite\?'★':'☆'/);
  assert.match(app, /button\.setAttribute\('aria-pressed',String\(favorite\)\)/);
  assert.match(app, /button\.title=favorite\?'Remove from favorites':'Add to favorites'/);
  assert.match(app, /contact\.favorite=!contact\.favorite;syncFavoriteButton\(\);saveContacts\(\)/);
  assert.match(app, /\$\('profileFavorite'\)\.textContent=contact\.favorite\?/);
  assert.match(app, /\$\('profileFavorite'\)\.addEventListener\('click',toggleSelectedFavorite\)/);
  assert.match(app, /disabled=!contact\|\|!!contact\.deleted\|\|!!contact\.historyOnly/);
});

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const web = read('frontend/web/app.js');
const html = read('frontend/web/index.html');
const css = read('frontend/web/experience.css');
const backend = read('backend/src/main.rs');
const android = read('apps/android/app/src/main/java/io/serein/chat/MainActivity.java');
const androidApi = read('apps/android/app/src/main/java/io/serein/chat/SereinApi.java');
const ios = read('apps/ios/SereinChat/SereinProductView.swift');
const iosApi = read('apps/ios/SereinChat/SereinAPI.swift');

test('exact account lookup is authenticated, throttled, non-enumerating, block-aware, and follows privacy settings', () => {
  assert.match(backend, /route\("\/api\/v1\/contact-lookup", get\(lookup_contact\)\)/);
  const lookup = backend.slice(backend.indexOf('async fn lookup_contact('), backend.indexOf('async fn create_contact_request('));
  assert.match(lookup, /require_user\(&state,&headers\)/);
  assert.match(lookup, /valid_email\(&identity\)/);
  assert.match(lookup, /valid_username\(&normalise_username\(&identity\)\)/);
  assert.match(lookup, /"contact-lookup",60/);
  assert.match(lookup, /a\.email_verified=TRUE/);
  assert.match(lookup, /NOT EXISTS\(SELECT 1 FROM user_blocks/);
  assert.match(lookup, /discoverable_by_email/);
  assert.match(lookup, /allow_contact_requests/);
  assert.match(lookup, /relationship.*connected.*incoming.*pending.*request/s);
  assert.match(lookup, /presence_visible=connected&&presence_allowed/);
  assert.match(lookup, /"result":null/);
  assert.doesNotMatch(lookup, /ILIKE|LIKE\s|prefix search/);
  assert.match(backend, /LEAST\(account_action_limits\.attempt_count\+1,61\)/);
  assert.match(backend, /private_lookup[\s\S]*CACHE_CONTROL,HeaderValue::from_static\("no-store"\)/);
});

test('Web lookup is exact-match and debounced, previews a profile card, and gives relationship-specific actions', () => {
  assert.match(html, /id="contactLookupResults" class="contact-lookup-results"/);
  assert.match(html, /id="contactLookupDialogResult" class="contact-lookup-results dialog-lookup-results"/);
  assert.match(html, /Exact username or verified email/);
  assert.match(web, /function normalizeContactLookupIdentity/);
  assert.match(web, /function lookupContactIdentity/);
  assert.match(web, /setTimeout\(run,500\)/);
  assert.match(web, /\/api\/v1\/contact-lookup\?identity=/);
  assert.match(web, /Available to receive a request/);
  assert.match(web, /Request sent · awaiting acceptance/);
  assert.match(web, /relationship==='connected'\?'message'/);
  assert.match(web, /\/api\/v1\/contact-requests\/\$\{encodeURIComponent\(result\.request_id\)\}\/accept/);
  assert.match(web, /Request sent to @\$\{result\.username\}/);
  assert.match(css, /\.contact-lookup-card/);
  assert.match(css, /\.contact-lookup-action svg/);
});

test('Android lookup exposes a privacy-aware live profile card with message, accept, request, and pending states', () => {
  assert.match(androidApi, /void lookupContact\(String identity, Callback cb\)/);
  assert.match(androidApi, /\/api\/v1\/contact-lookup\?identity=/);
  const finder = android.slice(android.indexOf('private void showAddContact()'), android.indexOf('private void showChatNotice'));
  assert.match(finder, /addTextChangedListener/);
  assert.match(finder, /postDelayed\(pending\[0\],450\)/);
  assert.match(finder, /renderContactLookupCard/);
  assert.match(finder, /✉ Message/);
  assert.match(finder, /✓ Accept/);
  assert.match(finder, /◷ Pending/);
  assert.match(finder, /＋ Request/);
  assert.match(finder, /email lookup works only when the account allows it/);
});

test('iOS Contacts offers a debounced exact-identity profile finder with relationship-aware controls', () => {
  assert.match(iosApi, /struct SereinContactLookup: Decodable, Identifiable/);
  assert.match(iosApi, /func lookupContact\(identity: String\) async throws -> SereinContactLookup\?/);
  assert.match(ios, /SereinContactFinder\(api: api\)/);
  const finder = ios.slice(ios.indexOf('private struct SereinContactFinder:'), ios.indexOf('private struct SereinNativeContacts:'));
  assert.match(finder, /\.task\(id: identity\)/);
  assert.match(finder, /Task\.sleep\(nanoseconds: 450_000_000\)/);
  assert.match(finder, /SereinAvatar\(name: result\.display_name/);
  assert.match(finder, /SereinNativeConversation\(api: api, contact: contact\)/);
  assert.match(finder, /person\.badge\.plus/);
  assert.match(finder, /email lookup works only when the account allows it/);
});

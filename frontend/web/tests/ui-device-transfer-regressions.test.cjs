const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');
const html = read('frontend/web/index.html');
const authCss = read('frontend/web/auth-responsive.css');
const workspaceCss = read('frontend/web/workspace.css');
const experienceCss = read('frontend/web/experience.css');
const app = read('frontend/web/app.js');
const androidEngine = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
const iosEngine = read('apps/ios/SereinChat/SereinChatEngine.swift');
const backend = read('backend/src/main.rs');
const core = read('crates/serein-core/src/lib.rs');
const symmetricRatchet = read('crates/serein-core/src/ratchet.rs');
const doubleRatchet = read('crates/serein-core/src/double_ratchet.rs');

test('auth view remains vertically scrollable on short screens and at larger text scales', () => {
  assert.match(authCss, /html\.auth-visible, body\.auth-visible\s*\{[^}]*overflow-y:\s*auto/s);
  assert.match(authCss, /body\.auth-visible #login, body\.auth-visible \.auth-main\s*\{[^}]*height:\s*auto/s);
  assert.match(authCss, /body\.auth-visible \.auth-card\s*\{\s*flex:\s*0 0 auto/s);
  assert.doesNotMatch(authCss, /html\.auth-visible, body\.auth-visible\s*\{[^}]*overflow-y:\s*hidden/s);
});

test('security modal has one bounded content scroller and device summaries avoid vertical text squeeze', () => {
  assert.match(html, /class="security-dialog-body"[\s\S]*?id="peerKeyControls"[\s\S]*?security-footnote[\s\S]*?class="connection-actions"/);
  assert.match(workspaceCss, /\.security-dialog-body\s*\{[^}]*overflow:\s*auto/s);
  assert.match(workspaceCss, /\.security-dialog \.peer-key-controls\s*\{\s*max-height:\s*none;\s*overflow:\s*visible/s);
  assert.match(experienceCss, /\.security-dialog \.peer-key-row\s*\{\s*display:\s*block;\s*padding:\s*0/s);
  assert.match(experienceCss, /\.security-dialog \.peer-key-summary\s*\{\s*display:\s*grid;\s*grid-template-columns:\s*minmax\(0, 1fr\) minmax\(/s);
  assert.match(experienceCss, /\.security-dialog \.peer-key-summary b\s*\{[^}]*overflow-wrap:\s*break-word/s);
});

test('GIF search controls keep intrinsic button width and let the search input shrink on narrow phones', () => {
  assert.match(experienceCss, /\.gif-search-wrap\s*\{\s*flex:\s*1;\s*\}/s);
  assert.match(experienceCss, /\.gif-search-wrap\s*\{\s*min-width:\s*0;\s*\}/s);
  assert.match(experienceCss, /\.gif-search-button\s*\{\s*width:\s*auto;\s*height:\s*auto/s);
  assert.match(experienceCss, /@media \(max-width: 360px\)[\s\S]*?\.gif-search-button\s*\{\s*padding-inline:\s*8px/s);
  assert.match(experienceCss, /\*::-webkit-scrollbar-thumb\s*\{/);
});

test('web refreshes recipient device discovery before message/file fan-out and retries one stale key-directory snapshot', () => {
  assert.match(app, /async function deriveCandidateConversationKeys\(contact,allowSnapshotRefresh=true\)/);
  assert.match(app, /const snapshotMismatch=remote\.some\(item=>!activeIds\.has\(item\.device_id\)\)\|\|active\.some\(device=>!byId\.has\(device\.id\)\)/);
  assert.match(app, /if\(snapshotMismatch&&allowSnapshotRefresh\)\{\s*await refreshContacts\(\)/);
  const send = app.slice(app.indexOf('async function sendMessage('), app.indexOf('async function encryptAndUploadAttachment('));
  assert.ok(send.indexOf('await refreshContacts()') < send.indexOf('const targets=contact.devices.filter'));
  const upload = app.slice(app.indexOf('async function encryptAndUploadAttachment('), app.indexOf('function clearAttachmentPreview('));
  assert.ok(upload.indexOf('await refreshContacts()') < upload.indexOf('const targets=contact.devices.filter'));
  assert.match(app, /await refreshContacts\(\);contact=state\.contacts\.find\(item=>item\.devices\.some\(device=>device\.id===packet\.from\)\)/);
  const incoming = app.slice(app.indexOf('async function processPacket('), app.indexOf('async function handlePacket('));
  assert.ok(incoming.indexOf('await deriveCandidateConversationKeys(contact)') < incoming.indexOf('const peer=state.conversationKeys.get'));
  assert.match(incoming, /if\(!peer\?\.trusted\)\{if\(state\.selected\?\.id===contact\.id\)state\.peerKeyState='Sender device key changed or is not locally pinned\.'/);
});

test('file uploads rebuild one stale live-device manifest after refreshing contacts and keys', () => {
  const send = app.slice(app.indexOf('async function sendMessage('), app.indexOf('async function encryptAndUploadAttachment('));
  const upload = app.slice(app.indexOf('async function encryptAndUploadAttachment('), app.indexOf('function clearAttachmentPreview('));
  assert.match(send, /expectedRecipientDeviceIds[\s\S]*?stale_attachment_targets/);
  assert.match(upload, /retryManifestSnapshot=true/);
  assert.match(upload, /await refreshContacts\(\)[\s\S]*?encryptAndUploadAttachment\(file,false,contact\.id,true\)/);
  assert.match(upload, /No transfer was created[\s\S]*A changed pinned key will remain blocked/);
  assert.match(upload, /sendMessage\(null,attachment,contact,targets\.map\(device=>device\.id\)\)/);
  assert.match(upload, /created&&complete&&error\.code==='stale_attachment_targets'[\s\S]*?No chat notice was sent/);
  assert.match(upload, /A recipient device key differs from its local pin/);
  assert.match(upload, /A recipient device lowered its pinned ratchet capability/);
  assert.match(upload, /if\(!created&&error\.status===400&&error\.message==='manifest must include the sending session and every active recipient device'\)/);
});

test('native text and file sends refresh device discovery immediately and retry only snapshot races', () => {
  const androidSend = androidEngine.slice(androidEngine.indexOf('private CompletableFuture<Void> sendMessage('), androidEngine.indexOf('private List<Peer> trustedTargets()'));
  const androidUpload = androidEngine.slice(androidEngine.indexOf('CompletableFuture<Void> uploadAttachment('), androidEngine.indexOf('static String mimeType'));
  const iosSend = iosEngine.slice(iosEngine.indexOf('private func sendMessage(_ text:'), iosEngine.indexOf('private func trustedTargets('));
  const iosUpload = iosEngine.slice(iosEngine.indexOf('func sendFile('), iosEngine.indexOf('func localFile('));
  assert.match(androidSend, /refreshPeersForSend\(\)\.thenComposeAsync/);
  assert.match(androidUpload, /refreshPeersForSend\(\)\.thenComposeAsync/);
  assert.match(androidEngine, /private CompletableFuture<Void> refreshPeersForSend\(\)[\s\S]*?refreshPeers\(\)[\s\S]*?retry/);
  assert.match(iosSend, /try await refreshPeerKeysForSend\(\)[\s\S]*?trustedTargets\(\)/);
  assert.match(iosUpload, /try await refreshPeerKeysForSend\(\)[\s\S]*?trustedTargets\(\)/);
  assert.match(iosEngine, /catch ChatError\.deviceListChanged \{ try await refreshPeerKeys\(\) \}/);
});

test('transport audit distinguishes live TCP messaging from unimplemented call signalling/media', () => {
  assert.match(backend, /tokio::net::TcpListener::bind/);
  assert.match(backend, /WebSocketUpgrade/);
  assert.match(backend, /\"quic_media_transport\": \"not_implemented\"/);
  assert.match(backend, /\"session_signaling\": \"not_implemented\"/);
  assert.match(html, /Text messaging uses the server’s HTTPS and WebSocket endpoints/);
  assert.match(core, /This framing is NOT a transport protocol/);
  assert.doesNotMatch(`${backend}\\n${app}`, /UdpSocket|RTCPeerConnection/);
});

test('shared Rust ratchets preserve transactional authentication and document bootstrap/security limits', () => {
  assert.ok(core.includes('symmetric chain ratchet, and a separate\n//! development-stage X25519 Double Ratchet'));
  assert.ok(core.includes('must not treat these modules as production-ready'));
  assert.match(symmetricRatchet, /authenticate\/decrypt with the ticket key, then commit/);
  assert.match(symmetricRatchet, /fn dropping_uncommitted_receive_ticket_preserves_chain_for_authentication_retry/);
  assert.match(symmetricRatchet, /fn tampered_ciphertext_does_not_consume_a_message_key/);
  assert.match(doubleRatchet, /temporary state copy and commit only after the GCM tag is verified/);
  assert.match(doubleRatchet, /fn double_ratchet_failed_authentication_does_not_commit_dh_or_chain_state/);
  assert.ok(doubleRatchet.includes('X3DH/signed-prekey directory handling, identity'));
});

test('recipient key pins and exact transfer manifests remain fail-closed with actionable stale-race errors', () => {
  assert.match(app, /previousFingerprint===fingerprint&&\[2,3\]\.includes\(previousRatchetVersion\)&&ratchetVersion>=previousRatchetVersion/);
  assert.match(app, /recipient device key changed or its ratchet capability was downgraded\. Sending remains blocked by the local pin/);
  assert.match(app, /Recipient devices changed again while preparing the encrypted upload\. No transfer was created/);
  assert.match(backend, /SELECT d\.id,d\.user_id FROM devices d WHERE d\.user_id IN \(\$1,\$2\) AND d\.revoked_at IS NULL AND EXISTS\(SELECT 1 FROM auth_sessions s WHERE s\.device_id=d\.id AND s\.user_id=d\.user_id AND s\.expires_at>now\(\)\)/);
  assert.match(backend, /if supplied!=expected\{[\s\S]*?manifest must include the sending session and every active recipient device/);
  assert.match(backend, /encrypted transfer quota advisory lock failed/);
  assert.match(backend, /encrypted transfer quota usage query failed/);
  assert.match(backend, /transfer quota lock unavailable/);
  assert.match(backend, /transfer quota usage unavailable/);
});

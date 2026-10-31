const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '../../..');
const read = file => fs.readFileSync(path.join(root, file), 'utf8');

test('all three clients check both key layers and automatically pin a first-seen combined fingerprint locally', () => {
  const web = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  const ios = read('apps/ios/SereinChat/SereinChatEngine.swift');
  assert.match(web, /fingerprintDeviceKeyBundle\(entry\.public_key,entry\.layer2_public_key\)/);
  assert.match(web, /const firstSeen=!trust/);
  assert.match(web, /source:'app-first-use'/);
  assert.match(android, /fingerprintBundle\(jwk,layer2Jwk\)/);
  assert.match(android, /boolean firstSeen=trustedFingerprint\.isEmpty\(\);if\(firstSeen\)\{local\.trustFingerprint\(contactId,id,fingerprint,ratchetVersion\)/);
  assert.match(ios, /fingerprintBundle\(layer1: jwk, layer2: layer2JWK\)/);
  assert.match(ios, /let firstSeen = old\.isEmpty/);
  assert.match(ios, /local\?\.trust\(userID: contact\.user_id, deviceID: target\.id, fingerprint: fingerprint/);
});

test('fingerprint changes and capability downgrades block send/decrypt, while same-key upgrades are adopted automatically', () => {
  const web = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  const ios = read('apps/ios/SereinChat/SereinChatEngine.swift');
  assert.match(web, /previousFingerprint===fingerprint&&\[2,3\]\.includes\(previousRatchetVersion\)&&ratchetVersion>=previousRatchetVersion/);
  assert.match(web, /else if\(trusted&&ratchetVersion>previousRatchetVersion\)/);
  assert.match(web, /Changed key · sending blocked/);
  assert.match(android, /boolean capabilityAccepted=\(pinnedVersion==2\|\|pinnedVersion==3\)&&ratchetVersion>=pinnedVersion/);
  assert.match(android, /sameFingerprint&&capabilityAccepted&&ratchetVersion>pinnedVersion/);
  assert.match(ios, /let capabilityAccepted = \(2\.\.\.3\)\.contains\(oldVersion\) && ratchetVersion >= oldVersion/);
  assert.match(ios, /if sameFingerprint && capabilityAccepted && ratchetVersion > oldVersion/);
});

test('clients and server reject unsupported key algorithms, ratchet capabilities, and invalid P-256 points', () => {
  const web = read('frontend/web/app.js');
  const android = read('apps/android/app/src/main/java/io/serein/chat/SereinChatEngine.java');
  const ios = read('apps/ios/SereinChat/SereinChatEngine.swift');
  const backend = read('backend/src/main.rs');
  assert.match(web, /entry\.algorithm!=='ECDH-P256'/);
  assert.match(web, /if\(!\[2,3\]\.includes\(ratchetVersion\)\)/);
  assert.match(web, /peer\.ratchetVersion!==3\|\|!window\.SereinCore\?\.wasmActive/);
  assert.match(android, /if\(ratchetVersion!=2&&ratchetVersion!=3\)/);
  assert.match(ios, /guard ratchetVersion == 2 \|\| ratchetVersion == 3/);
  assert.match(backend, /parse_p256_public_jwk\(layer1\)\?;parse_p256_public_jwk\(layer2\)\?/);
  assert.match(backend, /device_key_bundle_fingerprint_rejects_off_curve_points/);
});

test('product copy does not misrepresent first-use pinning as independent identity authentication', () => {
  const html = read('frontend/web/index.html');
  const security = read('frontend/web/security.html');
  const ios = read('apps/ios/SereinChat/SereinProductView.swift');
  assert.match(html, /not independent proof of a contact.s identity/);
  assert.match(security, /not independent identity proof/);
  assert.match(ios, /not independent identity proof if the key directory is compromised/);
  assert.doesNotMatch(html, /I compared this fingerprint/);
  assert.doesNotMatch(ios, /I compared this fingerprint/);
});

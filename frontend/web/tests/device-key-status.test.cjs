const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const app = fs.readFileSync(path.resolve(__dirname, '..', 'app.js'), 'utf8');
const crypto = fs.readFileSync(path.resolve(__dirname, '..', 'device-crypto.js'), 'utf8');

test('missing recipient keys are reported against the specific recipient device, not the current browser', () => {
  assert.match(app, /missingDevices\.push\(\{deviceId:device\.id,deviceName:device\.name\|\|'Device'\}\)/);
  assert.match(app, /peer-key-missing/);
  assert.match(app, /This signed-in device has not published both encryption-key layers yet/);
});

test('fingerprint trust remains local and scoped to the exact contact-device pair', () => {
  assert.match(app, /trusted-peer:\$\{contact\.id\}:\$\{device\.id\}/);
  assert.match(app, /localMetaKey\(name\).*state\.device\.id/);
  assert.match(app, /const storedVersion=trust\?\.ratchetVersion==null\?2:Number\(trust\.ratchetVersion\)/);
  assert.match(app, /const ratchetVersion=entry\.ratchet_version==null\?2:Number\(entry\.ratchet_version\)/);
  assert.match(app, /source:'app-first-use'/);
  assert.match(app, /deriveLayer2ConversationKey\(state\.deviceKeyPair\.layer2PrivateKey,state\.user\.id,state\.device\.id,contact\.id,device\.id,entry\.layer2_public_key\)/);
});

test('only public JWK coordinates are sent to the public-key directory', () => {
  const start = app.indexOf("const reply=await api('/api/v1/device-key'");
  const registration = app.slice(start, app.indexOf(';\n', start));
  assert.match(registration, /public_key:publicKey,layer2_public_key:layer2PublicKey/);
  assert.doesNotMatch(registration, /privateKey|layer2PrivateKey/);
  assert.match(crypto, /pair\.privateKey\.extractable\s*\|\|\s*publicJwk\.d/);
});

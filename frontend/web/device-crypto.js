/* Browser cryptographic adapter for Serein device-key exchange and message envelopes.
 * Uses native WebCrypto primitives only; review and key-lifecycle work remain outstanding.
 */
(() => {
  'use strict';
  const encoder = new TextEncoder();
  function decodeBase64Url(value) {
    const raw = String(value || '');
    const padded = raw.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(raw.length / 4) * 4, '=');
    return Uint8Array.from(atob(padded), character => character.charCodeAt(0));
  }
  function encodeBase64Url(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  function encodeBase64(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
  }
  function decodeStandardBase64(value) {
    const raw = String(value || '');
    if (!/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(raw)) throw new Error('Malformed message Base64.');
    return Uint8Array.from(atob(raw), character => character.charCodeAt(0));
  }
  function messageAdditionalData(metadata, layer = 'legacy') {
    const fields = ['conversationId', 'messageId', 'senderUserId', 'senderDeviceId', 'recipientUserId', 'recipientDeviceId'];
    const values = fields.map(field => String(metadata?.[field] || ''));
    if (values.some(value => !value || value.length > 128)) throw new Error('Message authentication metadata is incomplete.');
    const label = layer === 'legacy' ? 'serein-message-v1' : `serein-message-${layer}-v2`;
    return encoder.encode(JSON.stringify([label, ...values]));
  }
  async function sealMessageLayer(key, cleartext, aad) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, cleartext);
    return { iv: encodeBase64(iv), ciphertext: encodeBase64(new Uint8Array(ciphertext)) };
  }
  async function openMessageLayer(key, envelope, aad, maximum = 50_000) {
    const iv = decodeStandardBase64(envelope?.iv), ciphertext = decodeStandardBase64(envelope?.ciphertext);
    if (iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > maximum) throw new Error('Malformed encrypted-message envelope.');
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ciphertext);
  }
  async function encryptMessage(layer1Key, layer2Key, plaintext, metadata) {
    if (typeof plaintext !== 'string') throw new Error('Message plaintext must be text.');
    const cleartext = encoder.encode(plaintext);
    if (cleartext.length > 16_384) throw new Error('Message exceeds the 16 KiB encrypted-envelope plaintext limit.');
    const inner = await sealMessageLayer(layer1Key, cleartext, messageAdditionalData(metadata, 'layer1'));
    const innerBytes = encoder.encode(JSON.stringify({ version: 1, algorithm: 'AES-256-GCM', ...inner }));
    const outer = await sealMessageLayer(layer2Key, innerBytes, messageAdditionalData(metadata, 'layer2'));
    return { version: 2, algorithm: 'SEREIN-LAYER2-AES-256-GCM', ...outer };
  }
  async function decryptMessage(layer1Key, layer2Key, envelope, metadata) {
    if (envelope?.version === 1 && envelope?.algorithm === 'AES-256-GCM') {
      const plaintext = await openMessageLayer(layer1Key, envelope, messageAdditionalData(metadata), 16_400);
      return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
    }
    if (envelope?.version !== 2 || envelope?.algorithm !== 'SEREIN-LAYER2-AES-256-GCM') throw new Error('Unsupported encrypted-message envelope.');
    const outer = await openMessageLayer(layer2Key, envelope, messageAdditionalData(metadata, 'layer2'));
    let inner;
    try { inner = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(outer)); }
    catch { throw new Error('Malformed nested encrypted-message envelope.'); }
    if (inner?.version !== 1 || inner?.algorithm !== 'AES-256-GCM') throw new Error('Unsupported inner encrypted-message envelope.');
    const plaintext = await openMessageLayer(layer1Key, inner, messageAdditionalData(metadata, 'layer1'), 16_400);
    return new TextDecoder('utf-8', { fatal: true }).decode(plaintext);
  }
  async function generateDeviceKeyPair() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    if (pair.privateKey.extractable || publicJwk.d) throw new Error('WebCrypto returned an extractable device private key.');
    return { privateKey: pair.privateKey, publicJwk };
  }
  async function fingerprintP256(jwk) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('Unsupported public key type.');
    const x = decodeBase64Url(jwk.x), y = decodeBase64Url(jwk.y);
    if (x.length !== 32 || y.length !== 32) throw new Error('Malformed P-256 public key coordinates.');
    const prefix = encoder.encode('Serein ECDH P-256 public key v1\0');
    const material = new Uint8Array(prefix.length + x.length + y.length);
    material.set(prefix); material.set(x, prefix.length); material.set(y, prefix.length + x.length);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
    return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  async function fingerprintDeviceKeyBundle(layer1Jwk, layer2Jwk) {
    const first = await publicCoordinates(layer1Jwk), second = await publicCoordinates(layer2Jwk);
    const prefix = encoder.encode('Serein ECDH P-256 device key bundle v2\0');
    const material = new Uint8Array(prefix.length + 128);
    material.set(prefix); material.set(first.x, prefix.length); material.set(first.y, prefix.length + 32);
    material.set(second.x, prefix.length + 64); material.set(second.y, prefix.length + 96);
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', material));
    return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  async function publicCoordinates(jwk) {
    if (!jwk || jwk.kty !== 'EC' || jwk.crv !== 'P-256') throw new Error('Unsupported public key type.');
    const x = decodeBase64Url(jwk.x), y = decodeBase64Url(jwk.y);
    if (x.length !== 32 || y.length !== 32) throw new Error('Malformed P-256 public key coordinates.');
    return { x, y };
  }
  async function deriveCandidateConversationKey(privateKey, localUserId, localDeviceId, peerUserId, peerDeviceId, peerPublicJwk) {
    return deriveDevicePairKey(privateKey, localUserId, localDeviceId, peerUserId, peerDeviceId, peerPublicJwk, 'layer1');
  }
  async function deriveLayer2ConversationKey(privateKey, localUserId, localDeviceId, peerUserId, peerDeviceId, peerPublicJwk) {
    return deriveDevicePairKey(privateKey, localUserId, localDeviceId, peerUserId, peerDeviceId, peerPublicJwk, 'layer2');
  }
  async function deriveDevicePairKey(privateKey, localUserId, localDeviceId, peerUserId, peerDeviceId, peerPublicJwk, purpose) {
    const peerPublicKey = await crypto.subtle.importKey('jwk', peerPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const sharedSecret = await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, privateKey, 256);
    const material = await crypto.subtle.importKey('raw', sharedSecret, 'HKDF', false, ['deriveKey']);
    const parties = [`${localUserId}:${localDeviceId}`, `${peerUserId}:${peerDeviceId}`].sort();
    const context = purpose === 'layer2' ? `serein-e2ee-layer2-session-v1|${parties.join('|')}` : `serein-e2ee-conversation-v1|${parties.join('|')}`;
    const salt = await crypto.subtle.digest('SHA-256', encoder.encode(`${purpose === 'layer2' ? 'serein-e2ee-layer2-salt-v1' : 'serein-e2ee-salt-v1'}|${parties.join('|')}`));
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(context) },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }
  function transferMetadata(metadata) {
    const fields = ['transferId', 'senderUserId', 'senderDeviceId', 'recipientUserId', 'recipientDeviceId'];
    const values = fields.map(field => String(metadata?.[field] || ''));
    if (values.some(value => !value || value.length > 128)) throw new Error('Transfer authentication metadata is incomplete.');
    return values;
  }
  async function encryptTransferManifest(key, manifest, metadata) {
    const cleartext = encoder.encode(JSON.stringify(manifest));
    if (cleartext.length > 8_000) throw new Error('Transfer manifest exceeds its size limit.');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = encoder.encode(JSON.stringify(['serein-transfer-manifest-v1', ...transferMetadata(metadata)]));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, cleartext);
    return { version: 1, algorithm: 'AES-256-GCM', iv: encodeBase64(iv), ciphertext: encodeBase64(new Uint8Array(ciphertext)) };
  }
  async function decryptTransferManifest(key, envelope, metadata) {
    if (envelope?.version !== 1 || envelope?.algorithm !== 'AES-256-GCM') throw new Error('Unsupported encrypted-transfer manifest.');
    const iv = decodeStandardBase64(envelope.iv), ciphertext = decodeStandardBase64(envelope.ciphertext);
    if (iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > 8_016) throw new Error('Malformed encrypted-transfer manifest.');
    const aad = encoder.encode(JSON.stringify(['serein-transfer-manifest-v1', ...transferMetadata(metadata)]));
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ciphertext);
    return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext));
  }
  async function generateTransferKey() {
    const rawKey = crypto.getRandomValues(new Uint8Array(32));
    const key = await crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    return { key, rawKey };
  }
  async function importTransferKey(rawKey) {
    if (!(rawKey instanceof Uint8Array) || rawKey.length !== 32) throw new Error('Invalid transfer content key.');
    return crypto.subtle.importKey('raw', rawKey, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  }
  function transferChunkAad(metadata, index, count) {
    // Chunks are stored once per transfer and shared by every active recipient
    // device. Bind them to the recipient account (and all transfer routing), but
    // not a single recipient device; each device receives its own authenticated
    // manifest envelope containing the content key.
    if (!Number.isInteger(index) || index < 0 || !Number.isInteger(count) || count < 1 || index >= count) throw new Error('Invalid transfer chunk position.');
    return encoder.encode(JSON.stringify(['serein-transfer-chunk-v1', ...transferMetadata(metadata).slice(0, 4), index, count]));
  }
  function transferChunkIv(prefix, index) {
    if (!(prefix instanceof Uint8Array) || prefix.length !== 4 || !Number.isInteger(index) || index < 0 || index > 0xffffffff) throw new Error('Invalid transfer nonce prefix or chunk index.');
    const iv = new Uint8Array(12); iv.set(prefix, 0);
    const view = new DataView(iv.buffer); view.setUint32(8, index, false);
    return iv;
  }
  async function encryptTransferChunk(key, plaintext, metadata, index, count, iv = crypto.getRandomValues(new Uint8Array(12))) {
    if (!(iv instanceof Uint8Array) || iv.length !== 12) throw new Error('Invalid transfer chunk nonce.');
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: transferChunkAad(metadata, index, count), tagLength: 128 }, key, plaintext);
    return { iv, ciphertext: new Uint8Array(ciphertext) };
  }
  async function decryptTransferChunk(key, iv, ciphertext, metadata, index, count) {
    if (!(iv instanceof Uint8Array) || iv.length !== 12 || !(ciphertext instanceof Uint8Array) || ciphertext.length < 16) throw new Error('Malformed encrypted-transfer chunk.');
    return crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: transferChunkAad(metadata, index, count), tagLength: 128 }, key, ciphertext);
  }
  async function sha256Hex(bytes) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  window.SereinDeviceCrypto = Object.freeze({ generateDeviceKeyPair, fingerprintP256, fingerprintDeviceKeyBundle, deriveCandidateConversationKey, deriveLayer2ConversationKey, encryptMessage, decryptMessage, encryptTransferManifest, decryptTransferManifest, generateTransferKey, importTransferKey, encryptTransferChunk, decryptTransferChunk, transferChunkIv, sha256Hex, encodeBase64, encodeBase64Url, decodeStandardBase64 });
})();

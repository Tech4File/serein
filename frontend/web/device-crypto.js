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
  async function generateSigningKeyPair() {
    const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
    const publicJwk = await crypto.subtle.exportKey('jwk', pair.publicKey);
    if (pair.privateKey.extractable || publicJwk.d) throw new Error('WebCrypto returned an extractable device signing key.');
    return { privateKey: pair.privateKey, publicJwk: { kty:'EC', crv:'P-256', x:publicJwk.x, y:publicJwk.y } };
  }
  function rotationStatement(userId, deviceId, oldFingerprint, newFingerprint, timestamp, epoch) {
    if (!Number.isSafeInteger(timestamp) || timestamp < 1 || !Number.isSafeInteger(epoch) || epoch < 1 || !/^[0-9a-f-]{36}$/i.test(userId) || !/^[0-9a-f-]{36}$/i.test(deviceId) || !/^[0-9a-f]{64}$/.test(newFingerprint) || (oldFingerprint && !/^[0-9a-f]{64}$/.test(oldFingerprint))) throw new Error('Invalid key-continuity statement fields.');
    return encoder.encode(`SEREIN-DEVICE-KEY-ROTATION-V1\n${userId.toLowerCase()}\n${deviceId.toLowerCase()}\n${oldFingerprint}\n${newFingerprint}\n${timestamp}\n${epoch}\n`);
  }
  function derEncodeP256Signature(raw) {
    if (!(raw instanceof Uint8Array) || raw.length !== 64) throw new Error('Malformed ECDSA signature.');
    const integer = bytes => { let start=0;while(start<bytes.length-1&&bytes[start]===0)start++;let body=bytes.slice(start);if(body[0]&0x80)body=Uint8Array.from([0,...body]);return Uint8Array.from([2,body.length,...body]); };
    const r=integer(raw.slice(0,32)),s=integer(raw.slice(32)),body=Uint8Array.from([...r,...s]);return Uint8Array.from([0x30,body.length,...body]);
  }
  function derDecodeP256Signature(der) {
    if (!(der instanceof Uint8Array) || der.length<8 || der.length>72 || der[0]!==0x30 || der[1]!==der.length-2 || der[2]!==2) throw new Error('Malformed ECDSA continuity proof.');
    let at=3, lenR=der[at++];if(!lenR||at+lenR+2>der.length)throw new Error('Malformed ECDSA continuity proof.');let r=der.slice(at,at+lenR);at+=lenR;if(der[at++]!==2)throw new Error('Malformed ECDSA continuity proof.');let lenS=der[at++];if(!lenS||at+lenS!==der.length)throw new Error('Malformed ECDSA continuity proof.');let s=der.slice(at);
    if(r.length>33||s.length>33||(r[0]===0&&r.length>1&&(r[1]&0x80)===0)||(s[0]===0&&s.length>1&&(s[1]&0x80)===0)||(r[0]&0x80)||(s[0]&0x80))throw new Error('Non-canonical ECDSA continuity proof.');
    if(r[0]===0)r=r.slice(1);if(s[0]===0)s=s.slice(1);if(r.length>32||s.length>32)throw new Error('Malformed ECDSA continuity proof.');const raw=new Uint8Array(64);raw.set(r,32-r.length);raw.set(s,64-s.length);return raw;
  }
  async function signDeviceKeyRotation(privateKey, userId, deviceId, oldFingerprint, newFingerprint, timestamp, epoch) {
    const raw=new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},privateKey,rotationStatement(userId,deviceId,oldFingerprint,newFingerprint,timestamp,epoch)));
    try{return encodeBase64Url(derEncodeP256Signature(raw));}finally{raw.fill(0);}
  }
  async function verifyDeviceKeyRotation(publicJwk, userId, deviceId, oldFingerprint, newFingerprint, timestamp, epoch, proof) {
    try{const key=await crypto.subtle.importKey('jwk',publicJwk,{name:'ECDSA',namedCurve:'P-256'},false,['verify']);const der=decodeBase64Url(proof),raw=derDecodeP256Signature(der);try{return await crypto.subtle.verify({name:'ECDSA',hash:'SHA-256'},key,raw,rotationStatement(userId,deviceId,oldFingerprint,newFingerprint,timestamp,epoch));}finally{raw.fill(0);der.fill(0);}}catch{return false;}
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
  async function deriveRatchetBootstrapSecret(privateKey, localUserId, localDeviceId, peerUserId, peerDeviceId, peerPublicJwk, purpose) {
    if (!['layer1', 'layer2'].includes(purpose)) throw new Error('Unknown ratchet bootstrap purpose.');
    const peerPublicKey = await crypto.subtle.importKey('jwk', peerPublicJwk, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const raw = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: peerPublicKey }, privateKey, 256));
    const parties = [`${localUserId}:${localDeviceId}`, `${peerUserId}:${peerDeviceId}`].sort();
    const context = `Serein/${purpose}/symmetric-ratchet-bootstrap/v1|${parties.join('|')}`;
    const salt = new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(`Serein/${purpose}/symmetric-ratchet-salt/v1|${parties.join('|')}`)));
    let material;
    try {
      material = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveBits']);
      return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info: encoder.encode(context) }, material, 256));
    } finally { raw.fill(0); salt.fill(0); }
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
    try {
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, cleartext);
      return { version: 1, algorithm: 'AES-256-GCM', iv: encodeBase64(iv), ciphertext: encodeBase64(new Uint8Array(ciphertext)) };
    } finally { cleartext.fill(0); }
  }
  async function decryptTransferManifest(key, envelope, metadata) {
    if (envelope?.version !== 1 || envelope?.algorithm !== 'AES-256-GCM') throw new Error('Unsupported encrypted-transfer manifest.');
    const iv = decodeStandardBase64(envelope.iv), ciphertext = decodeStandardBase64(envelope.ciphertext);
    if (iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > 8_016) throw new Error('Malformed encrypted-transfer manifest.');
    const aad = encoder.encode(JSON.stringify(['serein-transfer-manifest-v1', ...transferMetadata(metadata)]));
    const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ciphertext));
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)); }
    finally { plaintext.fill(0); }
  }
  async function encryptTransferManifestLayer2(key, innerEnvelope, metadata) {
    const cleartext = encoder.encode(JSON.stringify(innerEnvelope));
    if (cleartext.length > 12_000) throw new Error('Nested transfer manifest exceeds its size limit.');
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const aad = encoder.encode(JSON.stringify(['serein-transfer-manifest-layer2-v1', ...transferMetadata(metadata)]));
    try {
      const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, cleartext);
      return { version: 2, algorithm: 'AES-256-GCM-LAYER2', iv: encodeBase64(iv), ciphertext: encodeBase64(new Uint8Array(ciphertext)) };
    } finally { cleartext.fill(0); }
  }
  async function decryptTransferManifestLayer2(key, envelope, metadata) {
    if (envelope?.version !== 2 || envelope?.algorithm !== 'AES-256-GCM-LAYER2') throw new Error('Unsupported Layer 2 transfer manifest.');
    const iv = decodeStandardBase64(envelope.iv), ciphertext = decodeStandardBase64(envelope.ciphertext);
    if (iv.length !== 12 || ciphertext.length < 16 || ciphertext.length > 12_016) throw new Error('Malformed Layer 2 transfer manifest.');
    const aad = encoder.encode(JSON.stringify(['serein-transfer-manifest-layer2-v1', ...transferMetadata(metadata)]));
    const plaintext = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, key, ciphertext));
    try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)); }
    finally { plaintext.fill(0); }
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
  function transferChunkLayerAad(metadata,index,count,layer){
    if(!Number.isInteger(index)||index<0||!Number.isInteger(count)||count<1||index>=count)throw new Error('Invalid transfer chunk position.');
    return encoder.encode(JSON.stringify([`serein-transfer-chunk-${layer}-v2`,...transferMetadata(metadata).slice(0,4),index,count]));
  }
  async function encryptTransferChunkLayer2(layer1Key,layer2Key,plaintext,metadata,index,count,iv1,iv2){
    if(!(iv1 instanceof Uint8Array)||iv1.length!==12||!(iv2 instanceof Uint8Array)||iv2.length!==12)throw new Error('Invalid two-layer transfer chunk nonce.');
    const inner=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv1,additionalData:transferChunkLayerAad(metadata,index,count,'layer1'),tagLength:128},layer1Key,plaintext));
    try{const outer=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv:iv2,additionalData:transferChunkLayerAad(metadata,index,count,'layer2'),tagLength:128},layer2Key,inner));return{iv1,iv2,ciphertext:outer};}
    finally{inner.fill(0);}
  }
  async function decryptTransferChunkLayer2(layer1Key,layer2Key,iv1,iv2,ciphertext,metadata,index,count){
    if(!(iv1 instanceof Uint8Array)||iv1.length!==12||!(iv2 instanceof Uint8Array)||iv2.length!==12||!(ciphertext instanceof Uint8Array)||ciphertext.length<32)throw new Error('Malformed two-layer encrypted-transfer chunk.');
    const inner=new Uint8Array(await crypto.subtle.decrypt({name:'AES-GCM',iv:iv2,additionalData:transferChunkLayerAad(metadata,index,count,'layer2'),tagLength:128},layer2Key,ciphertext));
    try{return await crypto.subtle.decrypt({name:'AES-GCM',iv:iv1,additionalData:transferChunkLayerAad(metadata,index,count,'layer1'),tagLength:128},layer1Key,inner);}
    finally{inner.fill(0);}
  }
  function historySyncAad(accountId,mainDeviceId,childDeviceId,requestId,index,count){const uuid=/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;if(![accountId,mainDeviceId,childDeviceId,requestId].every(value=>typeof value==='string'&&uuid.test(value))||!Number.isInteger(index)||index<0||!Number.isInteger(count)||count<1||index>=count||count>128)throw new Error('Invalid history-sync batch context.');/* Protocol: compact UTF-8 JSON array; fixed ASCII UUIDs and base-10 integers; field order is normative. */return encoder.encode(JSON.stringify(['serein-history-sync-batch-v1',accountId.toLowerCase(),mainDeviceId.toLowerCase(),childDeviceId.toLowerCase(),requestId.toLowerCase(),index,count,1]));}
  async function deriveHistorySyncKey(privateKey,accountId,localDeviceId,peerDeviceId,peerPublicJwk,mainDeviceId,childDeviceId,requestId,index,count){if(![mainDeviceId,childDeviceId].includes(localDeviceId)||![mainDeviceId,childDeviceId].includes(peerDeviceId)||localDeviceId===peerDeviceId)throw new Error('History-sync device roles do not match.');const peer=await crypto.subtle.importKey('jwk',peerPublicJwk,{name:'ECDH',namedCurve:'P-256'},false,[]),raw=new Uint8Array(await crypto.subtle.deriveBits({name:'ECDH',public:peer},privateKey,256));const parties=[mainDeviceId.toLowerCase(),childDeviceId.toLowerCase()].sort(),scope=`${accountId.toLowerCase()}|${parties.join('|')}`,salt=new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(`serein-history-sync-salt-v1|${scope}`))),info=encoder.encode(`serein-history-sync-key-v1|${scope}|${requestId.toLowerCase()}|${index}|${count}`);try{const material=await crypto.subtle.importKey('raw',raw,'HKDF',false,['deriveKey']);return await crypto.subtle.deriveKey({name:'HKDF',hash:'SHA-256',salt,info},material,{name:'AES-GCM',length:256},false,['encrypt','decrypt']);}finally{raw.fill(0);salt.fill(0);}}
  async function encryptHistorySyncBatch(key,plaintext,accountId,mainDeviceId,childDeviceId,requestId,index,count){const clear=typeof plaintext==='string'?encoder.encode(plaintext):new Uint8Array(plaintext);if(clear.length>480*1024)throw new Error('History-sync clear batch exceeds its safety limit.');const iv=crypto.getRandomValues(new Uint8Array(12));const ciphertext=new Uint8Array(await crypto.subtle.encrypt({name:'AES-GCM',iv,additionalData:historySyncAad(accountId,mainDeviceId,childDeviceId,requestId,index,count),tagLength:128},key,clear));return{version:1,algorithm:'AES-256-GCM',iv:encodeBase64Url(iv),ciphertext:encodeBase64Url(ciphertext)};}
  async function decryptHistorySyncBatch(key,envelope,accountId,mainDeviceId,childDeviceId,requestId,index,count){if(envelope?.version!==1||envelope?.algorithm!=='AES-256-GCM')throw new Error('Unsupported history-sync envelope.');const iv=decodeBase64Url(envelope.iv),ciphertext=decodeBase64Url(envelope.ciphertext);if(iv.length!==12||ciphertext.length<16||ciphertext.length>512*1024)throw new Error('Malformed history-sync ciphertext.');return crypto.subtle.decrypt({name:'AES-GCM',iv,additionalData:historySyncAad(accountId,mainDeviceId,childDeviceId,requestId,index,count),tagLength:128},key,ciphertext);}
  async function sha256Hex(bytes) {
    const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
    return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  window.SereinDeviceCrypto = Object.freeze({ generateDeviceKeyPair, generateSigningKeyPair, signDeviceKeyRotation, verifyDeviceKeyRotation, fingerprintP256, fingerprintDeviceKeyBundle, deriveCandidateConversationKey, deriveLayer2ConversationKey, deriveRatchetBootstrapSecret, encryptMessage, decryptMessage, encryptTransferManifest, decryptTransferManifest, encryptTransferManifestLayer2, decryptTransferManifestLayer2, generateTransferKey, importTransferKey, encryptTransferChunk, decryptTransferChunk, encryptTransferChunkLayer2, decryptTransferChunkLayer2, transferChunkIv, deriveHistorySyncKey, encryptHistorySyncBatch, decryptHistorySyncBatch, historySyncAadBytes: historySyncAad, sha256Hex, encodeBase64, encodeBase64Url, decodeStandardBase64 });
})();

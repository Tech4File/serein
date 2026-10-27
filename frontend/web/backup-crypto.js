/* Serein portable encrypted-backup container v3.
 * New exports use a random, stable backup-only key delivered as an app-layer-wrapped
 * envelope by the authenticated service. The key exists only in memory during the
 * backup operation. v1 password and v2 account-ID-derived files remain restorable.
 */
(() => {
  'use strict';
  const encoder = new TextEncoder();
  const decoder = new TextDecoder('utf-8', { fatal: true });
  const MAGIC = encoder.encode('SEREINBK');
  const FORMAT = 'SEREIN-BACKUP';
  const VERSION = 3;
  const PREVIOUS_VERSION = 2;
  const LEGACY_VERSION = 1;
  const KDF = 'HKDF-SHA256-SERVER-BACKUP-KEY';
  const LEGACY_KDF = 'PBKDF2-HMAC-SHA256';
  const LEGACY_ITERATIONS = 600_000;
  const KEY_DERIVATION_VERSION = 1;
  const MAX_HEADER_BYTES = 16 * 1024;
  const MAX_FILE_BYTES = 512 * 1024 * 1024;
  const MAX_CLEAR_BYTES = 512 * 1024 * 1024;
  const MIN_IDENTITY_CHARS = 1;
  const MAX_IDENTITY_CHARS = 128;
  const text = value => encoder.encode(value);

  function b64url(bytes) {
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
  }
  function unb64url(value, expectedLength, label) {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw new Error(`Malformed backup ${label}.`);
    const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
    const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
    if (expectedLength !== undefined && bytes.length !== expectedLength) throw new Error(`Malformed backup ${label}.`);
    return bytes;
  }
  function identityContext(identity) {
    // Product policy currently provides no username-change flow. Keep the stable account ID
    // in authenticated context too; neither ID nor username is a password/key or entropy.
    const accountId = String(identity?.accountId || '').trim().toLowerCase();
    const username = String(identity?.username || '').trim().toLowerCase();
    if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(accountId)) throw new Error('Backup account identity is incomplete.');
    if (username.length > MAX_IDENTITY_CHARS || /[\u0000-\u001f\u007f]/.test(username)) throw new Error('Backup account identity is incomplete.');
    return { accountId, username };
  }
  function canonicalWrapAad(identity, header) {
    return text(JSON.stringify([
      'serein-backup-key-wrap-v1', FORMAT, header.version, identity.accountId, identity.username,
      header.snapshot_id, header.kdf, header.iterations, header.salt,
    ]));
  }
  function canonicalPayloadAad(identity, header) {
    return text(JSON.stringify([
      'serein-backup-payload-v1', FORMAT, header.version, identity.accountId, identity.username,
      header.snapshot_id, header.created_at, header.compression, header.kdf,
      header.iterations, header.salt, header.key_wrap_iv, header.wrapped_key, header.payload_iv,
    ]));
  }
  async function derivePasswordKey(password, salt) {
    if (typeof password !== 'string' || password.length < 1 || encoder.encode(password).length > 1024) {
      throw new Error('Enter the legacy backup password.');
    }
    const passwordBytes = text(password);
    let material;
    try { material = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveKey']); }
    finally { passwordBytes.fill(0); }
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: LEGACY_ITERATIONS },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }
  async function readBounded(stream, maximum) {
    const reader = stream.getReader(), parts = [];
    let total = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        total += value.byteLength;
        if (total > maximum) { await reader.cancel(); throw new Error('Transformed backup exceeds its safe size limit.'); }
        parts.push(value);
      }
    } finally { reader.releaseLock(); }
    const result = new Uint8Array(total);
    let offset = 0;
    for (const part of parts) { result.set(part, offset); offset += part.byteLength; }
    return result;
  }
  async function transform(bytes, mode) {
    const Stream = mode === 'compress' ? globalThis.CompressionStream : globalThis.DecompressionStream;
    if (typeof Stream !== 'function') {
      throw new Error(mode === 'compress'
        ? 'This browser cannot create a compressed backup. Update the browser and try again.'
        : 'This browser cannot decompress this backup format.');
    }
    const format = new Stream('deflate');
    const stream = new Blob([bytes]).stream().pipeThrough(format);
    const result = await readBounded(stream, MAX_CLEAR_BYTES);
    return mode === 'compress' ? { bytes: result, compression: 'deflate' } : result;
  }
  function pack(headerBytes, ciphertext) {
    if (headerBytes.length < 2 || headerBytes.length > MAX_HEADER_BYTES) throw new Error('Backup header exceeds its safe size limit.');
    const size = MAGIC.length + 4 + headerBytes.length + ciphertext.length;
    if (size > MAX_FILE_BYTES) throw new Error('Encrypted backup exceeds the 512 MiB file limit.');
    const packed = new Uint8Array(size);
    packed.set(MAGIC, 0);
    new DataView(packed.buffer).setUint32(MAGIC.length, headerBytes.length, false);
    packed.set(headerBytes, MAGIC.length + 4);
    packed.set(ciphertext, MAGIC.length + 4 + headerBytes.length);
    return packed;
  }
  function unpack(fileBytes) {
    const bytes = fileBytes instanceof Uint8Array ? fileBytes : new Uint8Array(fileBytes);
    if (bytes.length < MAGIC.length + 4 + 2 + 16 || bytes.length > MAX_FILE_BYTES) throw new Error('Backup file is malformed or exceeds its safe size limit.');
    for (let i = 0; i < MAGIC.length; i++) if (bytes[i] !== MAGIC[i]) throw new Error('This is not a Serein encrypted backup file.');
    const headerLength = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(MAGIC.length, false);
    const start = MAGIC.length + 4, end = start + headerLength;
    if (headerLength < 2 || headerLength > MAX_HEADER_BYTES || end >= bytes.length || bytes.length - end < 16) throw new Error('Backup header is malformed.');
    let header;
    try { header = JSON.parse(decoder.decode(bytes.subarray(start, end))); }
    catch { throw new Error('Backup header is malformed.'); }
    const legacyFields = ['format','version','kdf','iterations','salt','snapshot_id','created_at','compression','key_wrap_iv','wrapped_key','payload_iv'];
    const v2Fields = ['format','version','kdf','key_derivation_version','snapshot_id','created_at','compression','payload_iv'];
    const currentFields = ['format','version','kdf','key_derivation_version','snapshot_id','created_at','compression','salt','payload_iv'];
    const fields = header?.version === LEGACY_VERSION ? legacyFields : header?.version === PREVIOUS_VERSION ? v2Fields : currentFields;
    if (!header || typeof header !== 'object' || Array.isArray(header) || Object.keys(header).some(key => !fields.includes(key)) || fields.some(key => !Object.hasOwn(header, key))) throw new Error('Backup header fields are unsupported.');
    if (header.format !== FORMAT || !['deflate','none'].includes(header.compression)) throw new Error('Unsupported or unsafe backup format parameters.');
    if (header.version === LEGACY_VERSION) {
      if (header.kdf !== LEGACY_KDF || header.iterations !== LEGACY_ITERATIONS) throw new Error('Unsupported or unsafe backup format parameters.');
      unb64url(header.salt, 16, 'salt');
      unb64url(header.key_wrap_iv, 12, 'key wrapper nonce');
      unb64url(header.wrapped_key, 48, 'wrapped data key');
    } else if (header.version === PREVIOUS_VERSION) {
      if (header.kdf !== 'HKDF-SHA256-ACCOUNT-UUID' || header.key_derivation_version !== KEY_DERIVATION_VERSION) throw new Error('Unsupported or unsafe backup format parameters.');
    } else if (header.version === VERSION) {
      if (header.kdf !== KDF || header.key_derivation_version !== KEY_DERIVATION_VERSION) throw new Error('Unsupported or unsafe backup format parameters.');
      unb64url(header.salt, 16, 'salt');
    } else throw new Error('Unsupported or unsafe backup format parameters.');
    if (typeof header.snapshot_id !== 'string' || !/^[0-9a-f-]{36}$/i.test(header.snapshot_id) || typeof header.created_at !== 'string' || !Number.isFinite(Date.parse(header.created_at))) throw new Error('Backup metadata is malformed.');
    unb64url(header.payload_iv, 12, 'payload nonce');
    return { header, ciphertext: bytes.slice(end) };
  }
  async function decryptLegacyV1(password, identityInput, fileBytes) {
    const identity = identityContext(identityInput);
    const { header, ciphertext } = unpack(fileBytes);
    const salt = unb64url(header.salt, 16, 'salt');
    const wrapIv = unb64url(header.key_wrap_iv, 12, 'key wrapper nonce');
    const wrappedKey = unb64url(header.wrapped_key, 48, 'wrapped data key');
    const payloadIv = unb64url(header.payload_iv, 12, 'payload nonce');
    let dataKeyBytes;
    let clear;
    try {
      const passwordKey = await derivePasswordKey(password, salt);
      dataKeyBytes = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: wrapIv, additionalData: canonicalWrapAad(identity, header), tagLength: 128 },
        passwordKey,
        wrappedKey,
      ));
      if (dataKeyBytes.length !== 32) throw new Error('Backup key is malformed.');
      const dataKey = await crypto.subtle.importKey('raw', dataKeyBytes, { name: 'AES-GCM' }, false, ['decrypt']);
      clear = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv: payloadIv, additionalData: canonicalPayloadAad(identity, header), tagLength: 128 },
        dataKey,
        ciphertext,
      ));
      if (clear.length > MAX_CLEAR_BYTES) throw new Error('Decompressed backup exceeds its safe size limit.');
      if (header.compression === 'deflate') {
        const compressed = clear;
        try { clear = await transform(compressed, 'decompress'); }
        finally { compressed.fill(0); }
      }
      if (clear.length > MAX_CLEAR_BYTES) throw new Error('Decompressed backup exceeds its safe size limit.');
      const payload = JSON.parse(decoder.decode(clear));
      if (payload?.format !== FORMAT || payload.version !== LEGACY_VERSION || payload.snapshot_id !== header.snapshot_id || payload.created_at !== header.created_at || payload.owner?.accountId !== identity.accountId || payload.owner?.username !== identity.username || !payload.data || typeof payload.data !== 'object' || Array.isArray(payload.data)) throw new Error('Backup does not belong to this signed-in account or its contents are incomplete.');
      return { snapshotId: header.snapshot_id, createdAt: header.created_at, data: payload.data };
    } catch {
      throw new Error('Backup could not be opened. Check the signed-in account and password, and ensure the backup file is intact.');
    } finally {
      dataKeyBytes?.fill(0);
      clear?.fill(0);
    }
  }
  async function deriveAccountKey(accountId) {
    const idBytes = text(accountId);
    let material;
    try { material = await crypto.subtle.importKey('raw', idBytes, 'HKDF', false, ['deriveKey']); }
    finally { idBytes.fill(0); }
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: text('Serein backup account key v2'), info: text(`Serein backup stable key v${KEY_DERIVATION_VERSION}`) },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }
  async function deriveServerBackupKey(backupKeyBytes, accountId, salt) {
    if (!(backupKeyBytes instanceof Uint8Array) || backupKeyBytes.byteLength !== 32) throw new Error('The server backup key is unavailable or malformed.');
    const material = await crypto.subtle.importKey('raw', backupKeyBytes, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt, info: text(`Serein backup payload v3|${accountId}`) },
      material,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  }
  function canonicalPayloadAadV3(identity, header) {
    return text(JSON.stringify([
      'serein-backup-payload-v3', FORMAT, VERSION, identity.accountId,
      header.snapshot_id, header.created_at, header.compression, header.kdf,
      header.key_derivation_version, header.salt, header.payload_iv,
    ]));
  }
  function canonicalPayloadAadV2(identity, header) {
    return text(JSON.stringify([
      'serein-backup-payload-v2', FORMAT, PREVIOUS_VERSION, identity.accountId,
      header.snapshot_id, header.created_at, header.compression,
      header.kdf, header.key_derivation_version, header.payload_iv,
    ]));
  }
  async function encrypt(identityInput, snapshot, backupKeyBytes, options = {}) {
    const identity = identityContext(identityInput);
    if (!(backupKeyBytes instanceof Uint8Array) || backupKeyBytes.byteLength !== 32) throw new Error('The server backup key is unavailable or malformed.');
    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) throw new Error('Backup snapshot must be an object.');
    const snapshotId = options.snapshotId || crypto.randomUUID();
    if (!/^[0-9a-f-]{36}$/i.test(snapshotId)) throw new Error('Backup snapshot ID is malformed.');
    const createdAt = options.createdAt || new Date().toISOString();
    if (!Number.isFinite(Date.parse(createdAt))) throw new Error('Backup creation time is malformed.');
    const payloadIv = crypto.getRandomValues(new Uint8Array(12));
    let clearBytes, compressedBytes;
    try {
      const payload = text(JSON.stringify({
        format: FORMAT,
        version: VERSION,
        owner: { accountId: identity.accountId, username: identity.username },
        created_at: createdAt,
        snapshot_id: snapshotId,
        data: snapshot,
      }));
      if (payload.length > MAX_CLEAR_BYTES) throw new Error('Backup snapshot exceeds its safe size limit.');
      clearBytes = payload;
      const compressed = await transform(payload, 'compress');
      compressedBytes = compressed.bytes;
      if (compressedBytes.length > MAX_CLEAR_BYTES) throw new Error('Compressed backup exceeds its safe size limit.');
      const header = {
        format: FORMAT,
        version: VERSION,
        kdf: KDF,
        key_derivation_version: KEY_DERIVATION_VERSION,
        salt: b64url(crypto.getRandomValues(new Uint8Array(16))),
        snapshot_id: snapshotId,
        created_at: createdAt,
        compression: compressed.compression,
        payload_iv: b64url(payloadIv),
      };
      const key = await deriveServerBackupKey(backupKeyBytes, identity.accountId, unb64url(header.salt, 16, 'salt'));
      const ciphertext = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: payloadIv, additionalData: canonicalPayloadAadV3(identity, header), tagLength: 128 },
        key,
        compressedBytes,
      );
      const packed = pack(text(JSON.stringify(header)), new Uint8Array(ciphertext));
      return { bytes: packed, filename: `serein-backup-${createdAt.replace(/[:.]/g, '-').replace(/[^0-9TZ-]/g, '')}-${snapshotId.slice(0,8)}.srbk`, header };
    } finally {
      clearBytes?.fill(0);
      compressedBytes?.fill(0);
    }
  }
  async function decrypt(identityInput, fileBytes, legacyPassword = '', backupKeyBytes = null) {
    const identity = identityContext(identityInput);
    const { header, ciphertext } = unpack(fileBytes);
    if (header.version === LEGACY_VERSION) return decryptLegacyV1(legacyPassword, identity, fileBytes);
    const iv = unb64url(header.payload_iv, 12, 'payload nonce');
    let clear;
    try {
      let key, aad;
      if (header.version === PREVIOUS_VERSION) {
        key = await deriveAccountKey(identity.accountId);
        aad = canonicalPayloadAadV2(identity, header);
      } else {
        key = await deriveServerBackupKey(backupKeyBytes, identity.accountId, unb64url(header.salt, 16, 'salt'));
        aad = canonicalPayloadAadV3(identity, header);
      }
      clear = new Uint8Array(await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 },
        key,
        ciphertext,
      ));
      if (clear.length > MAX_CLEAR_BYTES) throw new Error('Decompressed backup exceeds its safe size limit.');
      if (header.compression === 'deflate') {
        const compressed = clear;
        try { clear = await transform(compressed, 'decompress'); }
        finally { compressed.fill(0); }
      }
      if (clear.length > MAX_CLEAR_BYTES) throw new Error('Decompressed backup exceeds its safe size limit.');
      const payload = JSON.parse(decoder.decode(clear));
      if (payload?.format !== FORMAT || payload.version !== header.version || payload.snapshot_id !== header.snapshot_id || payload.created_at !== header.created_at || payload.owner?.accountId !== identity.accountId || !payload.data || typeof payload.data !== 'object' || Array.isArray(payload.data)) throw new Error('Backup account binding or contents are invalid.');
      return { snapshotId: header.snapshot_id, createdAt: header.created_at, data: payload.data };
    } catch {
      throw new Error('Backup could not be opened for this signed-in account, or the file is damaged.');
    } finally { clear?.fill(0); }
  }
  function inspect(fileBytes) {
    const { header } = unpack(fileBytes);
    return { version: header.version, createdAt: header.created_at, snapshotId: header.snapshot_id, compression: header.compression };
  }
  const api = Object.freeze({ encrypt, decrypt, inspect, iterations: LEGACY_ITERATIONS, format: FORMAT, version: VERSION, legacyVersion: LEGACY_VERSION });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof window !== 'undefined') window.SereinBackupCrypto = api;
})();

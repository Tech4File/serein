/* First-party Rust/WASM bridge. Ratchet operations fail closed when the shared core is unavailable. */
(() => {
  'use strict';
  const encoder = new TextEncoder();
  const MAX_RATCHET_PLAINTEXT_BYTES = 32768;
  const MAX_RATCHET_AAD_BYTES = 4096;
  const fallbackUsername = value => /^[a-z0-9_.-]{3,32}$/.test(String(value || ''));
  let exports = null;

  function callString(name, value) {
    if (!exports) return fallbackUsername(value);
    const bytes = encoder.encode(String(value || ''));
    const ptr = exports.serein_core_alloc(bytes.length);
    if (!ptr) return false;
    try {
      new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
      return exports[name](ptr, bytes.length) === 1;
    } finally { exports.serein_core_dealloc(ptr, bytes.length); }
  }

  const ready = (async () => {
    try {
      const script = document.currentScript;
      const wasmUrl = new URL('serein_core.wasm', script ? script.src : location.href);
      const response = await fetch(wasmUrl, { credentials: 'same-origin', cache: 'no-cache' });
      if (!response.ok) return false;
      const bytes = await response.arrayBuffer();
      const result = await WebAssembly.instantiate(bytes, {});
      exports = result.instance.exports;
      const required = [
        'memory', 'serein_core_validate_username', 'serein_core_registration_password_requirements',
        'serein_core_max_message_characters', 'serein_core_message_warning_characters',
        'serein_core_message_character_count', 'serein_core_alloc', 'serein_core_dealloc',
        'serein_core_ratchet_derive_chains', 'serein_core_ratchet_root_step', 'serein_core_ratchet_new',
        'serein_core_ratchet_restore', 'serein_core_ratchet_free', 'serein_core_ratchet_snapshot_len',
        'serein_core_ratchet_snapshot', 'serein_core_ratchet_encrypt', 'serein_core_ratchet_decrypt',
        'serein_core_double_ratchet_public_from_private', 'serein_core_double_ratchet_new_initiator',
        'serein_core_double_ratchet_new_responder', 'serein_core_double_ratchet_free',
        'serein_core_double_ratchet_snapshot_len', 'serein_core_double_ratchet_snapshot',
        'serein_core_double_ratchet_restore', 'serein_core_double_ratchet_encrypt',
        'serein_core_double_ratchet_decrypt',
      ];
      if (required.some(name => !exports[name])) { exports = null; return false; }
      return true;
    } catch (error) {
      console.info('Rust/WASM core not present; local development validation fallback active.', error);
      return false;
    }
  })();

  function requireWasmRatchet() {
    if (!exports) throw new Error('The shared ratchet core is unavailable; encrypted sending is disabled.');
  }
  function alloc(length) {
    if (!length) return 0;
    const ptr = exports.serein_core_alloc(length) >>> 0;
    if (!ptr) throw new Error('Shared crypto memory allocation failed.');
    return ptr;
  }
  function release(ptr, length) { if (ptr && length) exports.serein_core_dealloc(ptr, length); }
  function wipe(ptr, length) { if (ptr && length) new Uint8Array(exports.memory.buffer, ptr, length).fill(0); }
  function write(ptr, bytes) { if (bytes.length) new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes); }
  function copy(ptr, length) { return new Uint8Array(exports.memory.buffer, ptr, length).slice(); }
  function bytes(value, name, expectedLength) {
    if (!(value instanceof Uint8Array)) throw new TypeError(`${name} must be a Uint8Array.`);
    if (expectedLength !== undefined && value.length !== expectedLength) throw new RangeError(`${name} must be ${expectedLength} bytes.`);
    return value;
  }
  function ffiError(code) {
    const messages = {
      '-2': 'Ratchet state or cryptographic input was invalid.', '-3': 'Ratchet header or message size was invalid.',
      '-4': 'Ratchet session, direction, replay, or message ordering was invalid.',
      '-5': 'Message authentication failed.', '-6': 'Ratchet counter or KDF failed.',
      '-7': 'Message gap exceeded the skipped-key limit.',
    };
    return new Error(messages[String(code)] || `Ratchet core failed (${code}).`);
  }
  function checkedLength(value, label) {
    if (value < 0) throw ffiError(value);
    return value;
  }

  function wrapRatchet(rawHandle) {
    let handle = rawHandle >>> 0;
    function open() { if (!handle) throw new Error('Ratchet handle is closed.'); requireWasmRatchet(); }
    return Object.freeze({
      encrypt(nonceValue, plaintextValue, aadValue = new Uint8Array()) {
        open();
        const nonce = bytes(nonceValue, 'nonce', 12);
        const plaintext = bytes(plaintextValue, 'plaintext');
        const aad = bytes(aadValue, 'AAD');
        if (plaintext.length > MAX_RATCHET_PLAINTEXT_BYTES || aad.length > MAX_RATCHET_AAD_BYTES) throw new RangeError('Ratchet plaintext or AAD exceeds the shared-core limit.');
        const headerCapacity = 22, ciphertextCapacity = plaintext.length + 16;
        const noncePtr = alloc(nonce.length), plainPtr = alloc(plaintext.length), aadPtr = alloc(aad.length);
        const headerPtr = alloc(headerCapacity), cipherPtr = alloc(ciphertextCapacity);
        try {
          write(noncePtr, nonce); write(plainPtr, plaintext); write(aadPtr, aad);
          const written = exports.serein_core_ratchet_encrypt(handle, noncePtr, plainPtr, plaintext.length, aadPtr, aad.length,
            headerPtr, headerCapacity, cipherPtr, ciphertextCapacity);
          const ciphertextLength = checkedLength(written, 'encrypt');
          return { header: copy(headerPtr, headerCapacity), ciphertext: copy(cipherPtr, ciphertextLength), nonce: nonce.slice() };
        } finally {
          wipe(plainPtr, plaintext.length); wipe(aadPtr, aad.length);
          release(noncePtr, nonce.length); release(plainPtr, plaintext.length); release(aadPtr, aad.length);
          release(headerPtr, headerCapacity); release(cipherPtr, ciphertextCapacity);
        }
      },
      decrypt(headerValue, nonceValue, ciphertextValue, aadValue = new Uint8Array()) {
        open();
        const header = bytes(headerValue, 'header', 22), nonce = bytes(nonceValue, 'nonce', 12);
        const ciphertext = bytes(ciphertextValue, 'ciphertext'), aad = bytes(aadValue, 'AAD');
        if (ciphertext.length < 16 || ciphertext.length > MAX_RATCHET_PLAINTEXT_BYTES + 16 || aad.length > MAX_RATCHET_AAD_BYTES) throw new RangeError('Ciphertext or AAD exceeds the shared-core limit.');
        const plaintextCapacity = ciphertext.length - 16, outputCapacity = Math.max(1, plaintextCapacity);
        const headerPtr = alloc(header.length), noncePtr = alloc(nonce.length), cipherPtr = alloc(ciphertext.length);
        const aadPtr = alloc(aad.length), plainPtr = alloc(outputCapacity);
        try {
          write(headerPtr, header); write(noncePtr, nonce); write(cipherPtr, ciphertext); write(aadPtr, aad);
          const written = exports.serein_core_ratchet_decrypt(handle, headerPtr, noncePtr, cipherPtr, ciphertext.length,
            aadPtr, aad.length, plainPtr, plaintextCapacity);
          const plaintextLength = checkedLength(written, 'decrypt');
          return copy(plainPtr, plaintextLength);
        } finally {
          wipe(aadPtr, aad.length); wipe(plainPtr, outputCapacity);
          release(headerPtr, header.length); release(noncePtr, nonce.length); release(cipherPtr, ciphertext.length);
          release(aadPtr, aad.length); release(plainPtr, outputCapacity);
        }
      },
      snapshot() {
        // Raw ratchet secret state: encrypt/authenticate with the existing local store before persistence.
        open();
        const length = exports.serein_core_ratchet_snapshot_len(handle) >>> 0;
        if (length < 96 || length > 96 + 2000 * 36) throw new Error('Ratchet core returned an invalid snapshot size.');
        const ptr = alloc(length);
        try {
          const written = exports.serein_core_ratchet_snapshot(handle, ptr, length);
          if (written !== length) throw ffiError(written);
          return copy(ptr, length);
        } finally { wipe(ptr, length); release(ptr, length); }
      },
      close() {
        if (handle) { exports.serein_core_ratchet_free(handle); handle = 0; }
      },
    });
  }

  function wrapDoubleRatchet(rawHandle) {
    let handle = rawHandle >>> 0;
    function open() {
      if (!handle) throw new Error('Double Ratchet handle is closed.');
      requireWasmRatchet();
    }
    return Object.freeze({
      encrypt(nonceValue, plaintextValue, aadValue = new Uint8Array(), newLocalDhPrivateValue = null) {
        open();
        const nonce = bytes(nonceValue, 'nonce', 12);
        const plaintext = bytes(plaintextValue, 'plaintext');
        const aad = bytes(aadValue, 'AAD');
        if (plaintext.length > MAX_RATCHET_PLAINTEXT_BYTES || aad.length > MAX_RATCHET_AAD_BYTES) throw new RangeError('Double Ratchet plaintext or AAD exceeds the shared-core limit.');
        const newPrivate = newLocalDhPrivateValue === null ? null : bytes(newLocalDhPrivateValue, 'new local DH private key', 32);
        const headerCapacity = 58, ciphertextCapacity = plaintext.length + 16;
        const noncePtr = alloc(12), plainPtr = alloc(plaintext.length), aadPtr = alloc(aad.length);
        const privatePtr = newPrivate ? alloc(32) : 0;
        const headerPtr = alloc(headerCapacity), cipherPtr = alloc(ciphertextCapacity);
        try {
          write(noncePtr, nonce); write(plainPtr, plaintext); write(aadPtr, aad);
          if (newPrivate) write(privatePtr, newPrivate);
          const written = exports.serein_core_double_ratchet_encrypt(handle, noncePtr, plainPtr, plaintext.length,
            aadPtr, aad.length, privatePtr, headerPtr, headerCapacity, cipherPtr, ciphertextCapacity);
          const ciphertextLength = checkedLength(written, 'double ratchet encrypt');
          return { header: copy(headerPtr, headerCapacity), ciphertext: copy(cipherPtr, ciphertextLength), nonce: nonce.slice() };
        } finally {
          wipe(plainPtr, plaintext.length); wipe(aadPtr, aad.length); wipe(privatePtr, newPrivate ? 32 : 0);
          release(noncePtr, 12); release(plainPtr, plaintext.length); release(aadPtr, aad.length);
          release(privatePtr, newPrivate ? 32 : 0); release(headerPtr, headerCapacity); release(cipherPtr, ciphertextCapacity);
        }
      },
      decrypt(headerValue, nonceValue, ciphertextValue, aadValue, newLocalDhPrivateValue) {
        open();
        const header = bytes(headerValue, 'header', 58), nonce = bytes(nonceValue, 'nonce', 12);
        const ciphertext = bytes(ciphertextValue, 'ciphertext'), aad = bytes(aadValue, 'AAD');
        const newPrivate = bytes(newLocalDhPrivateValue, 'fresh local DH private key', 32);
        if (ciphertext.length < 16 || ciphertext.length > MAX_RATCHET_PLAINTEXT_BYTES + 16 || aad.length > MAX_RATCHET_AAD_BYTES) throw new RangeError('Ciphertext or AAD exceeds the shared-core limit.');
        const plaintextCapacity = ciphertext.length - 16, outputCapacity = Math.max(1, plaintextCapacity);
        const headerPtr = alloc(header.length), noncePtr = alloc(nonce.length), cipherPtr = alloc(ciphertext.length);
        const aadPtr = alloc(aad.length), privatePtr = alloc(32), plaintextPtr = alloc(outputCapacity);
        try {
          write(headerPtr, header); write(noncePtr, nonce); write(cipherPtr, ciphertext);
          write(aadPtr, aad); write(privatePtr, newPrivate);
          const written = exports.serein_core_double_ratchet_decrypt(handle, headerPtr, noncePtr, cipherPtr,
            ciphertext.length, aadPtr, aad.length, privatePtr, plaintextPtr, plaintextCapacity);
          const plaintextLength = checkedLength(written, 'double ratchet decrypt');
          return copy(plaintextPtr, plaintextLength);
        } finally {
          wipe(aadPtr, aad.length); wipe(privatePtr, 32); wipe(plaintextPtr, outputCapacity);
          release(headerPtr, header.length); release(noncePtr, nonce.length); release(cipherPtr, ciphertext.length);
          release(aadPtr, aad.length); release(privatePtr, 32); release(plaintextPtr, outputCapacity);
        }
      },
      snapshot() {
        open();
        const length = exports.serein_core_double_ratchet_snapshot_len(handle) >>> 0;
        if (length < 230 || length > 230 + 2000 * 68) throw new Error('Double Ratchet returned an invalid snapshot size.');
        const ptr = alloc(length);
        try {
          const written = exports.serein_core_double_ratchet_snapshot(handle, ptr, length);
          if (written !== length) throw ffiError(written);
          return copy(ptr, length);
        } finally { wipe(ptr, length); release(ptr, length); }
      },
      close() {
        if (handle) { exports.serein_core_double_ratchet_free(handle); handle = 0; }
      },
    });
  }

  window.SereinCore = {
    ready,
    get wasmActive() { return exports !== null; },
    get maxMessageCharacters() { return exports ? exports.serein_core_max_message_characters() : 4000; },
    get messageWarningCharacters() { return exports ? exports.serein_core_message_warning_characters() : 3600; },
    messageCharacterCount(value) {
      const text = String(value || '');
      if (!exports) return Array.from(text).length;
      const input = encoder.encode(text);
      if (!input.length) return 0;
      const ptr = exports.serein_core_alloc(input.length);
      if (!ptr) return Array.from(text).length;
      try {
        new Uint8Array(exports.memory.buffer, ptr, input.length).set(input);
        const count = exports.serein_core_message_character_count(ptr, input.length);
        return count < 0 || count === 0xffffffff ? Array.from(text).length : count;
      } finally { exports.serein_core_dealloc(ptr, input.length); }
    },
    validUsername(value) { return callString('serein_core_validate_username', String(value || '').trim().toLowerCase()); },
    registrationPasswordRequirements(value) {
      if (!exports) return null;
      const input = encoder.encode(String(value || ''));
      const ptr = input.length ? exports.serein_core_alloc(input.length) : 0;
      if (input.length && !ptr) return null;
      try {
        if (input.length) new Uint8Array(exports.memory.buffer, ptr, input.length).set(input);
        const mask = exports.serein_core_registration_password_requirements(ptr, input.length);
        return { length: !!(mask & 1), upper: !!(mask & 2), lower: !!(mask & 4), digit: !!(mask & 8), bytes: !!(mask & 16) };
      } finally { if (ptr) exports.serein_core_dealloc(ptr, input.length); }
    },
    async deriveRatchetChains(bootstrapValue, sessionValue, initiatorDirection = 0) {
      await ready; requireWasmRatchet();
      const bootstrap = bytes(bootstrapValue, 'bootstrap secret', 32), session = bytes(sessionValue, 'session id', 16);
      if (initiatorDirection !== 0 && initiatorDirection !== 1) throw new RangeError('Initiator direction must be 0 or 1.');
      const bootstrapPtr = alloc(32), sessionPtr = alloc(16), outputPtr = alloc(64);
      try {
        write(bootstrapPtr, bootstrap); write(sessionPtr, session);
        const status = exports.serein_core_ratchet_derive_chains(bootstrapPtr, sessionPtr, initiatorDirection, outputPtr);
        if (status !== 1) throw new Error('Directional ratchet seed derivation failed.');
        const output = copy(outputPtr, 64);
        return { initiatorToResponder: output.slice(0, 32), responderToInitiator: output.slice(32, 64) };
      } finally { wipe(bootstrapPtr, 32); wipe(outputPtr, 64); release(bootstrapPtr, 32); release(sessionPtr, 16); release(outputPtr, 64); }
    },
    async deriveRatchetRootStep(rootValue, dhValue) {
      await ready; requireWasmRatchet();
      const root = bytes(rootValue, 'root key', 32), dh = bytes(dhValue, 'DH output', 32);
      const rootPtr = alloc(32), dhPtr = alloc(32), outputPtr = alloc(64);
      try {
        write(rootPtr, root); write(dhPtr, dh);
        const status = exports.serein_core_ratchet_root_step(rootPtr, dhPtr, outputPtr);
        if (status !== 1) throw new Error('Ratchet root step rejected a non-contributory DH result or invalid root.');
        const output = copy(outputPtr, 64);
        return { rootKey: output.slice(0, 32), chainKey: output.slice(32, 64) };
      } finally { wipe(rootPtr, 32); wipe(dhPtr, 32); wipe(outputPtr, 64); release(rootPtr, 32); release(dhPtr, 32); release(outputPtr, 64); }
    },
    async createRatchet({ sessionId, sendDirection, sendChainKey, receiveChainKey }) {
      await ready; requireWasmRatchet();
      const session = bytes(sessionId, 'session id', 16), send = bytes(sendChainKey, 'sending chain key', 32), receive = bytes(receiveChainKey, 'receiving chain key', 32);
      if (sendDirection !== 0 && sendDirection !== 1) throw new RangeError('Sending direction must be 0 or 1.');
      const sessionPtr = alloc(16), sendPtr = alloc(32), receivePtr = alloc(32);
      try {
        write(sessionPtr, session); write(sendPtr, send); write(receivePtr, receive);
        const handle = exports.serein_core_ratchet_new(sessionPtr, sendDirection, sendPtr, receivePtr);
        if (!handle) throw new Error('Ratchet state initialization failed.');
        return wrapRatchet(handle);
      } finally { wipe(sendPtr, 32); wipe(receivePtr, 32); release(sessionPtr, 16); release(sendPtr, 32); release(receivePtr, 32); }
    },
    async restoreRatchet(snapshotValue) {
      await ready; requireWasmRatchet();
      const snapshot = bytes(snapshotValue, 'authenticated local ratchet snapshot');
      if (snapshot.length < 96 || snapshot.length > 96 + 1000 * 36) throw new RangeError('Ratchet snapshot size exceeded its bound.');
      const ptr = alloc(snapshot.length);
      try {
        write(ptr, snapshot);
        const handle = exports.serein_core_ratchet_restore(ptr, snapshot.length);
        if (!handle) throw new Error('Ratchet snapshot was malformed or exceeded bounds.');
        return wrapRatchet(handle);
      } finally { wipe(ptr, snapshot.length); release(ptr, snapshot.length); }
    },
    async doubleRatchetPublicFromPrivate(privateValue) {
      await ready; requireWasmRatchet();
      const privateKey = bytes(privateValue, 'X25519 private key', 32);
      const privatePtr = alloc(32), publicPtr = alloc(32);
      try {
        write(privatePtr, privateKey);
        const status = exports.serein_core_double_ratchet_public_from_private(privatePtr, publicPtr);
        if (status !== 1) throw new Error('X25519 private key was invalid.');
        return copy(publicPtr, 32);
      } finally { wipe(privatePtr, 32); release(privatePtr, 32); release(publicPtr, 32); }
    },
    async createDoubleRatchetInitiator({ sessionId, sendDirection, bootstrapSecret, localDhPrivate, remoteDhPublic }) {
      return createDoubleRatchet('initiator', { sessionId, sendDirection, bootstrapSecret, localDhPrivate, remoteDhPublic });
    },
    async createDoubleRatchetResponder({ sessionId, sendDirection, bootstrapSecret, localDhPrivate, remoteDhPublic }) {
      return createDoubleRatchet('responder', { sessionId, sendDirection, bootstrapSecret, localDhPrivate, remoteDhPublic });
    },
    async restoreDoubleRatchet(snapshotValue) {
      await ready; requireWasmRatchet();
      const snapshot = bytes(snapshotValue, 'authenticated local Double Ratchet snapshot');
      if (snapshot.length < 230 || snapshot.length > 230 + 2000 * 68) throw new RangeError('Double Ratchet snapshot size exceeded its bound.');
      const ptr = alloc(snapshot.length);
      try {
        write(ptr, snapshot);
        const handle = exports.serein_core_double_ratchet_restore(ptr, snapshot.length);
        if (!handle) throw new Error('Double Ratchet snapshot was malformed or exceeded bounds.');
        return wrapDoubleRatchet(handle);
      } finally { wipe(ptr, snapshot.length); release(ptr, snapshot.length); }
    },
  };

  async function createDoubleRatchet(role, { sessionId, sendDirection, bootstrapSecret, localDhPrivate, remoteDhPublic }) {
    await ready; requireWasmRatchet();
    const session = bytes(sessionId, 'session id', 16), bootstrap = bytes(bootstrapSecret, 'bootstrap secret', 32);
    const localPrivate = bytes(localDhPrivate, 'local X25519 private key', 32), remotePublic = bytes(remoteDhPublic, 'remote X25519 public key', 32);
    if (sendDirection !== 0 && sendDirection !== 1) throw new RangeError('Sending direction must be 0 or 1.');
    const sessionPtr = alloc(16), bootstrapPtr = alloc(32), localPtr = alloc(32), remotePtr = alloc(32);
    try {
      write(sessionPtr, session); write(bootstrapPtr, bootstrap); write(localPtr, localPrivate); write(remotePtr, remotePublic);
      const functionName = role === 'initiator'
        ? 'serein_core_double_ratchet_new_initiator'
        : 'serein_core_double_ratchet_new_responder';
      const handle = exports[functionName](sessionPtr, sendDirection, bootstrapPtr, localPtr, remotePtr);
      if (!handle) throw new Error('Double Ratchet initialization failed.');
      return wrapDoubleRatchet(handle);
    } finally {
      wipe(bootstrapPtr, 32); wipe(localPtr, 32);
      release(sessionPtr, 16); release(bootstrapPtr, 32); release(localPtr, 32); release(remotePtr, 32);
    }
  }
})();

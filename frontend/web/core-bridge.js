/* First-party Rust/WASM bridge. Falls back only for local preview builds where WASM was not built. */
(() => {
  'use strict';
  const encoder = new TextEncoder();
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
      if (!exports.memory || !exports.serein_core_validate_username || !exports.serein_core_registration_password_requirements || !exports.serein_core_max_message_characters || !exports.serein_core_message_warning_characters || !exports.serein_core_message_character_count || !exports.serein_core_alloc || !exports.serein_core_dealloc) { exports = null; return false; }
      return true;
    } catch (error) { console.info('Rust/WASM core not present; local development validation fallback active.', error); return false; }
  })();
  window.SereinCore = {
    ready,
    get wasmActive() { return exports !== null; },
    get maxMessageCharacters() { return exports ? exports.serein_core_max_message_characters() : 4000; },
    get messageWarningCharacters() { return exports ? exports.serein_core_message_warning_characters() : 3600; },
    messageCharacterCount(value) {
      const text = String(value || '');
      if (!exports) return Array.from(text).length;
      const bytes = encoder.encode(text);
      if (!bytes.length) return 0;
      const ptr = exports.serein_core_alloc(bytes.length);
      if (!ptr) return Array.from(text).length;
      try {
        new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
        const count = exports.serein_core_message_character_count(ptr, bytes.length);
        return count < 0 || count === 0xffffffff ? Array.from(text).length : count;
      } finally { exports.serein_core_dealloc(ptr, bytes.length); }
    },
    validUsername(value) { return callString('serein_core_validate_username', String(value || '').trim().toLowerCase()); },
    registrationPasswordRequirements(value) {
      if (!exports) return null;
      const bytes = encoder.encode(String(value || ''));
      const ptr = bytes.length ? exports.serein_core_alloc(bytes.length) : 0;
      if (bytes.length && !ptr) return null;
      try {
        if (bytes.length) new Uint8Array(exports.memory.buffer, ptr, bytes.length).set(bytes);
        const mask = exports.serein_core_registration_password_requirements(ptr, bytes.length);
        return { length: !!(mask & 1), upper: !!(mask & 2), lower: !!(mask & 4), digit: !!(mask & 8), bytes: !!(mask & 16) };
      } finally { if (ptr) exports.serein_core_dealloc(ptr, bytes.length); }
    },
  };
})();

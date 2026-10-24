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
      if (!exports.memory || !exports.serein_core_validate_username || !exports.serein_core_alloc || !exports.serein_core_dealloc) { exports = null; return false; }
      return true;
    } catch (error) { console.info('Rust/WASM core not present; local development validation fallback active.', error); return false; }
  })();
  window.SereinCore = {
    ready,
    get wasmActive() { return exports !== null; },
    validUsername(value) { return callString('serein_core_validate_username', String(value || '').trim().toLowerCase()); },
  };
})();

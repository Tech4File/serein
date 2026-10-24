/* Message-composer limits shared with the first-party Rust core when WASM is loaded. */
(() => {
  'use strict';
  const FALLBACK_MAX_CHARACTERS = 4000;
  const WARNING_RATIO = 0.9;
  const core = () => globalThis.SereinCore || null;

  function maxCharacters() {
    const value = Number(core()?.maxMessageCharacters);
    return Number.isInteger(value) && value > 0 ? value : FALLBACK_MAX_CHARACTERS;
  }
  function warningAt() {
    const value = Number(core()?.messageWarningCharacters);
    return Number.isInteger(value) && value >= 0 ? value : Math.ceil(maxCharacters() * WARNING_RATIO);
  }
  function characterCount(value) {
    const text = String(value ?? '');
    const sharedCount = core()?.messageCharacterCount?.(text);
    return Number.isInteger(sharedCount) && sharedCount >= 0 ? sharedCount : Array.from(text).length;
  }
  function truncate(value, max = maxCharacters()) {
    const limit = Number.isInteger(max) && max >= 0 ? max : maxCharacters();
    const text = String(value ?? '');
    if (characterCount(text) <= limit) return text;
    return Array.from(text).slice(0, limit).join('');
  }
  function counter(value) {
    const max = maxCharacters();
    const count = Math.min(characterCount(value), max);
    const remaining = max - count;
    const warning = count >= warningAt();
    return {
      count,
      remaining,
      warning,
      critical: count >= Math.ceil(max * 0.98),
      visible: warning,
      text: warning ? `${remaining} characters left` : `${count} / ${max}`,
    };
  }

  const api = Object.freeze({ FALLBACK_MAX_CHARACTERS, WARNING_RATIO, maxCharacters, characterCount, truncate, counter });
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (typeof globalThis !== 'undefined') globalThis.SereinMessageLimits = api;
})();

/* Version-3 two-layer ratchet envelope. State lifecycle/persistence is owned by the client adapter. */
(() => {
  'use strict';
  const encoder = new TextEncoder();
  const HEADER = 22;
  // Leave room for SRL1 + header + nonce + uint32 length inside the outer ratchet.
  const MAX_PLAINTEXT = 32_710;
  const MAX_CIPHERTEXT = MAX_PLAINTEXT + 16;
  const MAX_OUTER_CIPHERTEXT = MAX_PLAINTEXT + 74;
  const MAGIC = new Uint8Array([0x53, 0x52, 0x4c, 0x31]); // SRL1
  const ROUTE_FIELDS = ['conversationId', 'messageId', 'senderUserId', 'senderDeviceId', 'recipientUserId', 'recipientDeviceId'];
  function encode64(bytes) {
    let binary = '';
    for (let start = 0; start < bytes.length; start += 0x8000) binary += String.fromCharCode(...bytes.subarray(start, start + 0x8000));
    return btoa(binary);
  }
  function decode64(value, label, minimum = 0, maximum = MAX_OUTER_CIPHERTEXT + HEADER) {
    if (typeof value !== 'string' || value.length > Math.ceil(maximum / 3) * 4 + 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) throw new Error(`${label} encoding is invalid.`);
    const result = Uint8Array.from(atob(value), c => c.charCodeAt(0));
    if (result.length < minimum || result.length > maximum) throw new Error(`${label} length is outside the protocol bounds.`);
    return result;
  }
  function routeAad(metadata, layer) {
    const fields = ROUTE_FIELDS.map(field => String(metadata?.[field] || ''));
    if (fields.some(value => !value || value.length > 128)) throw new Error('Ratchet message routing metadata is incomplete.');
    return encoder.encode(JSON.stringify([`serein-message-v3-${layer}`, ...fields]));
  }
  function nonce() { return crypto.getRandomValues(new Uint8Array(12)); }
  function packInner(envelope) {
    const cipher = envelope.ciphertext;
    if (cipher.length < 16 || cipher.length > MAX_CIPHERTEXT || envelope.header.length !== HEADER || envelope.nonce.length !== 12) throw new Error('Layer 1 ratchet returned an invalid envelope.');
    const out = new Uint8Array(4 + HEADER + 12 + 4 + cipher.length);
    out.set(MAGIC, 0); out.set(envelope.header, 4); out.set(envelope.nonce, 4 + HEADER);
    new DataView(out.buffer).setUint32(4 + HEADER + 12, cipher.length, false);
    out.set(cipher, 4 + HEADER + 16);
    return out;
  }
  function unpackInner(bytes) {
    if (!(bytes instanceof Uint8Array) || bytes.length < 4 + HEADER + 12 + 4 + 16 || bytes.length > 4 + HEADER + 12 + 4 + MAX_CIPHERTEXT || MAGIC.some((v, i) => bytes[i] !== v)) throw new Error('Nested Layer 1 ratchet envelope is malformed.');
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const length = view.getUint32(4 + HEADER + 12, false);
    if (length < 16 || length > MAX_CIPHERTEXT || bytes.length !== 4 + HEADER + 12 + 4 + length) throw new Error('Nested Layer 1 ciphertext length is invalid.');
    return { header: bytes.slice(4, 4 + HEADER), nonce: bytes.slice(4 + HEADER, 4 + HEADER + 12), ciphertext: bytes.slice(4 + HEADER + 16) };
  }
  class LayeredRatchet {
    constructor(layer1, layer2) {
      if (!layer1 || !layer2 || typeof layer1.encrypt !== 'function' || typeof layer2.encrypt !== 'function') throw new TypeError('Two ratchet states are required.');
      this.layer1 = layer1; this.layer2 = layer2; this.closed = false;
    }
    ensureOpen() { if (this.closed) throw new Error('Layered ratchet handle is closed.'); }
    encrypt(plaintext, metadata) {
      this.ensureOpen();
      if (!(plaintext instanceof Uint8Array) || plaintext.length > MAX_PLAINTEXT) throw new RangeError('Layered ratchet plaintext exceeds 32 KiB.');
      const inner = this.layer1.encrypt(nonce(), plaintext, routeAad(metadata, 'layer1'));
      const packed = packInner(inner);
      const outer = this.layer2.encrypt(nonce(), packed, routeAad(metadata, 'layer2'));
      if (outer.header.length !== HEADER || outer.ciphertext.length > MAX_OUTER_CIPHERTEXT) throw new Error('Layer 2 ratchet returned an invalid envelope.');
      const complete = new Uint8Array(HEADER + outer.ciphertext.length);
      complete.set(outer.header); complete.set(outer.ciphertext, HEADER);
      return { version: 3, iv: encode64(outer.nonce), ciphertext: encode64(complete) };
    }
    decrypt(envelope, metadata) {
      this.ensureOpen();
      if (envelope?.version !== 3) throw new Error('Unsupported ratchet envelope version.');
      const outerNonce = decode64(envelope.iv, 'Layer 2 nonce', 12, 12);
      const complete = decode64(envelope.ciphertext, 'Layer 2 ciphertext', HEADER + 16, HEADER + MAX_OUTER_CIPHERTEXT);
      const packed = this.layer2.decrypt(complete.slice(0, HEADER), outerNonce, complete.slice(HEADER), routeAad(metadata, 'layer2'));
      const inner = unpackInner(packed);
      return this.layer1.decrypt(inner.header, inner.nonce, inner.ciphertext, routeAad(metadata, 'layer1'));
    }
    snapshots() { this.ensureOpen(); return { layer1: this.layer1.snapshot(), layer2: this.layer2.snapshot() }; }
    close() { if (!this.closed) { this.layer1.close(); this.layer2.close(); this.closed = true; } }
  }
  window.SereinLayeredRatchet = Object.freeze({ LayeredRatchet, routeAad });
})();

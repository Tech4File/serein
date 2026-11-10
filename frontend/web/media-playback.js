(function (root, factory) {
  const api = factory();
  if (typeof module === 'object' && module.exports) module.exports = api;
  if (root) root.SereinGifPlayback = Object.freeze(api);
})(typeof window === 'object' ? window : null, function () {
  'use strict';

  function gifDurationMs(input) {
    const bytes = input instanceof Uint8Array ? input : new Uint8Array(input);
    if (bytes.length < 13 || !["GIF87a", "GIF89a"].includes(String.fromCharCode(...bytes.subarray(0, 6)))) return 1000;
    let offset = 13;
    const screenPacked = bytes[10];
    if (screenPacked & 0x80) offset += 3 * (1 << ((screenPacked & 7) + 1));
    let pendingDelay = 100;
    let duration = 0;
    let frames = 0;
    const skipSubBlocks = () => {
      while (offset < bytes.length) {
        const length = bytes[offset++];
        if (length === 0) return true;
        if (offset + length > bytes.length) return false;
        offset += length;
      }
      return false;
    };
    while (offset < bytes.length && frames < 10000) {
      const marker = bytes[offset++];
      if (marker === 0x3b) break;
      if (marker === 0x21) {
        if (offset >= bytes.length) break;
        const label = bytes[offset++];
        if (label === 0xf9) {
          if (offset >= bytes.length) break;
          const size = bytes[offset++];
          if (size < 4 || offset + size > bytes.length) break;
          const delay = bytes[offset + 1] | (bytes[offset + 2] << 8);
          pendingDelay = Math.max(20, delay * 10);
          offset += size;
          if (bytes[offset] === 0) offset++;
        } else if (!skipSubBlocks()) break;
        continue;
      }
      if (marker !== 0x2c || offset + 9 > bytes.length) break;
      const imagePacked = bytes[offset + 8];
      offset += 9;
      if (imagePacked & 0x80) offset += 3 * (1 << ((imagePacked & 7) + 1));
      if (offset >= bytes.length) break;
      offset++; // LZW minimum code size
      if (!skipSubBlocks()) break;
      duration += pendingDelay;
      pendingDelay = 100;
      frames++;
    }
    return frames ? Math.min(120000, Math.max(250, 20 * frames, duration)) : 1000;
  }

  function attachTwoPassPlayback({ image, canvas, sourceUrl, durationMs = 1000, onOpen }) {
    let timer = 0;
    let pendingSecondTap = 0;
    let disposed = false;
    let playing = false;
    const start = () => {
      if (disposed) return;
      clearTimeout(timer);
      playing = true;
      canvas.hidden = true;
      image.hidden = false;
      image.removeAttribute('src');
      requestAnimationFrame(() => {
        if (disposed) return;
        image.onload = () => {
          clearTimeout(timer);
          timer = setTimeout(pauseAtCurrentFrame, Math.max(40, durationMs * 2));
        };
        image.src = sourceUrl;
      });
    };
    const pauseAtCurrentFrame = () => {
      if (disposed || !playing) return;
      try {
        canvas.width = image.naturalWidth || image.width || 1;
        canvas.height = image.naturalHeight || image.height || 1;
        const context = canvas.getContext('2d');
        context.drawImage(image, 0, 0, canvas.width, canvas.height);
        image.hidden = true;
        canvas.hidden = false;
        playing = false;
        image.removeAttribute('src');
      } catch {
        // Keep the GIF visible if the browser cannot snapshot the current frame.
      }
    };
    const handleTap = event => {
      event.preventDefault();
      if (pendingSecondTap) {
        clearTimeout(pendingSecondTap);
        pendingSecondTap = 0;
        onOpen?.();
        return;
      }
      start();
      pendingSecondTap = setTimeout(() => { pendingSecondTap = 0; }, Math.max(1400, durationMs * 2 + 300));
    };
    image.addEventListener('click', handleTap);
    canvas.addEventListener('click', handleTap);
    image.onload = () => { timer = setTimeout(pauseAtCurrentFrame, Math.max(40, durationMs * 2)); };
    image.src = sourceUrl;
    return Object.freeze({ dispose() {
      disposed = true;
      clearTimeout(timer);
      clearTimeout(pendingSecondTap);
      image.removeEventListener('click', handleTap);
      canvas.removeEventListener('click', handleTap);
      image.onload = null;
    } });
  }

  return { gifDurationMs, attachTwoPassPlayback };
});

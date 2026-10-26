/* Process a server history page without allowing one bad ciphertext to starve later messages. */
(() => {
  'use strict';

  async function processPage(items, cursor, processItem, persistCursor, onFailure = () => {}) {
    let nextCursor = cursor || null;
    let cursorBlocked = false;
    let failed = 0;

    for (const item of items) {
      let processed = false;
      try {
        processed = await processItem(item) !== false;
      } catch (error) {
        failed += 1;
        cursorBlocked = true;
        onFailure(error);
        continue;
      }

      if (!processed) {
        failed += 1;
        cursorBlocked = true;
        continue;
      }

      if (cursorBlocked) continue;
      const itemCursor = { after_created_at: item.created_at, after_id: item.id };
      try {
        await persistCursor(itemCursor);
        nextCursor = itemCursor;
      } catch (error) {
        // The message may already be durably stored and acknowledged. Keep processing
        // the page, but never move past a cursor that could not be persisted locally.
        failed += 1;
        cursorBlocked = true;
        onFailure(error);
      }
    }

    return { cursor: nextCursor, blocked: cursorBlocked, failed };
  }

  window.SereinHistorySync = Object.freeze({ processPage });
})();

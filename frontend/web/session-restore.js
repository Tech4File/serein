/* Retry transient session checks; only a confirmed 401 means the user is signed out. */
(() => {
  'use strict';

  async function fetchAccount(check, { attempts = 3, wait = milliseconds => new Promise(resolve => setTimeout(resolve, milliseconds)), onRetry = () => {} } = {}) {
    let lastError;
    for (let attempt = 1; attempt <= attempts; attempt += 1) {
      try {
        return await check();
      } catch (error) {
        lastError = error;
        if (error?.status === 401 || attempt === attempts) throw error;
        onRetry(attempt, error);
        await wait(Math.min(250 * (2 ** (attempt - 1)), 1000));
      }
    }
    throw lastError;
  }

  window.SereinSessionRestore = Object.freeze({ fetchAccount });
})();

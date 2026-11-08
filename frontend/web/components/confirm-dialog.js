(() => {
  'use strict';
  let pending = null;
  const byId = (id) => document.getElementById(id);

  function ask({ title = 'Please confirm', message = '', confirmLabel = 'Continue', danger = false } = {}) {
    const dialog = byId('confirmDialog');
    if (!dialog || pending) return Promise.resolve(false);
    byId('confirmDialogTitle').textContent = title;
    byId('confirmDialogMessage').textContent = message;
    byId('confirmDialogAccept').textContent = confirmLabel;
    dialog.classList.toggle('is-danger', danger);
    dialog.returnValue = '';
    return new Promise((resolve) => {
      pending = resolve;
      dialog.showModal();
      byId('confirmDialogCancel').focus({ preventScroll: true });
    });
  }

  function finish() {
    if (!pending) return;
    const resolve = pending;
    pending = null;
    resolve(byId('confirmDialog').returnValue === 'confirm');
  }

  byId('confirmDialog')?.addEventListener('close', finish);
  window.SereinConfirmDialog = Object.freeze({ ask });
})();

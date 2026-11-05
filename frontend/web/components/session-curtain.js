/* Independent loading-screen component. It does not own or mutate authentication layout. */
(() => {
  'use strict';
  const curtain = () => document.getElementById('sessionCurtain');
  let hideTimer = 0;
  let transitionHandler = null;
  let suspendedTargets = [];

  function suspendUnderlyingPage() {
    if (suspendedTargets.length) return;
    for (const element of [document.getElementById('login'), document.getElementById('app')].filter(Boolean)) {
      suspendedTargets.push([element, element.inert]);
      element.inert = true;
    }
  }

  function restoreUnderlyingPage() {
    for (const [element, wasInert] of suspendedTargets) element.inert = wasInert;
    suspendedTargets = [];
  }

  function clearPending(element) {
    clearTimeout(hideTimer);
    hideTimer = 0;
    if (transitionHandler) {
      element?.querySelector('.curtain-right')?.removeEventListener('transitionend', transitionHandler);
      transitionHandler = null;
    }
  }

  function show(title = 'Restoring your session', message = 'Checking this device and preparing your secure workspace…') {
    const layer = curtain();
    if (!layer) return;
    clearPending(layer);
    suspendUnderlyingPage();
    layer.hidden = false;
    layer.inert = false;
    layer.classList.remove('hidden', 'is-ready');
    layer.setAttribute('aria-hidden', 'false');
    const titleNode = document.getElementById('curtainTitle');
    const messageNode = document.getElementById('curtainMessage');
    if (titleNode) titleNode.textContent = title;
    if (messageNode) messageNode.textContent = message;
  }

  function hide() {
    const layer = curtain();
    if (!layer || layer.hidden) return;
    clearPending(layer);
    layer.inert = true;
    layer.setAttribute('aria-hidden', 'true');
    layer.classList.add('is-ready');
    const finish = () => {
      if (!layer.classList.contains('is-ready')) return;
      clearPending(layer);
      layer.classList.add('hidden');
      layer.hidden = true;
      restoreUnderlyingPage();
    };
    const reduceMotion = matchMedia('(prefers-reduced-motion: reduce)').matches || document.documentElement.classList.contains('reduce-motion');
    if (reduceMotion) { finish(); return; }
    const rightLeaf = layer.querySelector('.curtain-right');
    if (rightLeaf) {
      transitionHandler = event => {
        if (event.target === rightLeaf && event.propertyName === 'transform') finish();
      };
      rightLeaf.addEventListener('transitionend', transitionHandler);
    }
    const transition = getComputedStyle(layer.querySelector('.curtain-right') || layer).transitionDuration.split(',')[0].trim();
    const parsed = Number.parseFloat(transition) || .54;
    const durationMs = transition.endsWith('ms') ? parsed : parsed * 1000;
    hideTimer = setTimeout(finish, durationMs + 220);
  }

  window.SereinSessionCurtain = Object.freeze({ show, hide });
})();

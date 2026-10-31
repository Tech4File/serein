(() => {
  'use strict';
  const API = 'https://nekos.best/api/v2';
  const AMOUNT = 12;
  const MAX_BYTES = 64 * 1024 * 1024;
  const SEARCH_DEBOUNCE_MS = 720;
  const MIN_SEARCH_INTERVAL_MS = 750;
  const PREFERRED = [
    ['hug', 'Hugs'], ['pat', 'Pats'], ['wave', 'Waves'],
    ['laugh', 'Laughs'], ['dance', 'Dance'], ['smile', 'Smiles'],
  ];
  const $ = id => document.getElementById(id);
  const state = {
    categories: [], category: 'hug', query: '', results: [], seen: new Set(),
    loading: false, categoriesLoading: false, exhausted: false, repeats: 0,
    requestId: 0, controller: null, debounceTimer: 0, throttleTimer: 0,
    lastSearchAt: 0, cooldownUntil: 0,
  };

  function status(message, error = false) {
    const node = $('gifStatus');
    if (!node) return;
    node.textContent = message;
    node.classList.toggle('error', error);
  }
  function safeUrl(value) {
    try {
      const url = new URL(value);
      if (url.protocol !== 'https:' || url.hostname !== 'nekos.best' || !url.pathname.startsWith('/api/v2/')) return null;
      return url.href;
    } catch { return null; }
  }
  function normalizedQuery(value) { return String(value || '').trim().replace(/\s+/g, ' ').slice(0, 80); }
  function categoryLabel(slug) {
    return new Map(PREFERRED).get(slug) || slug.slice(0, 1).toUpperCase() + slug.slice(1);
  }
  function currentQueryUrl() {
    const url = new URL(state.query ? `${API}/search` : `${API}/${encodeURIComponent(state.category)}`);
    url.searchParams.set('amount', String(AMOUNT));
    if (state.query) {
      url.searchParams.set('query', state.query);
      url.searchParams.set('type', '2');
    }
    return url;
  }
  function setLoadMore(text, visible, disabled = false) {
    const button = $('gifLoadMore');
    if (!button) return;
    button.textContent = text;
    button.hidden = !visible;
    button.disabled = disabled;
  }
  function renderCategories() {
    const container = $('gifCategories');
    if (!container) return;
    container.replaceChildren();
    for (const [slug, label] of state.categories) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'picker-chip gif-category'; button.textContent = label;
      button.setAttribute('aria-pressed', String(!state.query && slug === state.category));
      button.addEventListener('click', () => {
        $('gifSearch').value = '';
        startView({ query: '', category: slug });
      });
      container.append(button);
    }
  }
  function addSkeletons(container, count) {
    for (let i = 0; i < count; i++) {
      const tile = document.createElement('div');
      tile.className = 'gif-skeleton'; tile.setAttribute('aria-hidden', 'true');
      container.append(tile);
    }
  }
  function renderResults() {
    const container = $('gifResults');
    if (!container) return;
    container.replaceChildren();
    for (const item of state.results) {
      const tile = document.createElement('button');
      tile.type = 'button'; tile.className = 'gif-result';
      tile.title = `Send GIF${item.anime_name ? ` · ${item.anime_name}` : ''}`;
      const image = document.createElement('img');
      image.src = item.url; image.alt = item.anime_name ? `GIF from ${item.anime_name}` : 'GIF';
      image.loading = 'lazy'; image.decoding = 'async'; image.referrerPolicy = 'no-referrer';
      image.addEventListener('error', () => {
        image.hidden = true; tile.classList.add('gif-result-unavailable');
        tile.setAttribute('aria-label', 'GIF preview unavailable');
      }, { once: true });
      const label = document.createElement('span'); label.textContent = item.anime_name || 'GIF';
      tile.append(image, label);
      tile.addEventListener('click', () => selectGif(item, tile));
      container.append(tile);
    }
    if ((state.loading || state.categoriesLoading) && state.results.length < 4) addSkeletons(container, Math.max(2, 4 - state.results.length));
    if (!state.results.length && !state.loading && !state.categoriesLoading) {
      const empty = document.createElement('p'); empty.className = 'gif-empty';
      empty.textContent = state.query ? `No GIFs found for “${state.query}”. Try another phrase.` : 'No GIFs in this category right now. Choose another category.';
      container.append(empty);
    }
  }
  function resetCurrentRequest() {
    state.requestId++;
    if (state.controller) state.controller.abort();
    state.controller = null;
    state.loading = false;
    clearTimeout(state.throttleTimer); state.throttleTimer = 0;
    return state.requestId;
  }
  async function fetchBatch(requestId = state.requestId) {
    if (requestId !== state.requestId || state.loading || state.exhausted) return;
    const wait = state.query ? Math.max(0, MIN_SEARCH_INTERVAL_MS - (Date.now() - state.lastSearchAt)) : 0;
    if (wait > 0) {
      state.loading = true; renderResults();
      status('Searching…'); setLoadMore('Searching…', true, true);
      state.throttleTimer = setTimeout(() => {
        if (requestId !== state.requestId) return;
        state.loading = false; state.throttleTimer = 0; fetchBatch(requestId);
      }, wait);
      return;
    }
    state.loading = true;
    const controller = new AbortController(); state.controller = controller;
    if (state.query) state.lastSearchAt = Date.now();
    renderResults();
    setLoadMore(state.results.length ? 'Loading more GIFs…' : 'Loading GIFs…', true, true);
    status(state.query ? `Searching GIFs for “${state.query}”…` : `Loading featured ${categoryLabel(state.category).toLowerCase()} GIFs…`);
    const url = currentQueryUrl();
    try {
      const response = await fetch(url, {
        cache: 'no-store', mode: 'cors', credentials: 'omit', redirect: 'error',
        referrerPolicy: 'no-referrer', signal: controller.signal,
      });
      if (requestId !== state.requestId) return;
      if (response.status === 429) {
        const retryAfter = Number(response.headers?.get?.('retry-after'));
        state.cooldownUntil = Date.now() + Math.max(3000, Number.isFinite(retryAfter) && retryAfter > 0 ? retryAfter * 1000 : 5000);
        throw new Error('The GIF service is rate-limiting requests. Wait a few seconds and retry.');
      }
      if (!response.ok) throw new Error(`GIF service returned HTTP ${response.status}.`);
      const payload = await response.json();
      if (requestId !== state.requestId) return;
      const rows = Array.isArray(payload?.results) ? payload.results : payload?.results ? [payload.results] : [];
      let added = 0;
      for (const raw of rows) {
        const urlValue = safeUrl(raw?.url);
        if (!urlValue || state.seen.has(urlValue)) continue;
        state.seen.add(urlValue);
        state.results.push({ url: urlValue, anime_name: String(raw.anime_name || '').slice(0, 100) });
        added++;
      }
      state.repeats = added ? 0 : state.repeats + 1;
      if (rows.length < AMOUNT || state.repeats >= 3 || state.results.length >= 72) state.exhausted = true;
      renderResults();
      if (state.query) status(state.results.length
        ? `Showing ${state.results.length} GIF${state.results.length === 1 ? '' : 's'} for “${state.query}”.`
        : `No GIFs found for “${state.query}”. Try another phrase.`, !state.results.length);
      else status(state.results.length
        ? `${state.results.length} featured GIF${state.results.length === 1 ? '' : 's'} · choose one to send or scroll for more.`
        : `No GIFs are available in ${categoryLabel(state.category)} right now. Choose a different category.`, !state.results.length);
      setLoadMore('Load more GIFs', state.results.length > 0 && !state.exhausted, false);
    } catch (error) {
      if (requestId !== state.requestId || error?.name === 'AbortError') return;
      const message = error?.message === 'Failed to fetch'
        ? 'The GIF service could not be reached from this browser. Check your connection and retry.'
        : error?.message || 'The GIF service could not be reached.';
      status(message, true);
      setLoadMore('Try again', true, false);
    } finally {
      if (requestId === state.requestId) {
        state.loading = false; state.controller = null; renderResults();
        if (state.exhausted && state.results.length) setLoadMore('No more GIFs in this set', true, true);
      }
    }
  }
  function startView({ query = '', category = state.category } = {}) {
    const requestId = resetCurrentRequest();
    state.query = normalizedQuery(query);
    state.category = category || state.categories[0]?.[0] || 'hug';
    state.results = []; state.seen.clear(); state.exhausted = false; state.repeats = 0;
    renderCategories(); renderResults();
    if (Date.now() < state.cooldownUntil) {
      const seconds = Math.ceil((state.cooldownUntil - Date.now()) / 1000);
      status(`Please wait ${seconds} seconds before searching again.`, true);
      setLoadMore('Try again', true, false);
      return;
    }
    fetchBatch(requestId);
  }
  function searchNow() {
    clearTimeout(state.debounceTimer); state.debounceTimer = 0;
    const query = normalizedQuery($('gifSearch').value);
    if (!query) {
      startView({ query: '', category: state.categories[0]?.[0] || 'hug' });
      return;
    }
    if (query.length < 2) {
      status('Type at least two characters to search GIFs.', true);
      return;
    }
    startView({ query, category: state.category });
  }
  function scheduleSearch() {
    clearTimeout(state.debounceTimer);
    const query = normalizedQuery($('gifSearch').value);
    if (query.length === 1) {
      resetCurrentRequest(); state.query = query; state.results = []; state.seen.clear();
      renderCategories(); renderResults(); status('Type one more character to search GIFs.', false);
      setLoadMore('', false); return;
    }
    state.debounceTimer = setTimeout(() => {
      state.debounceTimer = 0;
      if (!query) startView({ query: '', category: state.categories[0]?.[0] || 'hug' });
      else startView({ query, category: state.category });
    }, SEARCH_DEBOUNCE_MS);
    if (query.length >= 2) status('Searching as you type…');
  }
  function maybeLoadMore(event) {
    const node = event.currentTarget;
    if (node.scrollTop + node.clientHeight >= node.scrollHeight - 100) fetchBatch();
  }
  function parseCategories(data) {
    const gifCategories = new Set(Object.entries(data || {})
      .filter(([, value]) => String(value?.format || '').toLowerCase() === 'gif')
      .map(([key]) => key));
    const common = PREFERRED.filter(([slug]) => gifCategories.has(slug));
    if (common.length) return common;
    return [...gifCategories].slice(0, 8).map(slug => [slug, categoryLabel(slug)]);
  }
  async function loadCategories() {
    if (state.categoriesLoading) return;
    const requestAtStart = state.requestId;
    state.categoriesLoading = true; status('Loading GIF categories…'); renderResults();
    try {
      const response = await fetch(`${API}/endpoints`, {
        cache: 'force-cache', mode: 'cors', credentials: 'omit', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      if (!response.ok) throw new Error(`Category service returned HTTP ${response.status}.`);
      state.categories = parseCategories(await response.json());
      if (!state.categories.length) throw new Error('No GIF categories were returned.');
      if (!state.categories.some(([slug]) => slug === state.category)) state.category = state.categories[0][0];
      renderCategories();
    } catch (error) {
      // Category discovery is optional: still request the documented public hug endpoint.
      state.categories = PREFERRED; state.category = state.categories.some(([slug]) => slug === state.category) ? state.category : 'hug';
      renderCategories();
      status('Could not list GIF categories; loading the default featured GIFs instead.', true);
    } finally {
      state.categoriesLoading = false;
      renderResults();
      if (state.requestId === requestAtStart && !state.results.length && !state.loading) startView({ query: state.query, category: state.category });
    }
  }
  function open() {
    if (!state.categories.length) loadCategories();
    else if (!state.results.length && !state.loading && !state.categoriesLoading) startView({ query: state.query, category: state.category });
  }
  function close() { clearTimeout(state.debounceTimer); state.debounceTimer = 0; }
  async function selectGif(item, tile) {
    if (tile.disabled) return;
    tile.disabled = true; tile.classList.add('is-sending');
    status('Fetching the selected GIF, then encrypting it as a Serein attachment…');
    try {
      const response = await fetch(item.url, {
        mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer',
      });
      if (!response.ok) throw new Error(`GIF download returned HTTP ${response.status}.`);
      const length = Number(response.headers?.get?.('content-length') || 0);
      if (length > MAX_BYTES) throw new Error('Selected GIF exceeds the 64 MiB transfer limit.');
      const blob = await response.blob();
      if (!blob.size || blob.size > MAX_BYTES) throw new Error('Selected GIF is empty or exceeds the 64 MiB transfer limit.');
      const contentType = String(blob.type || '').toLowerCase();
      if (contentType && !contentType.startsWith('image/')) throw new Error('The provider returned a non-image file.');
      const file = new File([blob], `nekos-${crypto.randomUUID()}.gif`, {
        type: contentType === 'image/gif' ? contentType : 'image/gif', lastModified: Date.now(),
      });
      window.dispatchEvent(new CustomEvent('serein:gif-selected', {
        detail: { file, source: 'nekos.best', title: item.anime_name },
      }));
      status('GIF added to the encrypted send flow.');
    } catch (error) {
      status(`Could not use this GIF: ${error?.message || 'download failed'}. Try another result.`, true);
    } finally { tile.disabled = false; tile.classList.remove('is-sending'); }
  }
  function init() {
    $('gifSearchButton')?.addEventListener('click', searchNow);
    $('gifSearch')?.addEventListener('input', scheduleSearch);
    $('gifSearch')?.addEventListener('keydown', event => {
      if (event.key === 'Enter') { event.preventDefault(); clearTimeout(state.debounceTimer); searchNow(); }
    });
    $('gifSearchClear')?.addEventListener('click', () => {
      $('gifSearch').value = ''; clearTimeout(state.debounceTimer);
      startView({ query: '', category: state.categories[0]?.[0] || 'hug' }); $('gifSearch').focus();
    });
    $('gifResults')?.addEventListener('scroll', maybeLoadMore, { passive: true });
    $('gifLoadMore')?.addEventListener('click', () => {
      if (state.exhausted) return;
      if (Date.now() < state.cooldownUntil) {
        const seconds = Math.ceil((state.cooldownUntil - Date.now()) / 1000);
        status(`Please wait ${seconds} seconds before retrying.`, true); return;
      }
      fetchBatch();
    });
    window.SereinGifPicker = { open, search: searchNow, close, startView };
  }
  init();
})();

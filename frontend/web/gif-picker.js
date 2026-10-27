(() => {
  'use strict';
  const API = 'https://nekos.best/api/v2';
  const AMOUNT = 15;
  const MAX_BYTES = 64 * 1024 * 1024;
  const PREFERRED = [
    ['hug', 'Hug'], ['pat', 'Pat'], ['wave', 'Wave'],
    ['laugh', 'Laugh'], ['dance', 'Dance'], ['smile', 'Smile'],
  ];
  const $ = id => document.getElementById(id);
  const state = { categories: [], category: 'hug', query: '', results: [], seen: new Set(), loading: false, exhausted: false, repeats: 0 };

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
  function currentQueryUrl() {
    const url = new URL(state.query ? `${API}/search` : `${API}/${encodeURIComponent(state.category)}`);
    url.searchParams.set('type', '2');
    url.searchParams.set('amount', String(AMOUNT));
    if (state.query) url.searchParams.set('query', state.query);
    return url;
  }
  function renderCategories() {
    const container = $('gifCategories');
    if (!container) return;
    container.replaceChildren();
    for (const [slug, label] of state.categories) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'gif-category'; button.textContent = label;
      button.setAttribute('aria-pressed', String(!state.query && slug === state.category));
      button.addEventListener('click', () => {
        state.query = ''; $('gifSearch').value = ''; state.category = slug; resetAndLoad();
      });
      container.append(button);
    }
  }
  function renderResults() {
    const container = $('gifResults');
    if (!container) return;
    container.replaceChildren();
    for (const item of state.results) {
      const tile = document.createElement('button');
      tile.type = 'button'; tile.className = 'gif-result'; tile.title = `Send GIF${item.anime_name ? ` · ${item.anime_name}` : ''}`;
      const image = document.createElement('img'); image.src = item.url; image.alt = item.anime_name ? `GIF from ${item.anime_name}` : 'GIF'; image.loading = 'lazy'; image.decoding = 'async';
      image.addEventListener('error', () => { image.hidden = true; tile.classList.add('gif-result-unavailable'); tile.setAttribute('aria-label', 'GIF preview unavailable'); }, { once: true });
      const label = document.createElement('span'); label.textContent = item.anime_name || 'GIF';
      tile.append(image, label); tile.addEventListener('click', () => selectGif(item, tile)); container.append(tile);
    }
    if (!state.results.length && !state.loading) {
      const empty = document.createElement('p'); empty.className = 'gif-empty'; empty.textContent = state.query ? 'No GIFs found. Try a different phrase.' : 'No GIFs are available in this category right now.'; container.append(empty);
    }
  }
  async function fetchBatch() {
    if (state.loading || state.exhausted) return;
    state.loading = true; $('gifLoadMore').classList.remove('hidden'); $('gifLoadMore').textContent = state.results.length ? 'Loading more GIFs…' : 'Loading GIFs…'; status('GIFs load from nekos.best. Searches and request metadata go to that provider.');
    try {
      const response = await fetch(currentQueryUrl(), { cache: 'no-store', mode: 'cors', credentials: 'omit', redirect: 'error' });
      if (!response.ok) throw new Error(`GIF service returned ${response.status}.`);
      const payload = await response.json();
      const rows = Array.isArray(payload?.results) ? payload.results : payload?.results ? [payload.results] : [];
      let added = 0;
      for (const raw of rows) {
        const url = safeUrl(raw?.url);
        if (!url || state.seen.has(url)) continue;
        state.seen.add(url); state.results.push({ url, anime_name: String(raw.anime_name || '').slice(0, 100) }); added++;
      }
      state.repeats = added ? 0 : state.repeats + 1;
      if (rows.length < AMOUNT || state.repeats >= 3 || state.results.length >= 120) state.exhausted = true;
      renderResults();
      $('gifLoadMore').textContent = state.exhausted ? 'No more new GIFs in this result set.' : 'Scroll for more';
      if (state.query) status(`Showing ${state.results.length} GIF${state.results.length === 1 ? '' : 's'} for “${state.query}”.`);
      else status(`${state.results.length} GIF${state.results.length === 1 ? '' : 's'} loaded · scroll for more.`);
    } catch (error) {
      status(`Could not load GIFs: ${error.message}. You can still attach a GIF file with the paperclip.`, true);
      $('gifLoadMore').textContent = 'Try again'; state.exhausted = false;
    } finally { state.loading = false; }
  }
  function resetAndLoad() {
    state.results = []; state.seen.clear(); state.exhausted = false; state.repeats = 0;
    renderCategories(); renderResults(); fetchBatch();
  }
  async function search() {
    const query = $('gifSearch').value.trim().replace(/\s+/g, ' ').slice(0, 80);
    if (!query) { status('Enter a phrase to search for GIFs.', true); $('gifSearch').focus(); return; }
    state.query = query; state.results = []; state.seen.clear(); state.exhausted = false; state.repeats = 0;
    renderCategories(); await fetchBatch();
  }
  async function selectGif(item, tile) {
    const button = tile; if (button.disabled) return;
    button.disabled = true; button.classList.add('is-sending'); status('Fetching the selected GIF, then encrypting it as a Serein attachment…');
    try {
      const response = await fetch(item.url, { mode: 'cors', credentials: 'omit', cache: 'no-store', redirect: 'error' });
      if (!response.ok) throw new Error(`GIF download returned ${response.status}.`);
      const blob = await response.blob();
      if (!blob.size || blob.size > MAX_BYTES) throw new Error('Selected GIF is empty or exceeds the 64 MiB transfer limit.');
      const type = blob.type.toLowerCase();
      if (!type.startsWith('image/')) throw new Error('The provider returned a non-image file.');
      const file = new File([blob], `nekos-${crypto.randomUUID()}.gif`, { type: type === 'image/gif' ? type : 'image/gif', lastModified: Date.now() });
      window.dispatchEvent(new CustomEvent('serein:gif-selected', { detail: { file, source: 'nekos.best', title: item.anime_name } }));
    } catch (error) { status(`Could not use this GIF: ${error.message}. Try another result or attach a local file.`, true); }
    finally { button.disabled = false; button.classList.remove('is-sending'); }
  }
  function open() {
    if (!state.categories.length) loadCategories();
    else if (!state.results.length && !state.loading) resetAndLoad();
  }
  async function loadCategories() {
    if (state.loading) return;
    state.loading = true;
    try {
      const response = await fetch(`${API}/endpoints`, { cache: 'force-cache', mode: 'cors', credentials: 'omit', redirect: 'error' });
      if (!response.ok) throw new Error(`Category service returned ${response.status}.`);
      const data = await response.json();
      const gif = new Set(Object.entries(data || {}).filter(([, value]) => value?.format === 'gif').map(([key]) => key));
      state.categories = PREFERRED.filter(([slug]) => gif.has(slug));
      if (!state.categories.length) state.categories = [...gif].slice(0, 6).map(slug => [slug, slug[0].toUpperCase() + slug.slice(1)]);
      if (!state.categories.length) throw new Error('No GIF categories are available.');
      if (!state.categories.some(([slug]) => slug === state.category)) state.category = state.categories[0][0];
      state.loading = false; renderCategories(); await fetchBatch();
    } catch (error) {
      state.loading = false;
      state.categories = PREFERRED; renderCategories(); state.category = 'hug';
      status(`Could not load GIF categories: ${error.message}. Try a category or attach a local file.`, true);
    }
  }
  function init() {
    $('gifSearchForm')?.addEventListener('submit', event => { event.preventDefault(); search(); });
    $('gifSearchClear')?.addEventListener('click', () => { $('gifSearch').value = ''; state.query = ''; state.category = state.categories[0]?.[0] || 'hug'; resetAndLoad(); });
    $('gifResults')?.addEventListener('scroll', event => { const node = event.currentTarget; if (node.scrollTop + node.clientHeight >= node.scrollHeight - 100) fetchBatch(); });
    $('gifLoadMore')?.addEventListener('click', () => state.exhausted ? null : fetchBatch());
    window.SereinGifPicker = { open, search, close() {} };
  }
  init();
})();

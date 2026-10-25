(() => {
  'use strict';
  const labels = {
    core: { integrated: ['Integrated', 'good'], not_integrated: ['Not integrated', 'bad'], unknown: ['Unknown', 'unknown'] },
    protocol: { not_selected: ['Not selected', 'bad'], selected: ['Selected · review pending', 'warn'], in_development_unreviewed: ['In development · unreviewed', 'warn'], unknown: ['Unknown', 'unknown'] },
    source_implemented_unverified: ['Implemented in source · unverified', 'warn'],
    dual_public_key_source_implemented_unverified: ['Two public device keys · source unverified', 'warn'],
    web_android_ios_source_implemented_unverified: ['Web/Android/iOS source · runtime unverified', 'warn'],
    independent_layer1_layer2_key_pairs_source_implemented_unverified: ['Independent Layer 1/Layer 2 key pairs · unverified', 'warn'],
    browser_native_supported_codecs_only: ['Browser-supported codecs only', 'warn'],
    web_implemented_unreviewed: ['Web path active · independent review pending', 'warn'],
    manual_fingerprint_verification: ['Manual fingerprint comparison required', 'warn'],
    manual_combined_fingerprint_verification: ['Compare combined device-key fingerprint manually', 'warn'],
    manual_reverification_required: ['Key changes require manual re-verification', 'warn'],
    not_implemented: ['Not implemented', 'bad'],
    not_started: ['Not started', 'bad'],
    disabled: ['Disabled', 'warn'],
    enabled: ['Enabled · verify independently', 'warn'],
    partial: ['Partial', 'warn'],
    unknown: ['Unknown', 'unknown'],
  };

  // Mirrors the backend's public capability response. Only used when a live
  // request fails; it is explicitly labeled as a source snapshot, never live.
  const sourceSnapshot = {
    messaging_enabled: true,
    shared_core: { backend: true, web_wasm: true, android_native: false, ios_native: false, status: 'partial' },
    e2ee: {
      protocol: 'independent_device_bound_layer2_v2', protocol_status: 'in_development_unreviewed',
      device_key_registry: 'dual_public_key_source_implemented_unverified',
      web_device_key_enrollment: 'web_android_ios_source_implemented_unverified',
      web_conversation_key_derivation: 'independent_layer1_layer2_key_pairs_source_implemented_unverified',
      authenticated_key_exchange: 'manual_combined_fingerprint_verification',
      key_change_verification: 'manual_reverification_required', forward_secrecy: 'not_implemented',
      client_encrypt_decrypt: 'web_android_ios_source_implemented_unverified',
      message_delivery: 'enabled', independent_review: 'not_started',
    },
    file_transfers: {
      server_chunk_store: 'source_implemented_unverified', web_client: 'source_implemented_unverified',
      native_clients: 'source_implemented_unverified', media_preview: 'browser_native_supported_codecs_only',
      independent_review: 'not_started',
    },
    calls: {
      quic_media_transport: 'not_implemented', session_signaling: 'not_implemented',
      device_session_coordination: 'not_implemented',
    },
  };

  const byId = (id) => document.getElementById(id);
  let savedFontScale = 'system';
  try { savedFontScale = localStorage.getItem('serein.font-scale.v1') || 'system'; } catch { /* use the system default */ }
  document.documentElement.dataset.fontScale = ['system', 'large', 'extra_large'].includes(savedFontScale) ? savedFontScale : 'system';
  const setStatus = (id, key, group = '') => {
    const element = byId(id);
    const result = group ? labels[group]?.[key] : labels[key];
    const [text, style] = result || labels.unknown;
    element.textContent = text;
    element.className = `pill ${style}`;
  };
  const booleanCore = (value) => value === true ? 'integrated' : value === false ? 'not_integrated' : 'unknown';

  function configuredOrigin() {
    let saved = '';
    try { saved = localStorage.getItem('serein.api-origin.v1') || ''; } catch { /* storage may be unavailable */ }
    const raw = saved || window.SEREIN_CONFIG?.apiBase || location.origin;
    const url = new URL(raw, location.origin);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) {
      throw new Error('invalid configured service origin');
    }
    return url.origin;
  }

  function renderCapabilities(data) {
    const core = data.shared_core || {};
    const e2ee = data.e2ee || {};
    setStatus('core-backend', booleanCore(core.backend), 'core');
    setStatus('core-web', booleanCore(core.web_wasm), 'core');
    setStatus('core-android', booleanCore(core.android_native), 'core');
    setStatus('core-ios', booleanCore(core.ios_native), 'core');
    setStatus('e2ee-protocol', e2ee.protocol_status || 'unknown', 'protocol');
    setStatus('e2ee-key-directory', e2ee.device_key_registry || 'unknown');
    setStatus('e2ee-web-enrollment', e2ee.web_device_key_enrollment || 'unknown');
    setStatus('e2ee-shared-key', e2ee.web_conversation_key_derivation || 'unknown');
    setStatus('e2ee-keys', e2ee.key_change_verification || e2ee.authenticated_key_exchange || 'unknown');
    setStatus('e2ee-client', e2ee.client_encrypt_decrypt || 'unknown');
    setStatus('e2ee-forward', e2ee.forward_secrecy || 'unknown');
    setStatus('e2ee-delivery', data.messaging_enabled === true && e2ee.message_delivery === 'enabled' ? 'enabled' : data.messaging_enabled === false ? 'disabled' : 'unknown');
    setStatus('e2ee-review', e2ee.independent_review || 'unknown');
    const transfers = data.file_transfers || {};
    const calls = data.calls || {};
    setStatus('transfer-web', transfers.web_client || 'unknown');
    setStatus('transfer-native', transfers.native_clients || 'unknown');
    setStatus('transfer-preview', transfers.media_preview || 'unknown');
    setStatus('call-quic', calls.quic_media_transport || 'unknown');
  }

  async function refresh() {
    const summary = byId('summary');
    const overall = byId('overall');
    const source = byId('source');
    summary.dataset.state = 'loading';
    overall.textContent = 'Checking selected server…';
    try {
      const origin = configuredOrigin();
      const response = await fetch(`${origin}/api/v1/security/capabilities`, { cache: 'no-store', credentials: 'omit' });
      if (!response.ok) throw new Error('capability check unavailable');
      const data = await response.json();
      renderCapabilities(data);
      const enabled = data.messaging_enabled === true;
      summary.dataset.state = enabled ? 'ok' : 'error';
      overall.textContent = enabled ? 'Encrypted messaging source active · independent review pending' : data.messaging_enabled === false ? 'Messaging remains disabled' : 'Messaging state not reported';
      byId('checkedAt').textContent = `Live server check · ${new Date().toLocaleTimeString()} · refreshes every 30 seconds`;
      source.textContent = 'Live capability response received. This is not an audit.';
    } catch {
      renderCapabilities(sourceSnapshot);
      summary.dataset.state = 'degraded';
      overall.textContent = 'Live status unavailable · bundled source snapshot shown';
      byId('checkedAt').textContent = 'This snapshot describes repository source; it does not confirm the selected server or deployed build.';
      const version = String(window.SEREIN_CONFIG?.version || 'version not reported');
      source.textContent = `Bundled source snapshot · ${version} · check the configured server and refresh to retry.`;
    }
  }

  byId('refresh').addEventListener('click', refresh);
  refresh();
  setInterval(refresh, 30000);
})();

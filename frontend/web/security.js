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
    prototype: ['Prototype · not used for messages', 'warn'],
    web_prototype: ['Web prototype · not connected to messaging', 'warn'],
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
  const setStatus = (id, key, group = '') => {
    const element = document.getElementById(id);
    const result = group ? labels[group]?.[key] : labels[key];
    const [text, style] = result || labels.unknown;
    element.textContent = text;
    element.className = `pill ${style}`;
  };
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
  async function refresh() {
    const summary = document.getElementById('summary');
    const overall = document.getElementById('overall');
    const source = document.getElementById('source');
    summary.dataset.state = 'loading';
    overall.textContent = 'Checking selected server…';
    try {
      const origin = configuredOrigin();
      const response = await fetch(`${origin}/api/v1/security/capabilities`, { cache: 'no-store', credentials: 'omit' });
      if (!response.ok) throw new Error('capability check unavailable');
      const data = await response.json();
      const core = data.shared_core || {};
      const e2ee = data.e2ee || {};
      setStatus('core-backend', core.backend === true ? 'integrated' : 'not_integrated', 'core');
      setStatus('core-web', core.web_wasm === true ? 'integrated' : 'not_integrated', 'core');
      setStatus('core-android', core.android_native === true ? 'integrated' : 'not_integrated', 'core');
      setStatus('core-ios', core.ios_native === true ? 'integrated' : 'not_integrated', 'core');
      setStatus('e2ee-protocol', e2ee.protocol_status || 'unknown', 'protocol');
      setStatus('e2ee-key-directory', e2ee.device_key_registry || 'unknown');
      setStatus('e2ee-web-enrollment', e2ee.web_device_key_enrollment || 'unknown');
      setStatus('e2ee-shared-key', e2ee.web_conversation_key_derivation || 'unknown');
      setStatus('e2ee-keys', e2ee.key_change_verification || e2ee.authenticated_key_exchange || 'unknown');
      setStatus('e2ee-client', e2ee.client_encrypt_decrypt || 'unknown');
      setStatus('e2ee-forward', e2ee.forward_secrecy || 'unknown');
      setStatus('e2ee-delivery', data.messaging_enabled === true && e2ee.message_delivery === 'enabled' ? 'enabled' : 'disabled');
      setStatus('e2ee-review', e2ee.independent_review || 'unknown');
      const transfers = data.file_transfers || {}, calls = data.calls || {};
      setStatus('transfer-web', transfers.web_client || 'unknown');
      setStatus('transfer-native', transfers.native_clients || 'unknown');
      setStatus('transfer-preview', transfers.media_preview || 'unknown');
      setStatus('call-permissions', calls.permission_preflight || 'unknown');
      setStatus('call-quic', calls.quic_media_transport || 'unknown');
      const enabled = data.messaging_enabled === true;
      summary.dataset.state = enabled ? 'ok' : 'error';
      overall.textContent = enabled ? 'Encrypted messaging source active · independent review pending' : 'Messaging remains disabled';
      document.getElementById('checkedAt').textContent = `Checked ${new Date().toLocaleTimeString()} · auto-refreshes every 30 seconds`;
      source.textContent = 'Live capability response received. This is not an audit.';
    } catch {
      summary.dataset.state = 'error';
      overall.textContent = 'Live security status unavailable';
      document.getElementById('checkedAt').textContent = 'Could not read the selected server capability response.';
      for (const id of ['core-backend', 'core-web', 'core-android', 'core-ios', 'e2ee-protocol', 'e2ee-key-directory', 'e2ee-web-enrollment', 'e2ee-shared-key', 'e2ee-keys', 'e2ee-client', 'e2ee-forward', 'e2ee-delivery', 'e2ee-review', 'transfer-web', 'transfer-native', 'transfer-preview', 'call-permissions', 'call-quic']) {
        const element = document.getElementById(id);
        element.textContent = 'Unknown';
        element.className = 'pill unknown';
      }
      source.textContent = 'Check server availability and the configured web origin; no internal details are shown.';
    }
  }
  document.getElementById('refresh').addEventListener('click', refresh);
  refresh();
  setInterval(refresh, 30000);
})();

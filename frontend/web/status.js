(() => {
  'use strict';
  let savedFontScale = 'system';
  try { savedFontScale = localStorage.getItem('serein.font-scale.v1') || 'system'; } catch { /* use the system default */ }
  document.documentElement.dataset.fontScale = ['system', 'large', 'extra_large'].includes(savedFontScale) ? savedFontScale : 'system';
  const healthLabels = {
    api: { ready: ['Operational', 'ok'], other: ['Unavailable', 'bad'] },
    database: { ready: ['Connected', 'ok'], unavailable: ['Unavailable', 'bad'] },
    frontend: { available: ['Available', 'ok'], unavailable: ['Unavailable', 'bad'] },
    email_delivery: { configured: ['Configured', 'ok'], disabled: ['Not configured', 'warn'] },
  };
  function setPill(id, label, state = '') {
    const element = document.getElementById(id);
    element.textContent = label;
    element.className = `pill ${state}`;
  }
  function setHealthPill(id, key, value) {
    const mapping = healthLabels[id]?.[value] || ['Unknown', ''];
    setPill(key, mapping[0], mapping[1]);
  }
  function safeCapability(value) {
    return typeof value === 'string' && /^[a-z0-9_ -]{1,64}$/i.test(value) ? value.toLowerCase() : '';
  }
  function showCapabilityStatus(capabilities) {
    if (!capabilities || typeof capabilities !== 'object') {
      setPill('messaging', 'Unknown'); setPill('transfers', 'Unknown');
      setPill('calls', 'Unknown'); setPill('background', 'Unknown');
      return;
    }
    const e2ee = capabilities.e2ee || {}, transfers = capabilities.file_transfers || {}, calls = capabilities.calls || {};
    const messagingOn = capabilities.messaging_enabled === true && e2ee.message_delivery === 'enabled';
    setPill('messaging', messagingOn ? 'Enabled · not live-validated' : 'Unavailable', messagingOn ? 'warn' : 'bad');
    const transferState = safeCapability(transfers.server_chunk_store);
    setPill('transfers', transferState === 'source_implemented_unverified' ? 'Source present · unverified' : 'Unavailable', transferState === 'source_implemented_unverified' ? 'warn' : 'bad');
    const transport = safeCapability(calls.quic_media_transport), signaling = safeCapability(calls.session_signaling);
    if (transport === 'not_implemented' || signaling === 'not_implemented') setPill('calls', 'Not implemented', 'bad');
    else if (transport === 'source_implemented_unverified' && signaling === 'source_implemented_unverified') setPill('calls', 'Source present · unverified', 'warn');
    else setPill('calls', 'Unknown');
    setPill('background', 'Not configured', 'warn');
  }
  async function refresh() {
    const summary = document.getElementById('summary');
    document.getElementById('overall').textContent = 'Checking service health';
    summary.dataset.state = 'loading';
    const healthRequest = fetch('/healthz', { cache: 'no-store', credentials: 'same-origin' });
    const capabilityRequest = fetch('/api/v1/security/capabilities', { cache: 'no-store', credentials: 'same-origin' }).catch(() => null);
    try {
      const [response, capabilityResponse] = await Promise.all([healthRequest, capabilityRequest]);
      const data = await response.json();
      const components = data.components || {};
      setHealthPill('api', 'api', components.api);
      setHealthPill('database', 'database', components.database);
      setHealthPill('frontend', 'frontend', components.frontend);
      setHealthPill('email_delivery', 'email', components.email_delivery);
      let capabilityData = null;
      if (capabilityResponse?.ok) capabilityData = await capabilityResponse.json().catch(() => null);
      showCapabilityStatus(capabilityData);
      const ready = response.ok && data.status === 'ready';
      summary.dataset.state = ready ? 'ready' : 'degraded';
      document.getElementById('overall').textContent = ready ? 'Core service is operational' : 'Core service needs attention';
      document.getElementById('checkedAt').textContent = `Health checked ${new Date().toLocaleTimeString()}. Feature rows report implementation status, not service availability.`;
    } catch {
      summary.dataset.state = 'degraded';
      document.getElementById('overall').textContent = 'Status check unavailable';
      document.getElementById('checkedAt').textContent = 'The service health check could not be reached. Try again shortly.';
      for (const id of ['api', 'database', 'frontend', 'email']) setPill(id, 'Unknown');
      showCapabilityStatus(null);
    }
  }
  document.getElementById('refresh').addEventListener('click', refresh);
  refresh();
})();

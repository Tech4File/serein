(() => {
  'use strict';
  const labels = {
    api: { ready: ['Operational', 'ok'], other: ['Unavailable', 'bad'] },
    database: { ready: ['Connected', 'ok'], unavailable: ['Unavailable', 'bad'] },
    frontend: { available: ['Available', 'ok'], unavailable: ['Unavailable', 'bad'] },
    email_delivery: { configured: ['Configured', 'ok'], disabled: ['Not configured', 'warn'] },
  };
  function setPill(id, key) {
    const item = labels[id]?.[key] || ['Unknown', ''];
    const element = document.getElementById(id === 'email_delivery' ? 'email' : id);
    element.textContent = item[0];
    element.className = `pill ${item[1]}`;
  }
  async function refresh() {
    const summary = document.getElementById('summary');
    document.getElementById('overall').textContent = 'Checking service health';
    summary.dataset.state = 'loading';
    try {
      const response = await fetch('/healthz', { cache: 'no-store', credentials: 'same-origin' });
      const data = await response.json();
      const components = data.components || {};
      setPill('api', components.api);
      setPill('database', components.database);
      setPill('frontend', components.frontend);
      setPill('email_delivery', components.email_delivery);
      const ready = response.ok && data.status === 'ready';
      summary.dataset.state = ready ? 'ready' : 'degraded';
      document.getElementById('overall').textContent = ready ? 'All core services operational' : 'Some services need attention';
      document.getElementById('checkedAt').textContent = `Last checked ${new Date().toLocaleTimeString()}`;
    } catch {
      summary.dataset.state = 'degraded';
      document.getElementById('overall').textContent = 'Status check unavailable';
      document.getElementById('checkedAt').textContent = 'The service health check could not be reached. Try again shortly.';
      for (const id of ['api', 'database', 'frontend', 'email']) {
        const element = document.getElementById(id);
        element.textContent = 'Unknown';
        element.className = 'pill';
      }
    }
  }
  document.getElementById('refresh').addEventListener('click', refresh);
  refresh();
})();

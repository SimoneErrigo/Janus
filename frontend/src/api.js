const BASE = '/api';

function getToken() {
  return localStorage.getItem('janus_token');
}

/**
 * Live packet updates (SSE). Returns unsubscribe.
 * @param {function(Object[])} onNewPackets - called with array of new packet objects (streamed)
 * @param {function()} onRefresh - called when a full refresh is needed (metadata change)
 */
export function subscribePacketStream(onNewPackets, onRefresh) {
  const token = getToken();
  if (!token) return () => {};

  const url = `/api/packets/stream?token=${encodeURIComponent(token)}`;
  let es;
  try {
    es = new EventSource(url);
  } catch {
    return () => {};
  }
  const newHandler = (e) => {
    try {
      const packets = JSON.parse(e.data);
      if (Array.isArray(packets)) onNewPackets(packets);
    } catch {}
  };
  const refreshHandler = () => onRefresh();
  es.addEventListener('new-packets', newHandler);
  es.addEventListener('packets', refreshHandler);
  const fallback = setInterval(onRefresh, 20000);
  return () => {
    clearInterval(fallback);
    es.removeEventListener('new-packets', newHandler);
    es.removeEventListener('packets', refreshHandler);
    es.close();
  };
}

export function setToken(token) {
  localStorage.setItem('janus_token', token);
}

export function clearToken() {
  localStorage.removeItem('janus_token');
}

export function hasToken() {
  return !!getToken();
}

async function request(path, options = {}) {
  const token = getToken();
  const headers = { ...options.headers };
  if (token) headers['Authorization'] = `Bearer ${token}`;
  if (options.body && typeof options.body === 'object' && !(options.body instanceof FormData)) {
    headers['Content-Type'] = 'application/json';
    options.body = JSON.stringify(options.body);
  }

  const res = await fetch(BASE + path, { ...options, headers });

  if (res.status === 401) {
    clearToken();
    window.location.href = '/login';
    throw new Error('Unauthorized');
  }

  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || res.statusText);
  }

  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  login: (password) => request('/login', { method: 'POST', body: { password } }),

  // Services
  listServices: () => request('/services'),
  getService: (id) => request(`/services/${id}`),
  createService: (data) => request('/services', { method: 'POST', body: data }),
  updateService: (id, data) => request(`/services/${id}`, { method: 'PUT', body: data }),
  deleteService: (id) => request(`/services/${id}`, { method: 'DELETE' }),

  // Packets
  getPackets: (params) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v);
    });
    return request(`/packets?${qs.toString()}`);
  },

  getPacketFlow: (packetId) => request(`/packets/flow?packet_id=${packetId}`),
  generateExploit: (packetId) => request(`/packets/exploit?packet_id=${packetId}`),

  // Rules
  listRules: (serviceId) => {
    const qs = serviceId ? `?service_id=${serviceId}` : '';
    return request(`/rules${qs}`);
  },
  getRule: (id) => request(`/rules/${id}`),
  createRule: (data) => request('/rules', { method: 'POST', body: data }),
  updateRule: (id, data) => request(`/rules/${id}`, { method: 'PUT', body: data }),
  deleteRule: (id) => request(`/rules/${id}`, { method: 'DELETE' }),

  // Alerts
  listAlerts: (params = {}) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v);
    });
    return request(`/alerts?${qs.toString()}`);
  },
  getAlert: (id) => request(`/alerts/${id}`),
  clearAlerts: () => request('/alerts', { method: 'DELETE' }),

  // Config
  getConfig: () => request('/config'),
  updateConfig: (data) => request('/config', { method: 'PUT', body: data }),

  // Flag IDs
  getFlagIDs: () => request('/flagids'),
  getFlagIDStatus: () => request('/flagids/status'),
  refreshFlagIDs: () => request('/flagids/refresh', { method: 'POST' }),
  triggerBackfill: () => request('/flagids/backfill', { method: 'POST' }),

  // Cleanup
  getCleanupConfig: () => request('/config/cleanup'),
  updateCleanupConfig: (data) => request('/config/cleanup', { method: 'PUT', body: data }),
  runCleanup: () => request('/cleanup/run', { method: 'POST' }),
  purgeAll: () => request('/cleanup/purge', { method: 'POST' }),
  purgePackets: () => request('/cleanup/purge-packets', { method: 'POST' }),

  // System stats
  getSystemStats: () => request('/system/stats'),
};

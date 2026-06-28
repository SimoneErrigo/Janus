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

export function getDisplayName() {
  return localStorage.getItem('janus_name') || '';
}

export function setDisplayName(name) {
  if (name) localStorage.setItem('janus_name', name);
  else localStorage.removeItem('janus_name');
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
  login: (password, displayName = '') => request('/login', { method: 'POST', body: { password, display_name: displayName } }),

  // Session / multi-user
  getSessionActive: () => request('/session/active'),

  // PCAP export
  pcapExport: (params) => request('/pcap/export', { method: 'POST', body: params || {} }),
  pcapExportSelection: (ids) => request('/pcap/export-selection', { method: 'POST', body: { ids } }),
  listPcapFiles: () => request('/pcap/files'),
  deletePcapFile: (name) => request(`/pcap/files/${encodeURIComponent(name)}`, { method: 'DELETE' }),
  pcapDownloadUrl: (name) => {
    const token = localStorage.getItem('janus_token') || '';
    return `/api/pcap/files/${encodeURIComponent(name)}?token=${encodeURIComponent(token)}`;
  },
  flowPcapDownloadUrl: (packetId) => {
    const token = localStorage.getItem('janus_token') || '';
    return `/api/packets/flow/pcap?packet_id=${packetId}&token=${encodeURIComponent(token)}`;
  },
  pcapImport: async (file, serviceId, protocolId) => {
    const token = getToken();
    const fd = new FormData();
    fd.append('file', file);
    if (serviceId) fd.append('service_id', serviceId);
    if (protocolId) fd.append('protocol_id', protocolId);
    const res = await fetch(BASE + '/pcap/import', {
      method: 'POST',
      headers: token ? { Authorization: `Bearer ${token}` } : {},
      body: fd,
    });
    if (!res.ok) {
      const text = await res.text();
      throw new Error(text || res.statusText);
    }
    return res.json();
  },
  getPcapImportStatus: (id) => request(`/pcap/import/${encodeURIComponent(id)}/status`),

  // Saved flows
  listSavedFlows: () => request('/flows/saved'),
  createSavedFlow: (data) => request('/flows/saved', { method: 'POST', body: data }),
  getSavedFlow: (id) => request(`/flows/saved/${id}`),
  deleteSavedFlow: (id) => request(`/flows/saved/${id}`, { method: 'DELETE' }),

  // Services
  listServices: () => request('/services'),
  getService: (id) => request(`/services/${id}`),
  createService: (data) => request('/services', { method: 'POST', body: data }),
  updateService: (id, data) => request(`/services/${id}`, { method: 'PUT', body: data }),
  deleteService: (id) => request(`/services/${id}`, { method: 'DELETE' }),
  // Returns { [serviceId]: { service_id, state, running, last_error?, last_attempt? } }
  // for every proxy the backend has registered. Reflects the *real* listener
  // health, not just the configured enabled flag.
  getServicesStatus: () => request('/proxy/statuses'),
  // Kicks the bind-retry loop for one service to run immediately. Useful
  // right after rebuilding the underlying docker container.
  retryService: (id) => request(`/services/${id}/retry`, { method: 'POST' }),
  // Kicks every retrying proxy in one call.
  retryAllServices: () => request('/proxy/retry-all', { method: 'POST' }),

  // .proto files auto-discovered under PROTO_DIR
  listProtoFiles: () => request('/protos'),
  encodeProtoField: (data) => request('/protos/encode-field', { method: 'POST', body: data }),

  // Custom decoder protocols (Step 14)
  listProtocols: () => request('/protocols'),
  getProtocol: (id) => request(`/protocols/${id}`),
  createProtocol: (data) => request('/protocols', { method: 'POST', body: data }),
  updateProtocol: (id, data) => request(`/protocols/${id}`, { method: 'PUT', body: data }),
  deleteProtocol: (id) => request(`/protocols/${id}`, { method: 'DELETE' }),
  // Parse pasted Python (struct + Enum idiom) into a draft protocol.
  // Returns { protocol, warnings }. Nothing is persisted server-side.
  importProtocol: (code) => request('/protocols/import', { method: 'POST', body: { code } }),
  decodePacketCustom: (packetId, protocolId) => {
    const qs = new URLSearchParams({ packet_id: String(packetId) });
    if (protocolId) qs.set('protocol_id', protocolId);
    return request(`/packets/decoded-custom?${qs.toString()}`);
  },

  // Packets
  getPackets: (params) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v);
    });
    return request(`/packets?${qs.toString()}`);
  },

  getPacket: (id) => request(`/packets/${id}`),
  deletePacket: (id) => request(`/packets/${id}`, { method: 'DELETE' }),
  bulkDeletePackets: (ids) => request('/packets/bulk-delete', { method: 'POST', body: { ids } }),
  getPacketFlow: (packetId) => request(`/packets/flow?packet_id=${packetId}`),
  generateExploit: (packetId) => request(`/packets/exploit?packet_id=${packetId}`),
  decodePacket: (packetId) => request(`/packets/decoded?packet_id=${packetId}`),

  // Rules
  listRules: (serviceId) => {
    const qs = serviceId ? `?service_id=${serviceId}` : '';
    return request(`/rules${qs}`);
  },
  getRule: (id) => request(`/rules/${id}`),
  createRule: (data) => request('/rules', { method: 'POST', body: data }),
  updateRule: (id, data) => request(`/rules/${id}`, { method: 'PUT', body: data }),
  deleteRule: (id) => request(`/rules/${id}`, { method: 'DELETE' }),
  bulkDeleteRules: (ids) => request('/rules/bulk-delete', { method: 'POST', body: { ids } }),

  // Rule presets
  getPresets: () => request('/rules/presets'),
  applyPresets: (data) => request('/rules/presets/apply', { method: 'POST', body: data }),

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

  // Static capture mode
  getCaptureStatus: () => request('/traffic/capture'),
  startCapture: () => request('/traffic/capture/start', { method: 'POST' }),
  stopCapture: () => request('/traffic/capture/stop', { method: 'POST' }),
  applyCaptureFlagIDs: () => request('/traffic/capture/apply-flagids', { method: 'POST' }),

  // Cleanup
  getCleanupConfig: () => request('/config/cleanup'),
  updateCleanupConfig: (data) => request('/config/cleanup', { method: 'PUT', body: data }),
  runCleanup: () => request('/cleanup/run', { method: 'POST' }),
  purgeAll: () => request('/cleanup/purge', { method: 'POST' }),
  purgePackets: () => request('/cleanup/purge-packets', { method: 'POST' }),
  purgeDropped: () => request('/cleanup/purge-dropped', { method: 'POST' }),

  // System stats
  getSystemStats: () => request('/system/stats'),

  // Filter expression validation. Returns { ok: true } or
  // { ok: false, error, position }.
  validateFilter: (expression) => request('/filter/validate', { method: 'POST', body: { expression } }),

  // Round diff — backend-computed novelty + suspicion analysis between two rounds.
  getRoundDiff: (params) => {
    const qs = new URLSearchParams();
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') qs.set(k, v);
    });
    return request(`/round-diff?${qs.toString()}`);
  },
};
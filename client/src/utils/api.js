import axios from 'axios';
import { collectDeviceInfo } from './deviceInfo.js';
import { getUserName, getUserRole } from './authSession.js';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_URL || '',
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    'X-Fina-Client': 'web-app',
  },
});

const sessionId = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

const getAnalyticsHeaders = () => {
  const headers = {};

  try {
    if (window.screen) {
      headers['X-Screen-Width'] = String(window.screen.width);
      headers['X-Screen-Height'] = String(window.screen.height);
      headers['X-Color-Depth'] = String(window.screen.colorDepth || '');
    }

    if (navigator.hardwareConcurrency) {
      headers['X-HW-Cores'] = String(navigator.hardwareConcurrency);
    }

    if (navigator.deviceMemory) {
      headers['X-HW-Memory'] = String(navigator.deviceMemory);
    }

    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (conn) {
      if (conn.effectiveType) headers['X-Connection-Type'] = conn.effectiveType;
      if (conn.downlink) headers['X-Connection-Downlink'] = String(conn.downlink);
      if (conn.rtt) headers['X-Connection-RTT'] = String(conn.rtt);
    }

    headers['X-Session-Id'] = sessionId;
  } catch (_) {
    // Non-critical client analytics
  }

  return headers;
};

api.interceptors.request.use(
  async (config) => {
    Object.assign(config.headers, getAnalyticsHeaders());

    try {
      const deviceInfo = collectDeviceInfo();
      config.headers['X-Device-Info'] = btoa(unescape(encodeURIComponent(JSON.stringify(deviceInfo))));
    } catch (_) {
      // Do not block the request on analytics header failures
    }

    config.headers['X-User-Role'] = getUserRole();
    config.headers['X-User-Name'] = getUserName();

    return config;
  },
  (error) => Promise.reject(error)
);

api.interceptors.response.use(
  (response) => response,
  (error) => Promise.reject(error)
);

export default api;

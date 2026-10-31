/**
 * VULNEX Canonical API Client
 * Adheres strictly to docs/API_CONTRACTS.md standard envelope:
 * Success: { success: true, data: T, requestId: string }
 * Error:   { success: false, error: { code, message, details? }, requestId: string }
 */
import axios from 'axios';

/**
 * Standardized API Error Class
 */
export class ApiError extends Error {
  constructor(message, { code = 'UNKNOWN_ERROR', status = 500, requestId = null, details = null } = {}) {
    super(message);
    this.name = 'ApiError';
    this.code = code;
    this.status = status;
    this.requestId = requestId;
    this.details = details;
    this.isApiError = true;
  }
}

/**
 * Generate lightweight client request ID for distributed tracing
 */
const generateRequestId = () => {
  return `req_client_${Date.now()}_${Math.random().toString(36).substring(2, 9)}`;
};

const BASE_URL =
  (typeof import.meta !== 'undefined' && import.meta.env && import.meta.env.VITE_API_BASE_URL) ||
  'http://localhost:5001/api';

const axiosInstance = axios.create({
  baseURL: BASE_URL,
  timeout: 30000,
  headers: {
    'Accept': 'application/json',
  },
});

// Request Interceptor: Attach X-Request-ID if absent
axiosInstance.interceptors.request.use(
  (config) => {
    if (!config.headers['X-Request-ID']) {
      config.headers['X-Request-ID'] = generateRequestId();
    }
    return config;
  },
  (error) => {
    return Promise.reject(
      new ApiError('Failed to dispatch request', {
        code: 'REQUEST_DISPATCH_FAILED',
        status: 0,
        details: error.message,
      })
    );
  }
);

// Response Interceptor: Parse Canonical Envelope & Standardize Errors
axiosInstance.interceptors.response.use(
  (response) => {
    const payload = response.data;
    // Canonical envelope validation
    if (payload && typeof payload === 'object' && 'success' in payload) {
      if (payload.success) {
        return payload; // Envelope with { success: true, data, requestId }
      } else {
        throw new ApiError(payload.error?.message || 'Operation failed', {
          code: payload.error?.code || 'OPERATION_FAILED',
          status: response.status,
          requestId: payload.requestId || response.headers['x-request-id'],
          details: payload.error?.details,
        });
      }
    }
    // Fallback if raw JSON returned
    return {
      success: true,
      data: payload,
      requestId: response.headers['x-request-id'] || 'req_legacy',
    };
  },
  (error) => {
    if (error.response) {
      const { status, data, headers } = error.response;
      const reqId = data?.requestId || headers['x-request-id'] || 'req_unknown';

      if (data && data.error) {
        throw new ApiError(data.error.message || `HTTP Error ${status}`, {
          code: data.error.code || 'HTTP_ERROR',
          status,
          requestId: reqId,
          details: data.error.details,
        });
      }

      throw new ApiError(data?.message || `Request failed with HTTP ${status}`, {
        code: status === 404 ? 'RESOURCE_NOT_FOUND' : status === 403 ? 'FORBIDDEN' : 'SERVER_ERROR',
        status,
        requestId: reqId,
      });
    }

    if (error.code === 'ECONNABORTED' || error.message?.includes('timeout')) {
      throw new ApiError('Request timed out. Please verify backend connectivity.', {
        code: 'TIMEOUT',
        status: 408,
      });
    }

    if (error.message === 'Network Error' || !error.response) {
      throw new ApiError('Network error: Unable to reach VULNEX backend service.', {
        code: 'NETWORK_ERROR',
        status: 0,
      });
    }

    throw new ApiError(error.message || 'An unexpected error occurred.', {
      code: 'UNEXPECTED_ERROR',
      status: 500,
    });
  }
);

/**
 * High-Level Canonical API Methods
 */
export const vulnexApi = {
  // Raw instance access if needed
  client: axiosInstance,

  // Health
  health: {
    check: async () => {
      const res = await axiosInstance.get('/health');
      return res.data;
    },
  },

  // Repositories
  repositories: {
    list: async (params = {}) => {
      const res = await axiosInstance.get('/repositories', { params });
      return res.data;
    },
    get: async (id) => {
      const res = await axiosInstance.get(`/repositories/${encodeURIComponent(id)}`);
      return res.data;
    },
    register: async (payload) => {
      const res = await axiosInstance.post('/repositories', payload);
      return res.data;
    },
  },

  // Scans
  scans: {
    list: async () => {
      const res = await axiosInstance.get('/scans');
      return res.data;
    },
    start: async (payload) => {
      const res = await axiosInstance.post('/scans', payload);
      return res.data;
    },
    get: async (id) => {
      const res = await axiosInstance.get(`/scans/${encodeURIComponent(id)}`);
      return res.data;
    },
    getEvents: async (id) => {
      const res = await axiosInstance.get(`/scans/${encodeURIComponent(id)}/events`);
      return res.data;
    },
    getFindings: async (scanId, params = {}) => {
      const res = await axiosInstance.get(`/scans/${encodeURIComponent(scanId)}/findings`, { params });
      return res.data;
    },
    getReport: async (scanId) => {
      const res = await axiosInstance.get(`/scans/${encodeURIComponent(scanId)}/report`);
      return res.data;
    },
  },

  // Findings
  findings: {
    list: async (params = {}) => {
      const res = await axiosInstance.get('/findings', { params });
      return res.data;
    },
    get: async (id) => {
      const res = await axiosInstance.get(`/findings/${encodeURIComponent(id)}`);
      return res.data;
    },
    investigate: async (id) => {
      const res = await axiosInstance.post(`/findings/${encodeURIComponent(id)}/investigate`);
      return res.data;
    },
    generatePatch: async (id) => {
      const res = await axiosInstance.post(`/findings/${encodeURIComponent(id)}/patches`);
      return res.data;
    },
  },

  // Patches
  patches: {
    apply: async (patchId, payload = { confirm: true }) => {
      const res = await axiosInstance.post(`/patches/${encodeURIComponent(patchId)}/apply`, payload);
      return res.data;
    },
    verify: async (patchId) => {
      const res = await axiosInstance.post(`/patches/${encodeURIComponent(patchId)}/verify`);
      return res.data;
    },
  },
};

export default vulnexApi;

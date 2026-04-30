import axios, { AxiosError } from 'axios';
import { ApiError } from './errors';

/**
 * Single axios instance used by every feature's api layer.
 *   - withCredentials: backend sets an HTTP-only cookie on login; we need it sent back
 *   - 401 handler: bounce to /login with `next` param
 *   - Error envelope: backend returns `{ statusCode, message, error, path, timestamp }`
 *     — we re-throw as ApiError so ui code can switch on `.status` and `.code`.
 */
export const http = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL ?? '/api',
  withCredentials: true,
  timeout: 15_000,
});

http.interceptors.response.use(
  (r) => r,
  (error: AxiosError<{ statusCode: number; message: string; error?: string }>) => {
    const status = error.response?.status ?? 0;
    const body = error.response?.data;
    const message = body?.message ?? error.message ?? 'Request failed';

    if (status === 401 && typeof window !== 'undefined') {
      const current = window.location.pathname + window.location.search;
      const next = encodeURIComponent(current);
      // avoid loop from /login itself
      if (!window.location.pathname.startsWith('/login')) {
        window.location.replace(`/login?next=${next}`);
      }
    }

    return Promise.reject(new ApiError(message, status, body?.error));
  },
);

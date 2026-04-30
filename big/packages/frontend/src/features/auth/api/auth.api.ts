import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import { useAuthStore } from '@/stores/auth.store';
import type { MeDto } from '@cloudguard/shared';

/**
 * Session bootstrap. Call after login callback, on app load, and after role
 * changes. Populates the auth store so guards + usePermissions work.
 */
export function useMeQuery() {
  const setSession = useAuthStore((s) => s.setSession);
  return useQuery({
    queryKey: ['me'],
    queryFn: async () => {
      const { data } = await http.get<MeDto>('/auth/me');
      setSession(data, data.permissions);
      return data;
    },
    retry: false,
  });
}

export function useLogout() {
  const qc = useQueryClient();
  const clear = useAuthStore((s) => s.clear);
  return useMutation({
    mutationFn: async () => {
      await http.get('/auth/logout');
    },
    onSuccess: () => {
      clear();
      qc.clear();
      window.location.replace('/login');
    },
  });
}

/** URL to start Google OAuth. Full page redirect — not a fetch. */
export const GOOGLE_SIGN_IN_URL = `${import.meta.env.VITE_API_BASE_URL ?? '/api'}/auth/google`;
export const DEV_SIGN_IN_URL = `${import.meta.env.VITE_API_BASE_URL ?? '/api'}/auth/dev-login`;

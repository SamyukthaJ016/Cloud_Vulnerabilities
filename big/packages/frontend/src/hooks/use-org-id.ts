import { useAuthStore } from '@/stores/auth.store';

/** Shortcut for `useAuthStore(s => s.user?.orgId ?? null)`. */
export function useOrgId(): string | null {
  return useAuthStore((s) => s.user?.orgId ?? null);
}

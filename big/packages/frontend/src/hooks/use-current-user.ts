import { useAuthStore } from '@/stores/auth.store';

/** Returns the authenticated user (or null). Shortcut for components. */
export function useCurrentUser() {
  return useAuthStore((s) => s.user);
}

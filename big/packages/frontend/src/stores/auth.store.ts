import { create } from 'zustand';
import type { MeDto, PermissionKey } from '@cloudguard/shared';

interface AuthState {
  user: MeDto | null;
  permissions: PermissionKey[];
  setSession: (user: MeDto, permissions: PermissionKey[]) => void;
  clear: () => void;
}

/**
 * Minimal client-side auth state. The source of truth for "am I logged in"
 * is still the backend cookie + /auth/me — this store just caches it so
 * guards and UI don't re-fetch on every render.
 *
 * Populated by features/auth on /auth/me success. Cleared on /auth/logout.
 */
export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  permissions: [],
  setSession: (user, permissions) => set({ user, permissions }),
  clear: () => set({ user: null, permissions: [] }),
}));

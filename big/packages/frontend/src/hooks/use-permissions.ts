import { useAuthStore } from '@/stores/auth.store';
import type { PermissionKey } from '@cloudguard/shared';

/**
 * Returns `{ has, hasAny, hasAll }` for gating UI on the current user's
 * permissions. Use alongside the backend RBAC check — never trust UI-only gating.
 *
 * @example
 *   const { has } = usePermissions();
 *   if (!has('secret.write')) return <ReadOnlyView />;
 */
export function usePermissions() {
  const permissions = useAuthStore((s) => s.permissions);
  return {
    has: (key: PermissionKey) => permissions.includes(key),
    hasAny: (...keys: PermissionKey[]) => keys.some((k) => permissions.includes(k)),
    hasAll: (...keys: PermissionKey[]) => keys.every((k) => permissions.includes(k)),
  };
}

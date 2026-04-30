import { PropsWithChildren } from 'react';
import { Navigate } from 'react-router-dom';
import { useCurrentUser } from '@/hooks/use-current-user';
import type { SystemRoleKey } from '@cloudguard/shared';

/**
 * Gates a route by system role. RequireAuth must wrap the outer route already.
 */
export function RequireRole({
  role,
  children,
}: PropsWithChildren<{ role: SystemRoleKey | SystemRoleKey[] }>) {
  const user = useCurrentUser();
  const required = Array.isArray(role) ? role : [role];

  if (!user || !user.roleKey || !required.includes(user.roleKey as SystemRoleKey)) {
    return <Navigate to="/" replace />;
  }
  return <>{children}</>;
}

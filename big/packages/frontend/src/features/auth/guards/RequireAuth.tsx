import { PropsWithChildren } from 'react';
import { Navigate, useLocation } from 'react-router-dom';
import { useMeQuery } from '../api/auth.api';

/**
 * Wraps protected routes. Ensures /auth/me has been fetched; if not,
 * either waits for it or bounces to /login?next=<current>.
 */
export function RequireAuth({ children }: PropsWithChildren) {
  const location = useLocation();
  const { data, isLoading, isError } = useMeQuery();

  if (isLoading) {
    return <div className="p-8 text-center text-sm text-muted-foreground">Loading...</div>;
  }

  if (isError || !data) {
    const next = encodeURIComponent(location.pathname + location.search);
    return <Navigate to={`/login?next=${next}`} replace />;
  }

  if (!data.orgId) {
    return <Navigate to="/onboarding" replace />;
  }

  return <>{children}</>;
}

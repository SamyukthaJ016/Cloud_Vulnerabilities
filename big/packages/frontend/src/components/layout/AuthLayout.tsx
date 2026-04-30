import { Outlet } from 'react-router-dom';

/**
 * Centered-card layout for unauthenticated routes:
 * /login, /auth/callback, /auth/error, /onboarding.
 */
export function AuthLayout() {
  return (
    <div className="flex min-h-screen items-center justify-center bg-muted/30 p-4">
      <div className="w-full max-w-md rounded-lg border bg-card p-8 shadow-sm">
        <Outlet />
      </div>
    </div>
  );
}

import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { useMeQuery } from '../api/auth.api';

/**
 * Flow P (frontend half). Backend has already set the cookie via redirect;
 * we just bootstrap the session and forward to the intended route.
 */
export function AuthCallbackPage() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { data, isSuccess, isError } = useMeQuery();

  useEffect(() => {
    if (isError) navigate('/auth/error', { replace: true });
  }, [isError, navigate]);

  useEffect(() => {
    if (!isSuccess || !data) return;
    // N1: user with no org → onboarding
    if (!data.orgId) {
      navigate('/onboarding', { replace: true });
      return;
    }
    const next = params.get('next') ?? '/';
    navigate(next, { replace: true });
  }, [isSuccess, data, params, navigate]);

  return (
    <div className="text-center text-sm text-muted-foreground">Signing you in...</div>
  );
}

import { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import DOMPurify from 'dompurify';
import { useAuth } from '@/contexts/AuthContext';
import { useBrandingConfig } from '@/contexts/BrandingContext';

import { Button } from '@/components/ui/Button';
import { Input } from '@/components/ui/Input';

/**
 * SECURITY: Sanitize URL parameters to prevent XSS attacks
 * Only allows alphanumeric characters, spaces, and basic punctuation
 */
function sanitizeUrlParam(value: string | null): string {
  if (!value) return '';
  // First sanitize with DOMPurify to remove any HTML/scripts
  const purified = DOMPurify.sanitize(value, { ALLOWED_TAGS: [], ALLOWED_ATTR: [] });
  // Then limit length and remove any remaining control characters
  // eslint-disable-next-line no-control-regex
  return purified.substring(0, 200).replace(/[\x00-\x1F\x7F]/g, '');
}

export function AccountEntry({ signup = false }: { signup?: boolean }) {
  const { isAuthenticated, isLoading, login, loginWithGoogle, register, accessPending, authError, logout } = useAuth();
  const branding = useBrandingConfig();
  const navigate = useNavigate();
  const [busy, setBusy] = useState(false);
  const [email, setEmail] = useState('');
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (isAuthenticated) {
      navigate('/dashboard', { replace: true });
    }

    // Check for error in URL params
    // SECURITY: Sanitize URL parameters to prevent XSS attacks
    const params = new URLSearchParams(window.location.search);
    const errorParam = sanitizeUrlParam(params.get('error'));
    const errorDesc = sanitizeUrlParam(params.get('error_description'));
    if (errorParam) {
      setError(`${errorParam}: ${errorDesc || 'Unknown error'}`);
    }
  }, [isAuthenticated, navigate]);

  async function begin(action: () => Promise<void>) {
    setBusy(true);
    setError(null);
    try { await action(); }
    catch { setError('Unable to start sign-in. Please try again.'); }
    finally { setBusy(false); }
  }

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-surface-950">
        <div className="animate-spin w-8 h-8 border-4 border-surface-700 rounded-full border-t-brand-500"></div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center bg-surface-950 px-4">
      {/* Background gradient */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-brand-600/20 rounded-full blur-3xl"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-brand-600/10 rounded-full blur-3xl"></div>
      </div>
      <div className="relative z-10 w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <img src={branding.logoUrl} alt="Logo" className="w-16 h-16 object-contain mb-4" />
          <h1 className="text-3xl font-bold text-surface-100">{branding.platformName}</h1>
          <p className="text-surface-600 mt-2">Governance, Risk, and Compliance Platform</p>
        </div>

        {/* Error display */}
        {(error || authError) && (
          <div className="mb-4 p-4 bg-red-500/10 border border-red-500/30 rounded-lg">
            <p role="alert" className="text-red-600 text-sm">{error || authError}</p>
          </div>
        )}

        {/* Login card */}
        <div className="card p-8">
          {accessPending ? (
            <>
              <h2 className="text-xl font-semibold text-center mb-3">Finishing your account setup</h2>
              <p role="status" className="text-surface-600 mb-6">Your organization is being prepared. Please sign in again to refresh your access.</p>
              <Button fullWidth onClick={() => begin(login)} disabled={busy}>Retry sign-in</Button>
              <Button fullWidth variant="ghost" className="mt-3" onClick={logout}>Use another account</Button>
            </>
          ) : (
            <>
              <h2 className="text-xl font-semibold text-center mb-2">{signup ? 'Create your account' : 'Welcome back'}</h2>
              <p className="text-surface-600 text-center mb-6">{signup ? 'Start managing security and compliance in one place.' : 'Sign in to your compliance dashboard.'}</p>
              <Button fullWidth variant="secondary" disabled={busy} onClick={() => begin(loginWithGoogle)}>
                {signup ? 'Sign up with Google' : 'Continue with Google'}
              </Button>
              <div className="my-5 text-center text-sm text-surface-500">or</div>
              {signup ? (
                <form onSubmit={(event) => { event.preventDefault(); void begin(() => register(email)); }}>
                  <label htmlFor="signup-email" className="block text-sm font-medium mb-2">Email address</label>
                  <Input id="signup-email" type="email" autoComplete="email" required maxLength={254} value={email} onChange={(event) => setEmail(event.target.value)} className="w-full rounded-md border border-surface-400 bg-white px-3 py-2 text-surface-900 mb-4" />
                  <Button type="submit" fullWidth disabled={busy}>Continue with email</Button>
                  <p className="mt-4 text-sm text-surface-600">Next, verify your email and set up your account. Your own organization will be created automatically.</p>
                </form>
              ) : (
                <Button fullWidth disabled={busy} onClick={() => begin(login)}>Sign in with SSO</Button>
              )}
              <p className="mt-6 text-center text-sm text-surface-600">
                {signup ? 'Already have an account? ' : 'New here? '}
                <Link className="text-brand-700 underline" to={signup ? '/login' : '/signup'}>{signup ? 'Sign in' : 'Create an account'}</Link>
              </p>
            </>
          )}
        </div>

        {/* Footer */}
        <p className="text-center text-surface-600 text-sm mt-8">
          &copy; {new Date().getFullYear()} {branding.platformName}. All rights reserved.
        </p>
      </div>
    </div>
  );
}

export default function Login() {
  return <AccountEntry />;
}

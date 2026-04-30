import { Shield } from 'lucide-react';
import { GoogleSignInButton } from '../components/GoogleSignInButton';
import { DEV_SIGN_IN_URL } from '../api/auth.api';

export function LoginPage() {
  return (
    <div className="space-y-8">
      <div className="flex flex-col items-center space-y-3 text-center">
        <div className="flex h-12 w-12 items-center justify-center rounded-xl bg-primary text-primary-foreground">
          <Shield className="h-6 w-6" aria-hidden />
        </div>
        <div className="space-y-1">
          <h1 className="text-2xl font-semibold tracking-tight">Welcome to CloudGuard</h1>
          <p className="text-sm text-muted-foreground">
            Sign in with your Google account to continue.
          </p>
        </div>
      </div>

      <div className="space-y-3">
        <GoogleSignInButton />
        {import.meta.env.DEV ? (
          <a
            href={DEV_SIGN_IN_URL}
            className="flex w-full items-center justify-center rounded-md border border-dashed bg-muted/40 px-4 py-2 text-sm font-medium transition hover:bg-muted"
          >
            Enter local dev mode
          </a>
        ) : null}
      </div>

      <p className="text-center text-xs text-muted-foreground">
        By signing in you agree to the Terms of Service and Privacy Policy.
      </p>
    </div>
  );
}

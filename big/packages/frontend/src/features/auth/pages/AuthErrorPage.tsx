import { Link } from 'react-router-dom';

export function AuthErrorPage() {
  return (
    <div className="space-y-4 text-center">
      <h1 className="text-xl font-semibold">Sign-in failed</h1>
      <p className="text-sm text-muted-foreground">
        We couldn't complete your sign-in. Please try again.
      </p>
      <Link to="/login" className="text-sm font-medium text-primary underline">
        Back to sign in
      </Link>
    </div>
  );
}

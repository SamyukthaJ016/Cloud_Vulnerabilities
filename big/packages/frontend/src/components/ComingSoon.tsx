import { Link } from 'react-router-dom';
import { ArrowLeft, Construction } from 'lucide-react';

interface ComingSoonProps {
  title: string;
  description?: string;
  /** Flow-diagram nodes this page will eventually own — shown as a small hint. */
  flowNodes?: string;
}

/**
 * Placeholder used while a feature page is unimplemented.
 * Each feature page renders <ComingSoon ... /> until its real content lands.
 */
export function ComingSoon({ title, description, flowNodes }: ComingSoonProps) {
  return (
    <div className="flex min-h-[60vh] flex-col items-center justify-center px-6">
      <div className="mx-auto max-w-md space-y-5 text-center">
        <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-muted">
          <Construction className="h-7 w-7 text-muted-foreground" aria-hidden />
        </div>

        <div className="space-y-2">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          <p className="text-sm text-muted-foreground">
            {description ?? `The ${title} page is coming soon. We'll wire it up in a follow-up.`}
          </p>
        </div>

        {flowNodes && (
          <p className="text-xs text-muted-foreground">
            Flow diagram: <code className="rounded bg-muted px-1 py-0.5">{flowNodes}</code>
          </p>
        )}

        <Link
          to="/"
          className="inline-flex items-center gap-2 text-sm font-medium text-primary hover:underline"
        >
          <ArrowLeft className="h-4 w-4" />
          Back to overview
        </Link>
      </div>
    </div>
  );
}

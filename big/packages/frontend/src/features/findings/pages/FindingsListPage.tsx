import { Link } from 'react-router-dom';
import { AlertTriangle, Loader2 } from 'lucide-react';
import { format } from 'date-fns';
import { useFindingsQuery } from '../api/findings.api';
import { cn } from '@/lib/utils';

export function FindingsListPage() {
  const { data, isLoading, isError, error } = useFindingsQuery();

  if (isLoading) {
    return (
      <div className="flex min-h-[240px] items-center justify-center text-muted-foreground">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading findings…
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
        {error instanceof Error ? error.message : 'Failed to load findings.'}
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-7xl space-y-6">
      <header className="space-y-1">
        <h1 className="text-2xl font-semibold tracking-tight">Findings</h1>
        <p className="text-sm text-muted-foreground">
          Mirrored CloudGuard findings across your most recent cloud scans.
        </p>
      </header>

      {!data?.length ? (
        <div className="rounded-xl border bg-card p-10 text-center text-sm text-muted-foreground">
          <AlertTriangle className="mx-auto mb-3 h-5 w-5" />
          No findings are available yet. Run a scan in the main CloudGuard app and refresh this page.
        </div>
      ) : (
        <div className="overflow-hidden rounded-xl border bg-card">
          <div className="grid grid-cols-[120px_1fr_160px_180px] gap-4 border-b px-4 py-3 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
            <span>Severity</span>
            <span>Finding</span>
            <span>Scanner</span>
            <span>Created</span>
          </div>
          <div className="divide-y">
            {data.map((finding) => (
              <Link
                key={finding.id}
                to={`/findings/${finding.id}`}
                className="grid grid-cols-[120px_1fr_160px_180px] gap-4 px-4 py-4 text-sm hover:bg-muted/40"
              >
                <span>
                  <SeverityBadge severity={finding.severity} />
                </span>
                <span className="min-w-0">
                  <span className="block truncate font-medium">{finding.title}</span>
                  <span className="block truncate text-xs text-muted-foreground">
                    {finding.resource || finding.description || 'No extra context'}
                  </span>
                </span>
                <span className="capitalize text-muted-foreground">{finding.scannerKey}</span>
                <span className="text-muted-foreground">
                  {format(new Date(finding.createdAt), 'PPp')}
                </span>
              </Link>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const cls: Record<string, string> = {
    CRITICAL: 'bg-red-500/10 text-red-700',
    HIGH: 'bg-orange-500/10 text-orange-700',
    MEDIUM: 'bg-amber-500/10 text-amber-700',
    LOW: 'bg-blue-500/10 text-blue-700',
    INFO: 'bg-slate-500/10 text-slate-700',
  };

  return (
    <span className={cn('rounded-full px-2.5 py-1 text-xs font-medium', cls[severity] ?? cls.INFO)}>
      {severity.toLowerCase()}
    </span>
  );
}

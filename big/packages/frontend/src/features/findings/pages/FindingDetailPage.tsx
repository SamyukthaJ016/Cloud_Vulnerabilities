import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, Loader2 } from 'lucide-react';
import { format } from 'date-fns';
import { useFindingQuery } from '../api/findings.api';
import { cn } from '@/lib/utils';

export function FindingDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, isError, error } = useFindingQuery(id);

  if (isLoading) {
    return (
      <div className="flex min-h-[240px] items-center justify-center text-muted-foreground">
        <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading finding…
      </div>
    );
  }

  if (isError) {
    return (
      <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
        {error instanceof Error ? error.message : 'Failed to load finding.'}
      </div>
    );
  }

  if (!data) return null;

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <Link
        to="/findings"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to findings
      </Link>

      <header className="space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <SeverityBadge severity={data.severity} />
          <span className="rounded-full bg-muted px-2.5 py-1 text-xs font-medium capitalize text-muted-foreground">
            {data.scannerKey}
          </span>
        </div>
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">{data.title}</h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Captured {format(new Date(data.createdAt), 'PPpp')}
          </p>
        </div>
      </header>

      <section className="grid gap-4 sm:grid-cols-2">
        <Field label="Resource" value={data.resource ?? '—'} />
        <Field label="Status" value={data.status.toLowerCase()} />
        <Field label="External id" value={data.externalId ?? '—'} />
        <Field label="Scan job" value={data.scanJobId} mono />
      </section>

      <section className="rounded-xl border bg-card p-5">
        <h2 className="text-sm font-semibold">Description</h2>
        <p className="mt-3 whitespace-pre-wrap text-sm text-muted-foreground">
          {data.description ?? 'No description available.'}
        </p>
      </section>

      <section className="rounded-xl border bg-card p-5">
        <h2 className="text-sm font-semibold">Evidence</h2>
        <pre className="mt-3 overflow-x-auto rounded-lg bg-muted p-4 text-xs text-muted-foreground">
          {JSON.stringify(data.evidence ?? {}, null, 2)}
        </pre>
      </section>

      <section className="rounded-xl border bg-card p-5">
        <h2 className="text-sm font-semibold">Recommendation</h2>
        <p className="mt-3 whitespace-pre-wrap text-sm text-muted-foreground">
          {data.recommendation ?? 'Recommendation was not provided by the upstream scan.'}
        </p>
      </section>
    </div>
  );
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="rounded-md border bg-card p-3">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className={cn('mt-1 text-sm font-medium', mono && 'font-mono text-xs')}>{value}</p>
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

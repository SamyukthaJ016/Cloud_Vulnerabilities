import { Link, useParams } from 'react-router-dom';
import { ArrowLeft, ExternalLink, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { format } from 'date-fns';
import type { ScanStatus } from '@cloudguard/shared';
import { fetchScanReportUrl, useScanQuery } from '../api/scans.api';

export function ScanDetailPage() {
  const { id } = useParams<{ id: string }>();
  const { data, isLoading, isError, error } = useScanQuery(id);

  const handleViewReport = async () => {
    if (!id) return;
    try {
      const url = await fetchScanReportUrl(id);
      window.location.assign(url);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not open report');
    }
  };

  return (
    <div className="mx-auto max-w-4xl space-y-6">
      <Link
        to="/scans"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-4 w-4" /> Back to scans
      </Link>

      {isLoading && (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading…
        </div>
      )}

      {isError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {error instanceof Error ? error.message : 'Failed to load scan'}
        </div>
      )}

      {data && (
        <div className="space-y-6">
          <header className="flex flex-wrap items-end justify-between gap-3">
            <div>
              <h1 className="text-2xl font-semibold tracking-tight">{data.scannerKey}</h1>
              <p className="text-sm text-muted-foreground">
                Triggered by {data.triggeredBy.name ?? data.triggeredBy.email} on{' '}
                {format(new Date(data.queuedAt), 'PPpp')}
              </p>
            </div>
            <StatusPill status={data.status} />
          </header>

          <section className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Field label="External scan id" value={data.externalScanId ?? '—'} />
            <Field
              label="Started"
              value={data.startedAt ? format(new Date(data.startedAt), 'PPpp') : '—'}
            />
            <Field
              label="Completed"
              value={data.completedAt ? format(new Date(data.completedAt), 'PPpp') : '—'}
            />
            <Field label="Error" value={data.error ?? '—'} />
          </section>

          {data.summary && (
            <section className="rounded-xl border bg-card p-5">
              <h2 className="text-sm font-semibold">Findings summary</h2>
              <dl className="mt-3 grid grid-cols-5 gap-3 text-center">
                {Object.entries(data.summary).map(([sev, count]) => (
                  <div key={sev} className="rounded-md border bg-background p-3">
                    <dt className="text-xs uppercase text-muted-foreground">{sev}</dt>
                    <dd className="mt-1 text-xl font-semibold">{count}</dd>
                  </div>
                ))}
              </dl>
            </section>
          )}

          {data.status === 'COMPLETED' && (
            <button
              type="button"
              onClick={handleViewReport}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
            >
              <ExternalLink className="h-4 w-4" /> View report on scanner dashboard
            </button>
          )}
        </div>
      )}
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-md border bg-card p-3">
      <p className="text-xs uppercase tracking-wide text-muted-foreground">{label}</p>
      <p className="mt-1 truncate text-sm font-medium">{value}</p>
    </div>
  );
}

function StatusPill({ status }: { status: ScanStatus }) {
  const cls = STATUS_CLASS[status];
  return (
    <span className={`inline-flex rounded-full px-2.5 py-1 text-xs font-medium ${cls}`}>
      {status.toLowerCase()}
    </span>
  );
}

const STATUS_CLASS: Record<ScanStatus, string> = {
  DISPATCHED: 'bg-blue-500/10 text-blue-600',
  RUNNING: 'bg-amber-500/10 text-amber-700',
  COMPLETED: 'bg-emerald-500/10 text-emerald-700',
  FAILED: 'bg-destructive/10 text-destructive',
};

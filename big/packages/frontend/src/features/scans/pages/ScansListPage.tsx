import { Link } from 'react-router-dom';
import { ExternalLink, Loader2 } from 'lucide-react';
import { toast } from 'sonner';
import { formatDistanceToNow } from 'date-fns';
import type { ScanJobDto, ScanStatus } from '@cloudguard/shared';
import { fetchScanReportUrl, useScansQuery } from '../api/scans.api';

export function ScansListPage() {
  const { data, isLoading, isError, error } = useScansQuery();

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <header>
        <h1 className="text-2xl font-semibold tracking-tight">Scans</h1>
        <p className="text-sm text-muted-foreground">
          History of every scan triggered for this organization.
        </p>
      </header>

      {isLoading && (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading…
        </div>
      )}

      {isError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          Failed to load scans: {error instanceof Error ? error.message : 'unknown error'}
        </div>
      )}

      {data && data.length === 0 && (
        <div className="rounded-md border bg-card p-8 text-center text-sm text-muted-foreground">
          No scans yet. Start one from the <Link to="/scanners" className="underline">Scanners</Link> tab.
        </div>
      )}

      {data && data.length > 0 && (
        <div className="overflow-hidden rounded-xl border bg-card">
          <table className="w-full text-sm">
            <thead className="border-b bg-muted/40 text-left text-xs uppercase tracking-wide text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5">Scanner</th>
                <th className="px-4 py-2.5">Status</th>
                <th className="px-4 py-2.5">Started</th>
                <th className="px-4 py-2.5">By</th>
                <th className="px-4 py-2.5">
                  <span className="sr-only">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {data.map((scan) => (
                <ScanRow key={scan.id} scan={scan} />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function ScanRow({ scan }: { scan: ScanJobDto }) {
  const handleViewReport = async () => {
    try {
      const url = await fetchScanReportUrl(scan.id);
      window.location.assign(url);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Could not open report');
    }
  };

  return (
    <tr className="border-b last:border-0 hover:bg-muted/20">
      <td className="px-4 py-3 font-medium">
        <Link to={`/scans/${scan.id}`} className="hover:underline">
          {scan.scannerKey}
        </Link>
      </td>
      <td className="px-4 py-3">
        <StatusPill status={scan.status} />
      </td>
      <td className="px-4 py-3 text-muted-foreground">
        {scan.startedAt
          ? formatDistanceToNow(new Date(scan.startedAt), { addSuffix: true })
          : '—'}
      </td>
      <td className="px-4 py-3 text-muted-foreground">
        {scan.triggeredBy.name ?? scan.triggeredBy.email}
      </td>
      <td className="px-4 py-3 text-right">
        {scan.status === 'COMPLETED' && (
          <button
            type="button"
            onClick={handleViewReport}
            className="inline-flex items-center gap-1.5 rounded-md border bg-background px-2.5 py-1.5 text-xs font-medium hover:bg-muted"
          >
            <ExternalLink className="h-3.5 w-3.5" />
            View report
          </button>
        )}
      </td>
    </tr>
  );
}

function StatusPill({ status }: { status: ScanStatus }) {
  const cls = STATUS_CLASS[status];
  return (
    <span className={`inline-flex rounded-full px-2 py-0.5 text-xs font-medium ${cls}`}>
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

import { useState } from 'react';
import { AlertCircle, Cloud, ExternalLink, Loader2, Play, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import type { ScannerDto } from '@cloudguard/shared';
import { useScannersQuery, useRefreshScanners } from '../api/scanners.api';
import { ScanModal } from '../components/ScanModal';

export function ScannersPage() {
  const { data, isLoading, isError, error } = useScannersQuery();
  const refresh = useRefreshScanners();
  const [active, setActive] = useState<ScannerDto | null>(null);
  const cloudProjectUrl =
    import.meta.env.VITE_MAIN_PROJECT_URL || 'https://cloud-vulnerabilities.vercel.app';

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Scanners</h1>
          <p className="text-sm text-muted-foreground">
            Pick a scanner, enter credentials, and run a scan. Catalog is loaded from each
            scanner's manifest at startup.
          </p>
        </div>
        <button
          type="button"
          disabled={refresh.isPending}
          onClick={async () => {
            try {
              const results = await refresh.mutateAsync();
              const ok = results.filter((r) => r.availability === 'AVAILABLE').length;
              toast.success(`Refreshed ${ok}/${results.length} scanners`);
            } catch {
              toast.error('Refresh failed');
            }
          }}
          className="inline-flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-sm font-medium hover:bg-muted disabled:opacity-50"
        >
          <RefreshCw className={`h-4 w-4 ${refresh.isPending ? 'animate-spin' : ''}`} />
          Refresh manifests
        </button>
      </header>

      {isLoading && (
        <div className="flex items-center justify-center py-16 text-muted-foreground">
          <Loader2 className="mr-2 h-4 w-4 animate-spin" /> Loading scanners…
        </div>
      )}

      {isError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          Failed to load scanners: {error instanceof Error ? error.message : 'unknown error'}
        </div>
      )}

      {data && (
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <CloudTile href={cloudProjectUrl} />
          {data.map((s) => (
            <ScannerTile key={s.id} scanner={s} onRun={() => setActive(s)} />
          ))}
        </div>
      )}

      {data && data.length === 0 && (
        <div className="rounded-md border bg-card p-8 text-center text-sm text-muted-foreground">
          No scanners discovered yet. The Cloud tile is available now; configure{' '}
          <code className="rounded bg-muted px-1">SCANNER_N_BASE_URL</code> env vars if you want
          additional scanner tiles.
        </div>
      )}

      <ScanModal scanner={active} onClose={() => setActive(null)} />
    </div>
  );
}

function CloudTile({ href }: { href: string }) {
  return (
    <div className="flex flex-col rounded-xl border bg-card p-5">
      <div className="flex items-start gap-3">
        <div className="flex h-10 w-10 items-center justify-center rounded bg-sky-100 text-sky-700 dark:bg-sky-500/15 dark:text-sky-300">
          <Cloud className="h-5 w-5" aria-hidden />
        </div>
        <div className="min-w-0 flex-1">
          <h2 className="truncate text-base font-semibold">Cloud</h2>
          <p className="text-xs uppercase tracking-wide text-muted-foreground">AWS, GCP, K8s, IaC</p>
        </div>
      </div>

      <p className="mt-3 line-clamp-3 text-sm text-muted-foreground">
        Open the main CloudGuard scanner application for cloud posture checks, findings, and scan
        workflows.
      </p>

      <div className="mt-auto pt-4">
        <a
          href={href}
          target="_blank"
          rel="noreferrer"
          className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
        >
          <ExternalLink className="h-4 w-4" /> Open Cloud
        </a>
      </div>
    </div>
  );
}

function ScannerTile({
  scanner,
  onRun,
}: {
  scanner: ScannerDto;
  onRun: () => void;
}) {
  const unavailable = scanner.availability === 'UNAVAILABLE';
  return (
    <div className="flex flex-col rounded-xl border bg-card p-5">
      <div className="flex items-start gap-3">
        {scanner.iconUrl ? (
          <img src={scanner.iconUrl} alt="" className="h-10 w-10 rounded" />
        ) : (
          <div className="h-10 w-10 rounded bg-muted" />
        )}
        <div className="min-w-0 flex-1">
          <h2 className="truncate text-base font-semibold">{scanner.name}</h2>
          {scanner.category && (
            <p className="text-xs uppercase tracking-wide text-muted-foreground">
              {scanner.category}
            </p>
          )}
        </div>
      </div>

      <p className="mt-3 line-clamp-3 text-sm text-muted-foreground">
        {scanner.description ?? 'No description provided.'}
      </p>

      {unavailable && (
        <div className="mt-3 flex items-start gap-2 rounded-md bg-amber-500/10 px-3 py-2 text-xs text-amber-700 dark:text-amber-400">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <span title={scanner.lastError ?? undefined}>
            Unavailable{scanner.lastError ? ` — ${scanner.lastError}` : ''}
          </span>
        </div>
      )}

      <div className="mt-auto pt-4">
        <button
          type="button"
          onClick={onRun}
          disabled={unavailable}
          className="inline-flex w-full items-center justify-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90 disabled:opacity-50"
        >
          <Play className="h-4 w-4" /> Run scan
        </button>
      </div>
    </div>
  );
}

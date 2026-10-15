import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { cloudGuardApi } from '@/lib/api/cloudguard.api';

export default function CloudGuardOverview() {
  const query = useQuery({
    queryKey: ['cloudguard-connector-dashboard'],
    queryFn: cloudGuardApi.dashboard,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });
  const scan = query.isError ? undefined : query.data?.latest_scan;
  return (
    <section className="card p-5" aria-label="CloudGuard scan findings">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-surface-100">CloudGuard Scan Findings</h2>
          <p className="mt-1 text-sm text-surface-400">
            {query.isPending ? 'Checking the scanner connector…' : query.isError
              ? 'Scanner connector unavailable. Findings could not be loaded.'
              : scan ? `Last completed scan #${scan.id} · ${scan.provider.toUpperCase()}`
                : 'No completed scanner scan is available.'}
          </p>
        </div>
        <Link to="/cloudguard-grc" className="btn-primary">View Scanner Findings</Link>
      </div>
      {scan && (
        <div className="mt-4 grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[
            ['Findings', scan.finding_count],
            ['Resources', scan.resource_count],
            ['Critical', scan.severity_counts.critical],
            ['High', scan.severity_counts.high],
          ].map(([label, count]) => (
            <div key={label} className="rounded-lg border border-surface-700 p-3">
              <p className="text-sm text-surface-400">{label}</p>
              <p className="mt-1 text-2xl font-semibold text-surface-100">{count}</p>
            </div>
          ))}
        </div>
      )}
      <p className="mt-4 text-sm text-surface-400">Scanner findings are available in the connector. Saving them in GRC Evidence and the Risk Register requires an import.</p>
    </section>
  );
}

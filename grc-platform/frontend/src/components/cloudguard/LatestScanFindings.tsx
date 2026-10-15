import { useState } from 'react';
import type { CloudGuardScanSnapshot } from '@/lib/api/cloudguard.api';

export default function LatestScanFindings({ scan }: { scan: CloudGuardScanSnapshot | null | undefined }) {
  const [search, setSearch] = useState('');
  if (!scan) return <section className="card p-5"><h2 className="text-lg font-semibold">Latest Scanner Findings</h2><p className="mt-2 text-surface-400">No completed scan is available.</p></section>;
  const findings = scan.findings.filter(f => `${f.title} ${f.resource} ${f.severity}`.toLowerCase().includes(search.toLowerCase()));
  return (
    <section className="card p-5" aria-label="Latest scanner findings">
      <h2 className="text-lg font-semibold text-surface-100">Latest Scanner Findings</h2>
      <p className="mt-1 text-sm text-surface-400">Scan #{scan.id} · {scan.provider.toUpperCase()} · {scan.finding_count} findings across {scan.resource_count} resources</p>
      <label className="mt-4 block text-sm text-surface-400">
        Search findings
        <input value={search} onChange={e => setSearch(e.target.value)} className="input mt-1 w-full" placeholder="Finding, resource, or severity" />
      </label>
      <div className="mt-4 overflow-x-auto">
        <table className="min-w-full divide-y divide-surface-700 text-left text-sm">
          <thead><tr><th className="p-3">Severity</th><th className="p-3">Finding</th><th className="p-3">Resource</th><th className="p-3">Scanner</th></tr></thead>
          <tbody className="divide-y divide-surface-800">
            {findings.map(f => <tr key={f.id}><td className="p-3 font-semibold uppercase">{f.severity}</td><td className="p-3" title={f.description}>{f.title}</td><td className="p-3">{typeof f.resource === 'string' ? f.resource : JSON.stringify(f.resource)}</td><td className="p-3">{f.tool || f.provider}</td></tr>)}
          </tbody>
        </table>
        {!findings.length && <p className="py-5 text-surface-400">{scan.finding_count ? 'No findings match this search.' : 'This scan reported no findings.'}</p>}
      </div>
    </section>
  );
}

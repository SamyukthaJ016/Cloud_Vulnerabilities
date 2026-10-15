import { useMutation, useQueryClient } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { useAuth } from '@/contexts/AuthContext';
import { cloudGuardApi, type CloudGuardScanSnapshot } from '@/lib/api/cloudguard.api';
import { Button } from '@/components/ui/Button';

export default function ImportScan({ scan }: { scan?: CloudGuardScanSnapshot | null }) {
  const { hasRole } = useAuth();
  const queryClient = useQueryClient();
  const canImport = hasRole('admin') || hasRole('compliance_manager');
  const mutation = useMutation({
    mutationFn: (scanId: number) => cloudGuardApi.importLatest(scanId),
    onSuccess: () => {
      for (const key of ['dashboard-full', 'dashboard-summary', 'risks', 'risk-dashboard', 'evidence']) {
        void queryClient.invalidateQueries({ queryKey: [key] });
      }
    },
  });
  const error = mutation.error as { response?: { data?: { message?: string | string[] } }; message?: string } | null;
  const message = error?.response?.data?.message || error?.message;
  return (
    <section className="card p-5" aria-label="Import scanner findings">
      <h2 className="text-lg font-semibold text-surface-100">Import Latest Scan into GRC</h2>
      <p className="mt-2 text-sm text-surface-400">
        Save a downloadable evidence report and register the scan's non-informational findings as risks awaiting review.
        Repeated imports preserve existing risk assessments and avoid duplicates.
      </p>
      {scan && <p className="mt-2 text-sm">Scan #{scan.id} · {scan.finding_count} findings · {scan.severity_counts.info} informational observations retained in the report</p>}
      {!canImport && <p className="mt-3 text-sm text-amber-400">Import requires an administrator or compliance manager with permission to create risks. Your current account can view the findings.</p>}
      <Button type="button" className="mt-4" disabled={!canImport || !scan || mutation.isPending} onClick={() => scan && mutation.mutate(scan.id)}>
        {mutation.isPending ? 'Importing scan…' : 'Import into Evidence and Risk Register'}
      </Button>
      {mutation.isError && <p role="alert" className="mt-3 text-sm text-rose-400">{Array.isArray(message) ? message.join(' ') : message || 'Import failed. Please try again.'}</p>}
      {mutation.data && <div role="status" className="mt-3 space-y-2 text-sm">
        <p>Scan #{mutation.data.scanId}: {mutation.data.createdRisks} new risks, {mutation.data.existingRisks} existing risks. {mutation.data.informationalFindings} informational observations retained in the evidence report.</p>
        {!!mutation.data.deletedRisksSkipped && <p>{mutation.data.deletedRisksSkipped} previously deleted risks were left unchanged.</p>}
        <div className="flex gap-4"><Link className="text-brand-400 underline" to={`/evidence/${mutation.data.evidenceId}`}>Open Evidence Report</Link><Link className="text-brand-400 underline" to="/risks">Open Risk Register</Link></div>
      </div>}
    </section>
  );
}

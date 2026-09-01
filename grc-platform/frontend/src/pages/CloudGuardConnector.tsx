import { useMemo } from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  ArrowPathIcon,
  CheckCircleIcon,
  CloudIcon,
  DocumentCheckIcon,
  ExclamationTriangleIcon,
  ShieldCheckIcon,
  SignalSlashIcon,
} from '@heroicons/react/24/outline';
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts';
import clsx from 'clsx';
import {
  cloudGuardApi,
  CloudGuardControl,
  CloudGuardFinding,
  CloudGuardSeverity,
} from '@/lib/api/cloudguard.api';

const pipelineSteps = [
  'Scanner Job',
  'Connector Normalization',
  'Evidence Ingestion',
  'Risk Scoring',
  'Control Mapping',
  'Audit Review',
];

const severityRank: Record<CloudGuardSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const familyRules = [
  { family: 'Policy and Governance', terms: ['policy', 'governance', 'dpdp'] },
  { family: 'Asset Management', terms: ['asset', 'inventory', 'resource'] },
  { family: 'Access Control', terms: ['access', 'identity', 'iam', 'mfa', 'authentication'] },
  { family: 'Data Protection', terms: ['data', 'storage', 'encrypt', 'bucket', 'database'] },
  { family: 'Network Security', terms: ['network', 'ingress', 'port', 'firewall', 'security group'] },
  { family: 'Incident Response', terms: ['incident', 'response', 'recovery'] },
  { family: 'Vulnerability Management', terms: ['vulnerab', 'owasp', 'component', 'patch', 'iac'] },
  { family: 'Logging and Monitoring', terms: ['log', 'audit', 'monitor', 'trail'] },
];

function controlFamily(control: CloudGuardControl) {
  const haystack = `${control.control_id} ${control.control_name} ${control.framework}`.toLowerCase();
  return familyRules.find((rule) => rule.terms.some((term) => haystack.includes(term)))?.family
    || 'Policy and Governance';
}

function controlWeight(status: CloudGuardControl['status']) {
  if (status === 'compliant') return 100;
  if (status === 'partial') return 50;
  return 0;
}

function controlStatus(controls: CloudGuardControl[]) {
  if (!controls.length || controls.every((control) => control.status === 'no_evidence')) return 'No Evidence';
  if (controls.some((control) => control.status === 'non_compliant')) return 'Failed';
  if (controls.some((control) => control.status === 'partial')) return 'Needs Review';
  return 'Approved';
}

function displayName(value: string) {
  return value
    .replace(/[_-]+/g, ' ')
    .replace(/\b\w/g, (character) => character.toUpperCase());
}

function latestLabel(value?: string | null) {
  if (!value) return 'No sync recorded';
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
}

function findingAuditStatus(status: CloudGuardControl['status']) {
  if (status === 'non_compliant') return 'Failed';
  if (status === 'partial') return 'Needs Review';
  if (status === 'compliant') return 'Approved';
  return 'No Evidence';
}

export default function CloudGuardConnector() {
  const dashboardQuery = useQuery({
    queryKey: ['cloudguard-connector-dashboard'],
    queryFn: cloudGuardApi.dashboard,
    refetchInterval: 30_000,
    refetchOnWindowFocus: true,
  });

  const dashboard = dashboardQuery.data;
  const compliance = dashboard?.compliance;
  const workers = dashboard?.workers;

  const connectorHealth = useMemo(() => {
    if (!dashboard || !compliance || !workers) return [];

    const workerRows = workers.workers.map((worker) => ({
      name: displayName(worker.worker_id),
      mode: `${displayName(worker.worker_type)} worker`,
      status: worker.online ? 'Connected' : 'Offline',
      lastSync: latestLabel(worker.last_seen_at),
      evidence: null as number | null,
    }));
    const sourceRows = Object.entries(compliance.source_counts).map(([source, evidence]) => ({
      name: displayName(source),
      mode: 'Evidence source',
      status: 'Connected',
      lastSync: latestLabel(compliance.generated_at),
      evidence,
    }));

    return [
      {
        name: 'CloudGuard API Connector',
        mode: 'Protected server connector',
        status: 'Connected',
        lastSync: latestLabel(dashboard.generated_at),
        evidence: compliance.counts.evidence_artifacts,
      },
      ...workerRows,
      ...sourceRows,
    ];
  }, [dashboard, compliance, workers]);

  const controlFamilies = useMemo(() => {
    const controls = compliance?.controls || [];
    return familyRules.map(({ family }) => {
      const familyControls = controls.filter((control) => controlFamily(control) === family);
      const assessed = familyControls.filter((control) => control.status !== 'no_evidence');
      const score = assessed.length
        ? Math.round(assessed.reduce((sum, control) => sum + controlWeight(control.status), 0) / assessed.length)
        : 0;
      return {
        family,
        score,
        findings: familyControls.reduce((sum, control) => sum + control.finding_count, 0),
        evidence: familyControls.reduce((sum, control) => sum + control.evidence_count, 0),
        status: controlStatus(familyControls),
      };
    });
  }, [compliance]);

  const fixFirst = useMemo(() => {
    const rows = (compliance?.controls || []).flatMap((control) =>
      (control.sample_findings || []).map((finding: CloudGuardFinding) => ({
        finding: finding.title,
        source: control.sources.length ? control.sources.map(displayName).join(', ') : displayName(control.framework),
        control: controlFamily(control),
        risk: displayName(finding.severity),
        severity: finding.severity,
        audit: findingAuditStatus(control.status),
        fix: finding.recommendation || 'Review the affected resource and apply the mapped control guidance.',
      }))
    );

    return rows
      .sort((left, right) => severityRank[left.severity] - severityRank[right.severity])
      .slice(0, 8)
      .map((row, index) => ({ ...row, priority: index + 1 }));
  }, [compliance]);

  const severityBySource = useMemo(
    () => Object.entries(compliance?.severity_by_source || {}).map(([source, counts]) => ({
      source: displayName(source),
      ...counts,
    })),
    [compliance]
  );

  const evidenceSplit = useMemo(() => {
    const counts = compliance?.evidence_review_counts;
    return [
      { name: 'System Generated', value: counts?.system_generated || 0, color: '#0891b2' },
      { name: 'Manual Uploaded', value: counts?.manual_uploaded || 0, color: '#2563eb' },
      { name: 'Pending Review', value: counts?.pending_review || 0, color: '#d97706' },
      { name: 'Approved', value: counts?.approved || 0, color: '#059669' },
    ];
  }, [compliance]);

  const evidenceTotal = evidenceSplit.reduce((sum, item) => sum + item.value, 0);
  const connectorCount = Object.keys(compliance?.source_counts || {}).length;

  return (
    <div className="space-y-6 animate-fade-in">
      <section className="relative overflow-hidden rounded-lg border border-surface-800 bg-surface-900 p-6">
        <div className="absolute inset-x-0 top-0 h-1 bg-cyan-500" />
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-xs font-bold uppercase text-brand-400">Live GRC Connector</p>
            <h1 className="mt-2 text-3xl font-bold text-surface-100">CloudGuard Evidence and Compliance</h1>
            <p className="mt-2 max-w-3xl text-sm text-surface-500">
              Scanner jobs stay independent while this view reads their normalized evidence, maps it to controls,
              and prioritizes the findings that need action.
            </p>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            <Metric label="Compliance" value={`${Math.round(compliance?.score || 0)}%`} />
            <Metric label="Evidence" value={String(compliance?.counts.evidence_artifacts || 0)} />
            <Metric label="Open Risks" value={String(compliance?.counts.findings || 0)} />
            <Metric label="Sources" value={String(connectorCount)} />
          </div>
        </div>
        <div className="mt-5 flex flex-wrap items-center gap-3 border-t border-surface-800 pt-4 text-sm">
          <span className={clsx(
            'inline-flex items-center gap-2 font-medium',
            workers?.scan_workers_online ? 'text-emerald-300' : 'text-amber-300'
          )}>
            {workers?.scan_workers_online
              ? <CheckCircleIcon className="h-5 w-5" />
              : <SignalSlashIcon className="h-5 w-5" />}
            Scanner workers {workers?.scan_workers_online ? 'online' : 'offline'}
          </span>
          <span className="text-surface-600">Last refreshed {latestLabel(dashboard?.generated_at)}</span>
          <button
            type="button"
            onClick={() => dashboardQuery.refetch()}
            className="btn-secondary ml-auto inline-flex items-center gap-2"
            disabled={dashboardQuery.isFetching}
          >
            <ArrowPathIcon className={clsx('h-4 w-4', dashboardQuery.isFetching && 'animate-spin')} />
            Refresh
          </button>
        </div>
      </section>

      {dashboardQuery.isError && (
        <section className="rounded-lg border border-rose-500/40 bg-rose-500/10 p-5">
          <div className="flex items-start gap-3">
            <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 text-rose-300" />
            <div>
              <h2 className="font-semibold text-rose-100">CloudGuard data is unavailable</h2>
              <p className="mt-1 text-sm text-rose-200/80">
                Check the connector URL, connector token, and CloudGuard backend health. No demo findings are shown as a fallback.
              </p>
            </div>
          </div>
        </section>
      )}

      <section className="grid gap-6 xl:grid-cols-[1.1fr_0.9fr]">
        <div className="card p-5">
          <h2 className="text-lg font-semibold text-surface-100">Evidence Pipeline</h2>
          <p className="text-sm text-surface-500">How an independent scanner result becomes audit-ready evidence.</p>
          <div className="mt-6 grid gap-3 md:grid-cols-6">
            {pipelineSteps.map((step, index) => (
              <div key={step} className="rounded-lg border border-surface-800 bg-surface-950 p-3">
                <div className="mb-3 flex h-8 w-8 items-center justify-center rounded-full bg-brand-500/15 text-sm font-bold text-brand-300">
                  {index + 1}
                </div>
                <p className="text-sm font-medium text-surface-200">{step}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="card p-5">
          <h2 className="text-lg font-semibold text-surface-100">Evidence Review State</h2>
          <p className="text-sm text-surface-500">Current evidence classification from CloudGuard metadata.</p>
          {evidenceTotal ? (
            <div className="mt-4 h-64">
              <ResponsiveContainer>
                <PieChart>
                  <Pie data={evidenceSplit} innerRadius={58} outerRadius={92} dataKey="value" paddingAngle={3}>
                    {evidenceSplit.map((entry) => <Cell key={entry.name} fill={entry.color} />)}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState text="No evidence has been ingested for this CloudGuard user yet." />
          )}
          <div className="grid grid-cols-2 gap-2">
            {evidenceSplit.map((item) => (
              <div key={item.name} className="flex items-center gap-2 text-xs text-surface-400">
                <span className="h-2.5 w-2.5 rounded-full" style={{ background: item.color }} />
                {item.name}: {item.value}
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="grid gap-6 xl:grid-cols-[0.95fr_1.05fr]">
        <div className="card p-5">
          <h2 className="text-lg font-semibold text-surface-100">Connector Health</h2>
          <div className="mt-4 overflow-x-auto rounded-lg border border-surface-800">
            <table className="min-w-full divide-y divide-surface-800 text-sm">
              <thead className="bg-surface-800/70 text-left text-xs uppercase text-surface-500">
                <tr>
                  <th className="px-4 py-3">Connector</th>
                  <th className="px-4 py-3">Mode</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Evidence</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-800">
                {connectorHealth.map((connector) => (
                  <tr key={`${connector.mode}-${connector.name}`}>
                    <td className="px-4 py-3 text-surface-200">
                      <div className="font-medium">{connector.name}</div>
                      <div className="text-xs text-surface-600">{connector.lastSync}</div>
                    </td>
                    <td className="px-4 py-3 text-surface-500">{connector.mode}</td>
                    <td className="px-4 py-3"><StatusPill value={connector.status} /></td>
                    <td className="px-4 py-3 font-semibold text-surface-200">{connector.evidence ?? '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
            {!connectorHealth.length && <EmptyState text="Waiting for the first successful connector sync." />}
          </div>
        </div>

        <div className="card p-5">
          <h2 className="text-lg font-semibold text-surface-100">Risk by Evidence Source</h2>
          <p className="text-sm text-surface-500">Severity totals calculated from current normalized findings.</p>
          {severityBySource.length ? (
            <div className="mt-4 h-80">
              <ResponsiveContainer>
                <BarChart data={severityBySource}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#263238" />
                  <XAxis dataKey="source" stroke="#94a3b8" />
                  <YAxis stroke="#94a3b8" allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="critical" stackId="a" fill="#e11d48" />
                  <Bar dataKey="high" stackId="a" fill="#ea580c" />
                  <Bar dataKey="medium" stackId="a" fill="#ca8a04" />
                  <Bar dataKey="low" stackId="a" fill="#16a34a" />
                </BarChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <EmptyState text="No normalized findings are available for charting." />
          )}
        </div>
      </section>

      <section className="card p-5">
        <div className="flex items-center gap-2">
          <ShieldCheckIcon className="h-5 w-5 text-brand-400" />
          <h2 className="text-lg font-semibold text-surface-100">MSME Control Mapping</h2>
        </div>
        <p className="mt-1 text-sm text-surface-500">Live CloudGuard controls grouped into operational security families.</p>
        <div className="mt-4 grid gap-3 md:grid-cols-2 xl:grid-cols-4">
          {controlFamilies.map((control) => (
            <div key={control.family} className="rounded-lg border border-surface-800 bg-surface-950 p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <h3 className="font-semibold text-surface-100">{control.family}</h3>
                  <p className="mt-1 text-xs text-surface-600">
                    {control.findings} findings · {control.evidence} evidence
                  </p>
                </div>
                <StatusPill value={control.status} />
              </div>
              <div className="mt-4 h-2 rounded-full bg-surface-800">
                <div
                  className={clsx(
                    'h-2 rounded-full',
                    control.score >= 70 ? 'bg-emerald-500' : control.score >= 50 ? 'bg-amber-500' : 'bg-rose-500'
                  )}
                  style={{ width: `${control.score}%` }}
                />
              </div>
              <p className="mt-2 text-sm font-semibold text-surface-200">{control.score}% compliant</p>
            </div>
          ))}
        </div>
      </section>

      <section className="card p-5">
        <div className="flex items-center gap-2">
          <ExclamationTriangleIcon className="h-5 w-5 text-amber-300" />
          <h2 className="text-lg font-semibold text-surface-100">What To Fix First</h2>
        </div>
        {fixFirst.length ? (
          <div className="mt-4 overflow-x-auto rounded-lg border border-surface-800">
            <table className="min-w-full divide-y divide-surface-800 text-sm">
              <thead className="bg-surface-800/70 text-left text-xs uppercase text-surface-500">
                <tr>
                  <th className="px-4 py-3">Priority</th>
                  <th className="px-4 py-3">Finding</th>
                  <th className="px-4 py-3">Source</th>
                  <th className="px-4 py-3">Control Family</th>
                  <th className="px-4 py-3">Risk</th>
                  <th className="px-4 py-3">Audit</th>
                  <th className="px-4 py-3">Remediation</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-800">
                {fixFirst.map((item) => (
                  <tr key={`${item.priority}-${item.finding}`}>
                    <td className="px-4 py-3 font-bold text-surface-100">#{item.priority}</td>
                    <td className="px-4 py-3 font-medium text-surface-100">{item.finding}</td>
                    <td className="px-4 py-3 text-surface-500">{item.source}</td>
                    <td className="px-4 py-3 text-surface-300">{item.control}</td>
                    <td className="px-4 py-3"><RiskPill value={item.risk} /></td>
                    <td className="px-4 py-3"><StatusPill value={item.audit} /></td>
                    <td className="px-4 py-3 text-surface-500">{item.fix}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <EmptyState text="No actionable findings have been ingested. Run a scanner job to populate this queue." />
        )}
      </section>

      <section className="grid gap-4 md:grid-cols-3">
        <SummaryCard
          icon={<CloudIcon className="h-5 w-5" />}
          title="CloudGuard Role"
          text="Runs cloud, Kubernetes, IaC, and web security scanner jobs independently."
        />
        <SummaryCard
          icon={<DocumentCheckIcon className="h-5 w-5" />}
          title="GRC Role"
          text="Reads normalized evidence, maps controls, and manages review and audit work."
        />
        <SummaryCard
          icon={<CheckCircleIcon className="h-5 w-5" />}
          title="Connection"
          text="A protected backend connector shares evidence without exposing scanner credentials to the browser."
        />
      </section>
    </div>
  );
}

function StatusPill({ value }: { value: string }) {
  const style =
    ['Connected', 'Ready', 'Approved'].includes(value)
      ? 'bg-emerald-500/15 text-emerald-300'
      : ['Failed', 'Offline'].includes(value)
        ? 'bg-rose-500/15 text-rose-300'
        : value === 'No Evidence'
          ? 'bg-surface-700 text-surface-400'
          : 'bg-amber-500/15 text-amber-300';

  return <span className={clsx('inline-flex rounded-full px-2.5 py-1 text-xs font-semibold', style)}>{value}</span>;
}

function RiskPill({ value }: { value: string }) {
  const style =
    value === 'Critical'
      ? 'bg-rose-500/20 text-rose-200'
      : value === 'High'
        ? 'bg-orange-500/20 text-orange-200'
        : value === 'Medium'
          ? 'bg-yellow-500/20 text-yellow-200'
          : 'bg-emerald-500/20 text-emerald-200';

  return <span className={clsx('inline-flex rounded-full px-2.5 py-1 text-xs font-semibold', style)}>{value}</span>;
}

function Metric({ label, value }: { label: string; value: string }) {
  return (
    <div className="rounded-lg border border-surface-800 bg-surface-950 px-4 py-3">
      <p className="text-xs uppercase text-surface-600">{label}</p>
      <p className="mt-1 text-2xl font-bold text-surface-100">{value}</p>
    </div>
  );
}

function EmptyState({ text }: { text: string }) {
  return <p className="px-4 py-10 text-center text-sm text-surface-600">{text}</p>;
}

function SummaryCard({ icon, title, text }: { icon: React.ReactNode; title: string; text: string }) {
  return (
    <div className="rounded-lg border border-surface-800 bg-surface-900 p-4">
      <div className="flex items-center gap-2 text-brand-300">
        {icon}
        <h3 className="font-semibold text-surface-100">{title}</h3>
      </div>
      <p className="mt-2 text-sm text-surface-500">{text}</p>
    </div>
  );
}

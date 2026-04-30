import { Link } from 'react-router-dom';
import {
  Activity,
  AlertTriangle,
  ArrowUpRight,
  CreditCard,
  Loader2,
  Radar,
  ScrollText,
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useCurrentUser } from '@/hooks/use-current-user';
import { cn } from '@/lib/utils';
import { useDashboardBootstrap } from '../api/dashboard.api';

/**
 * Overview / home page.
 *
 * Today: shows the visual layout with placeholder values.
 * When the dashboard module's bootstrap query is wired (see
 * features/dashboard/api/dashboard.api.ts), populate these tiles
 * from `useDashboardBootstrap()`.
 */
export function DashboardPage() {
  const user = useCurrentUser();
  const { data, isLoading, isError, error } = useDashboardBootstrap();
  const greeting = getGreeting();
  const today = new Date().toLocaleDateString(undefined, {
    weekday: 'long',
    day: 'numeric',
    month: 'long',
    year: 'numeric',
  });

  return (
    <div className="mx-auto max-w-7xl space-y-8">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">
            {greeting}
            {user?.email ? `, ${user.email.split('@')[0]}` : ''}
          </h1>
          <p className="text-sm text-muted-foreground">{today}</p>
        </div>
        {isLoading ? (
          <div className="flex items-center gap-2 rounded-lg border bg-card px-3 py-2 text-xs text-muted-foreground">
            <Loader2 className="h-3.5 w-3.5 animate-spin" />
            Refreshing CloudGuard results
          </div>
        ) : (
          <div className="flex items-center gap-2 rounded-lg border bg-card px-3 py-2 text-xs text-muted-foreground">
            <span className="h-2 w-2 rounded-full bg-emerald-500" />
            Overview synced from the Cloud scanner
          </div>
        )}
      </header>

      {isError && (
        <div className="rounded-md border border-destructive/30 bg-destructive/10 p-4 text-sm text-destructive">
          {error instanceof Error ? error.message : 'Failed to load dashboard overview.'}
        </div>
      )}

      {/* Stat cards */}
      <section
        aria-label="Overview stats"
        className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4"
      >
        <StatCard
          label="Scans (last 30 days)"
          value={isLoading ? '...' : String(data?.metrics.scansLast30Days ?? 0)}
          icon={Activity}
          accent="bg-blue-500/10 text-blue-600"
          to="/scans"
        />
        <StatCard
          label="Open findings"
          value={isLoading ? '...' : String(data?.metrics.openFindings ?? 0)}
          icon={AlertTriangle}
          accent="bg-orange-500/10 text-orange-600"
          to="/findings"
        />
        <StatCard
          label="Active scanners"
          value={isLoading ? '...' : String(data?.metrics.activeScanners ?? 0)}
          icon={Radar}
          accent="bg-emerald-500/10 text-emerald-600"
          to="/scanners"
        />
        <StatCard
          label="Total findings"
          value={isLoading ? '...' : String(data?.metrics.totalFindings ?? 0)}
          icon={CreditCard}
          accent="bg-violet-500/10 text-violet-600"
          to="/findings"
        />
      </section>

      {/* Recent activity + quick start */}
      <section className="grid gap-6 lg:grid-cols-3">
        <Panel title="Recent scans" linkTo="/scans" linkLabel="View all">
          {data?.recent.scans.length ? (
            <div className="space-y-3">
              {data.recent.scans.map((scan) => (
                <Link
                  key={scan.id}
                  to={`/scans/${scan.id}`}
                  className="flex items-center justify-between rounded-lg border bg-background px-3 py-3 text-sm hover:bg-muted/50"
                >
                  <div>
                    <p className="font-medium capitalize">{scan.scannerKey}</p>
                    <p className="text-xs text-muted-foreground">
                      {scan.completedAt
                        ? `${formatDistanceToNow(new Date(scan.completedAt), { addSuffix: true })}`
                        : 'In progress'}
                    </p>
                  </div>
                  <div className="text-right">
                    <p className="font-semibold">
                      {Object.values(scan.summary ?? {}).reduce(
                        (sum, value) => sum + Number(value ?? 0),
                        0,
                      )}
                    </p>
                    <p className="text-xs text-muted-foreground">findings</p>
                  </div>
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={Activity}
              line="No scans yet."
              sub="Run a cloud scan from the main CloudGuard app first."
            />
          )}
        </Panel>

        <Panel title="Latest findings" linkTo="/findings" linkLabel="View all">
          {data?.recent.findings.length ? (
            <div className="space-y-3">
              {data.recent.findings.map((finding) => (
                <Link
                  key={finding.id}
                  to={`/findings/${finding.id}`}
                  className="flex items-start justify-between gap-3 rounded-lg border bg-background px-3 py-3 text-sm hover:bg-muted/50"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">{finding.title}</p>
                    <p className="text-xs text-muted-foreground">
                      {formatDistanceToNow(new Date(finding.createdAt), { addSuffix: true })}
                    </p>
                  </div>
                  <SeverityBadge severity={finding.severity} />
                </Link>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={AlertTriangle}
              line="No findings yet."
              sub="Findings will appear here after the next CloudGuard scan sync."
            />
          )}
        </Panel>

        <Panel title="Recent activity" linkTo="/audit" linkLabel="View audit log">
          <EmptyState
            icon={ScrollText}
            line="No activity yet."
            sub="User and system actions will appear here."
          />
        </Panel>
      </section>

      {/* Get started */}
      <section className="rounded-xl border bg-card p-6">
        <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <h2 className="text-base font-semibold">Get started</h2>
            <p className="mt-1 text-sm text-muted-foreground">
              Configure a scanner, add credentials, then trigger your first scan.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Link
              to="/scanners"
              className="inline-flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-sm font-medium hover:bg-muted"
            >
              Configure scanners
              <ArrowUpRight className="h-4 w-4" />
            </Link>
            <Link
              to="/secrets"
              className="inline-flex items-center gap-2 rounded-md border bg-background px-3 py-2 text-sm font-medium hover:bg-muted"
            >
              Add credentials
              <ArrowUpRight className="h-4 w-4" />
            </Link>
            <Link
              to="/findings"
              className="inline-flex items-center gap-2 rounded-md bg-primary px-3 py-2 text-sm font-medium text-primary-foreground hover:opacity-90"
            >
              Review findings
              <ArrowUpRight className="h-4 w-4" />
            </Link>
          </div>
        </div>
      </section>
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

// ─────────────────────────────────────────────────────────────────────

interface StatCardProps {
  label: string;
  value: string;
  icon: React.ComponentType<{ className?: string }>;
  accent: string;
  to: string;
}

function StatCard({ label, value, icon: Icon, accent, to }: StatCardProps) {
  return (
    <Link
      to={to}
      className="group rounded-xl border bg-card p-5 transition hover:border-primary/40 hover:shadow-sm"
    >
      <div className="flex items-start justify-between">
        <div className={cn('flex h-9 w-9 items-center justify-center rounded-lg', accent)}>
          <Icon className="h-4 w-4" />
        </div>
        <ArrowUpRight className="h-4 w-4 text-muted-foreground opacity-0 transition group-hover:opacity-100" />
      </div>
      <div className="mt-4 space-y-1">
        <p className="text-2xl font-semibold tracking-tight">{value}</p>
        <p className="text-xs text-muted-foreground">{label}</p>
      </div>
    </Link>
  );
}

interface PanelProps {
  title: string;
  linkTo: string;
  linkLabel: string;
  children: React.ReactNode;
}

function Panel({ title, linkTo, linkLabel, children }: PanelProps) {
  return (
    <div className="rounded-xl border bg-card">
      <div className="flex items-center justify-between border-b px-5 py-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        <Link
          to={linkTo}
          className="text-xs font-medium text-muted-foreground hover:text-foreground"
        >
          {linkLabel}
        </Link>
      </div>
      <div className="p-5">{children}</div>
    </div>
  );
}

interface EmptyStateProps {
  icon: React.ComponentType<{ className?: string }>;
  line: string;
  sub: string;
}

function EmptyState({ icon: Icon, line, sub }: EmptyStateProps) {
  return (
    <div className="flex min-h-[140px] flex-col items-center justify-center text-center text-sm text-muted-foreground">
      <Icon className="mb-2 h-5 w-5" aria-hidden />
      <p className="font-medium text-foreground">{line}</p>
      <p className="mt-0.5 text-xs">{sub}</p>
    </div>
  );
}

function getGreeting(): string {
  const h = new Date().getHours();
  if (h < 12) return 'Good morning';
  if (h < 18) return 'Good afternoon';
  return 'Good evening';
}

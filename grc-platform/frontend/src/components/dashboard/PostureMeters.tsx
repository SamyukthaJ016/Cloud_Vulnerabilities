import { Link } from 'react-router-dom';
import { ArrowUpRightIcon } from '@heroicons/react/24/outline';
import type { FullDashboardResponse } from '@/lib/api';

interface PostureMetersProps {
  summary?: FullDashboardResponse['summary'];
  policies?: FullDashboardResponse['policyStats'];
  unavailable?: boolean;
}

function count(value: number | undefined): number | null {
  return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
}

function Meter({
  title,
  numerator,
  denominator,
  detail,
  empty,
  href,
  backlog = false,
  unavailable,
}: {
  title: string;
  numerator: number | null;
  denominator: number | null;
  detail: string;
  empty: string;
  href: string;
  backlog?: boolean;
  unavailable?: boolean;
}) {
  const percentage =
    !unavailable && numerator !== null && denominator !== null && denominator > 0
      ? Math.min(100, Math.max(0, Math.round((numerator / denominator) * 100)))
      : null;
  const circumference = 2 * Math.PI * 70;
  const sweep = circumference * 0.75;
  const needsReview = backlog && percentage !== null && percentage > 0;
  const valueText =
    percentage === null ? (unavailable ? 'Unavailable' : 'No data') : `${percentage}%`;

  return (
    <article className="posture-meter">
      <div className="flex items-center justify-between gap-3">
        <h3 className="text-sm font-medium text-surface-200">{title}</h3>
        <Link
          to={href}
          aria-label={`View ${title.toLowerCase()}`}
          className="meter-link rounded-md p-1.5 text-surface-500 hover:bg-brand-500/10 hover:text-brand-400"
        >
          <ArrowUpRightIcon className="h-4 w-4" />
        </Link>
      </div>
      <div
        className="relative mx-auto w-full max-w-[240px]"
        role={percentage !== null ? 'meter' : undefined}
        aria-label={title}
        aria-valuemin={percentage !== null ? 0 : undefined}
        aria-valuemax={percentage !== null ? 100 : undefined}
        aria-valuenow={percentage ?? undefined}
        aria-valuetext={
          percentage !== null
            ? `${percentage}%. ${numerator} of ${denominator}. ${backlog ? 'Lower is better.' : 'Higher is better.'}`
            : undefined
        }
      >
        <svg viewBox="0 0 200 176" className="w-full" aria-hidden="true">
          <circle
            cx="100"
            cy="100"
            r="70"
            fill="none"
            stroke="var(--meter-track)"
            strokeWidth="11"
            strokeLinecap="round"
            strokeDasharray={`${sweep} ${circumference}`}
            transform="rotate(135 100 100)"
          />
          {percentage !== null && percentage > 0 && (
            <circle
              className="meter-arc"
              cx="100"
              cy="100"
              r="70"
              fill="none"
              stroke={needsReview ? '#fbbf24' : 'var(--meter-fill)'}
              strokeWidth="11"
              strokeLinecap="round"
              strokeDasharray={`${(sweep * percentage) / 100} ${circumference}`}
              transform="rotate(135 100 100)"
            />
          )}
          <text
            x="100"
            y="103"
            textAnchor="middle"
            className="meter-value"
            fontSize={percentage === null ? 22 : 34}
          >
            {valueText}
          </text>
          <text x="100" y="126" textAnchor="middle" className="meter-direction" fontSize="10">
            {percentage !== null
              ? backlog
                ? 'LOWER IS BETTER'
                : 'HIGHER IS BETTER'
              : unavailable
                ? 'DATA UNAVAILABLE'
                : 'AWAITING RECORDS'}
          </text>
        </svg>
      </div>
      <div className="-mt-3 text-center">
        <p className="text-sm font-medium text-surface-200">
          {unavailable
            ? 'Could not load records'
            : percentage === null
              ? empty
              : `${numerator} of ${denominator} ${detail}`}
        </p>
        <p className="mt-1 text-xs text-surface-500">
          {backlog
            ? 'Pending review is work still to complete.'
            : title === 'Control implementation'
              ? 'Excludes controls marked not applicable.'
              : 'Published policies out of all policy records.'}
        </p>
      </div>
    </article>
  );
}

export default function PostureMeters({ summary, policies, unavailable }: PostureMetersProps) {
  const controls = summary?.controls;
  const total = count(controls?.total);
  const excluded = count(controls?.byStatus?.not_applicable);
  const applicable = total !== null && excluded !== null ? Math.max(0, total - excluded) : null;
  return (
    <section aria-label="Governance and compliance meters" className="posture-panel">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-surface-800 px-5 py-4 sm:px-6">
        <div>
          <p className="dashboard-eyebrow">PROGRAM HEALTH</p>
          <h2 className="mt-1 text-lg font-semibold text-surface-100">Your compliance posture</h2>
        </div>
        <span className="text-xs text-surface-500">Based on GRC records</span>
      </div>
      <div className="grid grid-cols-1 divide-y divide-surface-800 md:grid-cols-3 md:divide-x md:divide-y-0">
        <Meter
          title="Control implementation"
          numerator={count(controls?.byStatus?.implemented)}
          denominator={applicable}
          detail="applicable controls implemented"
          empty="No applicable controls yet"
          href="/controls"
          unavailable={unavailable}
        />
        <Meter
          title="Evidence awaiting review"
          numerator={count(summary?.evidence?.pendingReview)}
          denominator={count(summary?.evidence?.total)}
          detail="evidence items awaiting review"
          empty="No evidence uploaded yet"
          href="/evidence"
          backlog
          unavailable={unavailable}
        />
        <Meter
          title="Policy publication"
          numerator={count(policies?.published)}
          denominator={count(policies?.total)}
          detail="policies published"
          empty="No policies created yet"
          href="/policies"
          unavailable={unavailable}
        />
      </div>
    </section>
  );
}

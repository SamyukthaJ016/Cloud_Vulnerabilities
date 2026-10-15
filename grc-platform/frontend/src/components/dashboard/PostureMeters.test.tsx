import { describe, expect, it } from 'vitest';
import { render, screen } from '@/test/utils';
import type { FullDashboardResponse } from '@/lib/api';
import PostureMeters from './PostureMeters';

const summary: FullDashboardResponse['summary'] = {
  complianceScore: { overall: 70, byFramework: {} },
  controls: {
    total: 100,
    byStatus: { implemented: 60, not_applicable: 20 },
    byCategory: {},
    overdue: 0,
  },
  evidence: { total: 40, pendingReview: 10, expired: 0, expiringSoon: 0 },
  upcomingTests: [],
  recentActivity: [],
};
const policies: FullDashboardResponse['policyStats'] = {
  total: 10,
  published: 8,
  approved: 1,
  inReview: 1,
  draft: 0,
  overdueReview: 0,
};

describe('GRC posture meters', () => {
  it('uses applicable controls and distinguishes review backlog from completion', () => {
    render(<PostureMeters summary={summary} policies={policies} />);
    expect(screen.getByRole('meter', { name: 'Control implementation' })).toHaveAttribute(
      'aria-valuenow',
      '75'
    );
    expect(screen.getByText('60 of 80 applicable controls implemented')).toBeInTheDocument();
    expect(screen.getByRole('meter', { name: 'Evidence awaiting review' })).toHaveAttribute(
      'aria-valuetext',
      '25%. 10 of 40. Lower is better.'
    );
    expect(screen.getByRole('meter', { name: 'Policy publication' })).toHaveAttribute(
      'aria-valuenow',
      '80'
    );
    expect(screen.getByRole('link', { name: 'View evidence awaiting review' })).toHaveAttribute(
      'href',
      '/evidence'
    );
  });

  it('shows an empty state rather than a healthy score when there are no records', () => {
    render(
      <PostureMeters
        summary={{
          ...summary,
          controls: {
            ...summary.controls,
            total: 0,
            byStatus: { implemented: 0, not_applicable: 0 },
          },
          evidence: { ...summary.evidence, total: 0, pendingReview: 0 },
        }}
        policies={{ ...policies, total: 0, published: 0 }}
      />
    );
    expect(screen.queryAllByRole('meter')).toHaveLength(0);
    expect(screen.getByText('No applicable controls yet')).toBeInTheDocument();
    expect(screen.getByText('No evidence uploaded yet')).toBeInTheDocument();
    expect(screen.getByText('No policies created yet')).toBeInTheDocument();
  });

  it('suppresses cached percentages when the source is unavailable', () => {
    render(<PostureMeters summary={summary} policies={policies} unavailable />);
    expect(screen.queryAllByRole('meter')).toHaveLength(0);
    expect(screen.getAllByText('Could not load records')).toHaveLength(3);
    expect(screen.queryByText('75%')).not.toBeInTheDocument();
  });

  it('represents a zero review backlog as a measured zero', () => {
    render(
      <PostureMeters
        summary={{ ...summary, evidence: { ...summary.evidence, pendingReview: 0 } }}
        policies={policies}
      />
    );
    expect(screen.getByRole('meter', { name: 'Evidence awaiting review' })).toHaveAttribute(
      'aria-valuenow',
      '0'
    );
    expect(screen.getByText('0 of 40 evidence items awaiting review')).toBeInTheDocument();
  });
});

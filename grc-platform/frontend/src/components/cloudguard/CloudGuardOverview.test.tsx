import { describe, expect, it, vi } from 'vitest';
import { render, screen } from '@/test/utils';
import { useQuery } from '@tanstack/react-query';
import CloudGuardOverview from './CloudGuardOverview';
import { scanFixture } from './latest-scan.fixture';

vi.mock('@tanstack/react-query', async importOriginal => ({...await importOriginal<typeof import('@tanstack/react-query')>(), useQuery:vi.fn()}));

describe('Live scanner dashboard overview', () => {
  it('uses the latest scan count instead of historic mapped counts', () => {
    vi.mocked(useQuery).mockReturnValue({isError:false,isPending:false,data:{latest_scan:scanFixture,compliance:{counts:{findings:1027}}}} as never);
    render(<CloudGuardOverview />);
    expect(screen.getByText('Last completed scan #26 · KUBERNETES')).toBeInTheDocument();
    expect(screen.queryByText('1027')).not.toBeInTheDocument();
    expect(screen.getByRole('link',{name:'View Scanner Findings'})).toHaveAttribute('href','/cloudguard-grc');
  });
  it('does not display stale counts as a healthy connection after a connector error', () => {
    vi.mocked(useQuery).mockReturnValue({isError:true,isPending:false,data:{latest_scan:scanFixture}} as never);
    render(<CloudGuardOverview />);
    expect(screen.getByText(/Scanner connector unavailable/)).toBeInTheDocument();
    expect(screen.queryByText('Resources')).not.toBeInTheDocument();
  });
});

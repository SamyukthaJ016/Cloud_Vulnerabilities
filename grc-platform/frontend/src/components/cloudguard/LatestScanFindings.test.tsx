import { fireEvent, render, screen } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import LatestScanFindings from './LatestScanFindings';
import { scanFixture } from './latest-scan.fixture';
import { latestScanControls } from '@/lib/cloudguard-latest-scan';

describe('Latest scanner findings', () => {
  it('lists all findings including information, and supports search', () => {
    render(<LatestScanFindings scan={scanFixture} />);
    expect(screen.getByText('Privileged container')).toBeInTheDocument();
    expect(screen.getByText('No IaC baseline')).toBeInTheDocument();
    fireEvent.change(screen.getByLabelText('Search findings'), {target:{value:'pod-a'}});
    expect(screen.queryByText('No IaC baseline')).not.toBeInTheDocument();
    expect(screen.getByText('Privileged container')).toBeInTheDocument();
  });
  it('does not truncate the framework mapping input to a few samples', () => {
    const controls = latestScanControls({...scanFixture,findings:Array.from({length:47},(_,id)=>({...scanFixture.findings[0],id}))});
    expect(controls[0].finding_count).toBe(47);
    expect(controls[0].sample_findings).toHaveLength(47);
    expect(latestScanControls(null)).toEqual([]);
  });
  it('shows a clean scan without claiming the whole environment is secure', () => {
    render(<LatestScanFindings scan={{...scanFixture,finding_count:0,findings:[]}} />);
    expect(screen.getByText('This scan reported no findings.')).toBeInTheDocument();
  });
});

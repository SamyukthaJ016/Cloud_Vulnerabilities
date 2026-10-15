import { fireEvent } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { render, screen, waitFor } from '@/test/utils';
import { useAuth } from '@/contexts/AuthContext';
import { cloudGuardApi } from '@/lib/api/cloudguard.api';
import ImportScan from './ImportScan';
import { scanFixture } from './latest-scan.fixture';

vi.mock('@/contexts/AuthContext', () => ({useAuth:vi.fn()}));
vi.mock('@/lib/api/cloudguard.api', () => ({cloudGuardApi:{importLatest:vi.fn()}}));

beforeEach(() => vi.clearAllMocks());

describe('Import scanner findings', () => {
  it('keeps import unavailable to a viewer', () => {
    vi.mocked(useAuth).mockReturnValue({hasRole:()=>false} as never);
    render(<ImportScan scan={scanFixture} />);
    expect(screen.getByRole('button',{name:'Import into Evidence and Risk Register'})).toBeDisabled();
    expect(screen.getByText(/requires an administrator/)).toBeInTheDocument();
    expect(cloudGuardApi.importLatest).not.toHaveBeenCalled();
  });
  it('imports only the reviewed scan ID and links the created evidence', async () => {
    vi.mocked(useAuth).mockReturnValue({hasRole:role=>role==='admin'} as never);
    vi.mocked(cloudGuardApi.importLatest).mockResolvedValue({scanId:26,evidenceId:'evidence-26',evidenceCreated:true,createdRisks:1,existingRisks:0,deletedRisksSkipped:0,informationalFindings:1,risks:[]});
    render(<ImportScan scan={scanFixture} />);
    fireEvent.click(screen.getByRole('button',{name:'Import into Evidence and Risk Register'}));
    await waitFor(()=>expect(screen.getByRole('status')).toHaveTextContent('1 new risks'));
    expect(cloudGuardApi.importLatest).toHaveBeenCalledWith(26);
    expect(screen.getByRole('link',{name:'Open Evidence Report'})).toHaveAttribute('href','/evidence/evidence-26');
  });
});

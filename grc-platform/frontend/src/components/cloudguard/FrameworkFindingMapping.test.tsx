import { beforeEach, describe, expect, it, vi } from 'vitest';
import userEvent from '@testing-library/user-event';
import { act, render, screen, waitFor } from '@/test/utils';
import { frameworkCatalogApi } from '@/lib/api/framework-catalog.api';
import type { CatalogFrameworkDetail } from '@/lib/api/framework-catalog.api';
import type { CloudGuardControl } from '@/lib/api/cloudguard.api';
import FrameworkFindingMapping from './FrameworkFindingMapping';

vi.mock('@/lib/api/framework-catalog.api', () => ({
  frameworkCatalogApi: { list: vi.fn(), detail: vi.fn() },
}));

const catalogs: CatalogFrameworkDetail[] = [
  {
    id: 'iso27001-2022',
    name: 'ISO 27001',
    version: '2022',
    source: 'ISO',
    isActivated: true,
    requirements: [
      {
        reference: 'A.8.8',
        title: 'Management of Technical Vulnerabilities',
        description: 'Identify and manage vulnerabilities.',
        isCategory: false,
      },
    ],
  },
  {
    id: 'nist-csf-2',
    name: 'NIST CSF',
    version: '2.0',
    source: 'NIST',
    isActivated: false,
    requirements: [
      {
        reference: 'ID.RA-01',
        title: 'Vulnerabilities are identified',
        description: 'Identify vulnerabilities.',
        isCategory: false,
      },
    ],
  },
];
const controls: CloudGuardControl[] = [
  {
    control_id: 'SCANNER-1',
    control_name: 'Vulnerability control',
    framework: 'scanner',
    status: 'non_compliant',
    evidence_count: 1,
    finding_count: 2,
    sources: ['trivy'],
    severity_counts: { critical: 0, high: 2, medium: 0, low: 0, info: 0 },
    sample_findings: [
      {
        control_id: 'SCANNER-1',
        title: 'Unpatched dependency',
        resource: 'host-a',
        severity: 'high',
      },
      { control_id: 'SCANNER-1', title: 'Unusual result', resource: 'host-b', severity: 'high' },
    ],
  },
];

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(frameworkCatalogApi.list).mockResolvedValue(catalogs);
  vi.mocked(frameworkCatalogApi.detail).mockImplementation(async (id) =>
    catalogs.find((catalog) => catalog.id === id)!
  );
});

function setupUser() {
  const user = userEvent.setup();
  return {
    selectOptions: async (...args: Parameters<typeof user.selectOptions>) => {
      await act(async () => {
        await user.selectOptions(...args);
      });
    },
    click: async (...args: Parameters<typeof user.click>) => {
      await act(async () => {
        await user.click(...args);
      });
    },
  };
}

describe('framework finding mapping', () => {
  it('loads frameworks and generates suggestions only after a selection', async () => {
    const user = setupUser();
    render(<FrameworkFindingMapping controls={controls} />);
    await screen.findByRole('option', { name: /ISO 27001/ });
    expect(frameworkCatalogApi.detail).not.toHaveBeenCalled();
    await user.selectOptions(screen.getByLabelText('Compliance framework'), 'iso27001-2022');
    await screen.findByRole('button', { name: 'Select A.8.8 for Unpatched dependency' });
    expect(screen.getByLabelText('Requirement for Unpatched dependency')).toHaveValue('');
    expect(screen.getByText(/No suggestion. Review the catalog/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: 'Official reference: ISO' })).toHaveAttribute(
      'href',
      'https://www.iso.org/standard/27001'
    );
    await user.click(screen.getByRole('button', { name: 'Select A.8.8 for Unpatched dependency' }));
    expect(screen.getByLabelText('Requirement for Unpatched dependency')).toHaveValue('A.8.8');
    await user.selectOptions(screen.getByLabelText('Requirement for Unusual result'), 'A.8.8');
    expect(screen.getByText(/2 selected/)).toBeInTheDocument();
  });

  it('clears selections on framework changes and does not carry ISO references into NIST', async () => {
    const user = setupUser();
    render(<FrameworkFindingMapping controls={controls} />);
    await screen.findByRole('option', { name: /ISO 27001/ });
    await user.selectOptions(screen.getByLabelText('Compliance framework'), 'iso27001-2022');
    await user.click(
      await screen.findByRole('button', { name: 'Select A.8.8 for Unpatched dependency' })
    );
    await user.selectOptions(screen.getByLabelText('Compliance framework'), 'nist-csf-2');
    await screen.findByRole('button', { name: 'Select ID.RA-01 for Unpatched dependency' });
    expect(screen.getByLabelText('Requirement for Unpatched dependency')).toHaveValue('');
    expect(screen.queryByRole('option', { name: /A.8.8/ })).not.toBeInTheDocument();
    expect(
      screen.getByRole('link', { name: 'Activate it in the Framework Library' })
    ).toBeInTheDocument();
  });

  it('does not fabricate findings when the connector has no samples', async () => {
    const user = setupUser();
    render(<FrameworkFindingMapping controls={[]} />);
    await screen.findByRole('option', { name: /ISO 27001/ });
    await user.selectOptions(screen.getByLabelText('Compliance framework'), 'iso27001-2022');
    await screen.findByText(/No live finding samples are available/);
    expect(screen.queryByRole('button', { name: 'Export mapping draft' })).not.toBeInTheDocument();
  });

  it('shows catalog failures instead of falling back to invented standards', async () => {
    vi.mocked(frameworkCatalogApi.list).mockRejectedValue(new Error('offline'));
    render(<FrameworkFindingMapping controls={controls} />);
    await screen.findByText(/Frameworks could not be loaded/);
    expect(screen.getByLabelText('Compliance framework')).toBeDisabled();
    expect(frameworkCatalogApi.detail).not.toHaveBeenCalled();
  });

  it('does not generate mappings when fetching requirements fails', async () => {
    vi.mocked(frameworkCatalogApi.detail).mockRejectedValue(new Error('offline'));
    const user = setupUser();
    render(<FrameworkFindingMapping controls={controls} />);
    await screen.findByRole('option', { name: /ISO 27001/ });
    await user.selectOptions(screen.getByLabelText('Compliance framework'), 'iso27001-2022');
    await screen.findByText(/Requirements could not be loaded/);
    expect(screen.queryByRole('table')).not.toBeInTheDocument();
  });

  it('exports the selected framework, draft state, source and unmapped rows', async () => {
    let blob: Blob | undefined;
    const createUrl = vi.fn((value: Blob) => {
      blob = value;
      return 'blob:test';
    });
    const revokeUrl = vi.fn();
    vi.stubGlobal(
      'URL',
      Object.assign(class extends URL {}, {
        createObjectURL: createUrl,
        revokeObjectURL: revokeUrl,
      })
    );
    const click = vi.spyOn(HTMLAnchorElement.prototype, 'click').mockImplementation(() => {});
    try {
      const user = setupUser();
      render(<FrameworkFindingMapping controls={controls} generatedAt="2026-10-12T10:00:00Z" />);
      await screen.findByRole('option', { name: /ISO 27001/ });
      await user.selectOptions(screen.getByLabelText('Compliance framework'), 'iso27001-2022');
      await user.click(
        await screen.findByRole('button', { name: 'Select A.8.8 for Unpatched dependency' })
      );
      await user.click(screen.getByRole('button', { name: 'Export mapping draft' }));
      await waitFor(() => expect(createUrl).toHaveBeenCalledOnce());
      const content = await new Promise<string>((resolve) => {
        const reader = new FileReader();
        reader.onload = () => resolve(String(reader.result));
        reader.readAsText(blob!);
      });
      expect(content).toContain('A.8.8');
      expect(content).toContain('Draft — review required');
      expect(content).toContain('Unmapped');
      expect(content).toContain('https://www.iso.org/standard/27001');
      expect(content).toContain('2026-10-12T10:00:00Z');
      expect(revokeUrl).toHaveBeenCalledWith('blob:test');
    } finally {
      click.mockRestore();
      vi.unstubAllGlobals();
    }
  });
});

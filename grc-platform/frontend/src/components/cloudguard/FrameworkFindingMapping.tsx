import { useMemo, useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Link } from 'react-router-dom';
import { Button } from '@/components/ui/Button';
import { SelectNative } from '@/components/ui/SelectNative';
import { frameworkCatalogApi, CatalogFrameworkDetail } from '@/lib/api/framework-catalog.api';
import type { CloudGuardControl } from '@/lib/api/cloudguard.api';
import {
  findingMappingKey,
  findingResourceLabel,
  flattenMappingRequirements,
  frameworkSources,
  mappingCsvCell,
  suggestFindingRequirements,
} from '@/lib/cloudguard-framework-mapping';

interface Props {
  controls: CloudGuardControl[];
  generatedAt?: string;
}

export default function FrameworkFindingMapping({ controls, generatedAt }: Props) {
  const [frameworkId, setFrameworkId] = useState('');
  const catalogQuery = useQuery({
    queryKey: ['framework-catalog-status'],
    queryFn: frameworkCatalogApi.list,
  });
  const detailQuery = useQuery({
    queryKey: ['framework-finding-mapping-catalog', frameworkId],
    queryFn: () => frameworkCatalogApi.detail(frameworkId),
    enabled: Boolean(frameworkId),
  });
  const source = frameworkSources[frameworkId];
  const selectedFramework = catalogQuery.data?.find((framework) => framework.id === frameworkId);

  return (
    <section className="card p-5" aria-labelledby="framework-finding-mapping-heading">
      <div className="flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
        <div>
          <h2
            id="framework-finding-mapping-heading"
            className="text-lg font-semibold text-surface-900"
          >
            Map Vulnerabilities to a Framework
          </h2>
          <p className="mt-1 max-w-3xl text-sm text-surface-600">
            Choose a framework, review suggested requirements, and select the requirement that
            applies to each finding.
          </p>
        </div>
        <div className="w-full md:max-w-sm">
          <label
            htmlFor="finding-framework"
            className="mb-1 block text-sm font-medium text-surface-900"
          >
            Compliance framework
          </label>
          <SelectNative
            id="finding-framework"
            value={frameworkId}
            onChange={(event) => setFrameworkId(event.target.value)}
            disabled={catalogQuery.isPending || catalogQuery.isError}
          >
            <option value="">Choose a framework</option>
            {catalogQuery.data?.map((framework) => (
              <option key={framework.id} value={framework.id}>
                {framework.name} · {framework.version}
                {framework.isActivated ? ' · Active' : ''}
              </option>
            ))}
          </SelectNative>
        </div>
      </div>

      {catalogQuery.isError && (
        <div className="mt-4 text-sm text-rose-600" role="alert">
          <p>Frameworks could not be loaded. Check the GRC service connection.</p>
          <Button type="button" variant="secondary" onClick={() => catalogQuery.refetch()}>
            Retry frameworks
          </Button>
        </div>
      )}
      {catalogQuery.isPending && (
        <p className="mt-4 text-sm text-surface-600" role="status">
          Loading frameworks…
        </p>
      )}
      {!catalogQuery.isPending && !catalogQuery.isError && !catalogQuery.data?.length && (
        <p className="mt-4 text-sm text-surface-600">No framework catalogs are available.</p>
      )}

      {selectedFramework && (
        <div className="mt-4 rounded-lg border border-surface-200 bg-surface-50 p-4 text-sm text-surface-600">
          <p className="font-medium text-surface-900">
            {selectedFramework.name} · Catalog version {selectedFramework.version}
          </p>
          {source ? (
            <>
              <a
                href={source.url}
                target="_blank"
                rel="noopener noreferrer"
                className="mt-1 inline-block text-brand-600 underline"
              >
                Official reference: {source.publisher}
              </a>
              <p className="mt-1 text-xs">
                Publisher reference checked {source.checkedOn}. Catalog requirements and individual
                mappings still need review.
              </p>
              {source.note && <p className="mt-2">{source.note}</p>}
            </>
          ) : (
            <p className="mt-1">No publisher reference has been checked for this catalog.</p>
          )}
          {!selectedFramework.isActivated && (
            <p className="mt-2">
              Preview catalog.{' '}
              <Link to="/framework-library" className="text-brand-600 underline">
                Activate it in the Framework Library
              </Link>{' '}
              to use it in your compliance program.
            </p>
          )}
        </div>
      )}

      {frameworkId && detailQuery.isPending && (
        <p className="mt-4 text-sm text-surface-600" role="status">
          Loading requirements…
        </p>
      )}
      {frameworkId && detailQuery.isError && (
        <div className="mt-4 text-sm text-rose-600" role="alert">
          <p>
            Requirements could not be loaded. No mappings are generated without the selected
            catalog.
          </p>
          <Button type="button" variant="secondary" onClick={() => detailQuery.refetch()}>
            Retry requirements
          </Button>
        </div>
      )}
      {frameworkId && detailQuery.data?.id === frameworkId && !detailQuery.isError && (
        <MappingDraft
          key={frameworkId}
          framework={detailQuery.data}
          controls={controls}
          generatedAt={generatedAt}
        />
      )}
    </section>
  );
}

function MappingDraft({
  framework,
  controls,
  generatedAt,
}: Props & { framework: CatalogFrameworkDetail }) {
  const [selections, setSelections] = useState<Record<string, string>>({});
  const [page, setPage] = useState(0);
  const requirements = useMemo(
    () => flattenMappingRequirements(framework.requirements),
    [framework.requirements]
  );
  const rows = useMemo(() => {
    const seen = new Set<string>();
    return controls
      .flatMap((control) => control.sample_findings.map((finding) => ({ control, finding })))
      .flatMap(({ control, finding }) => {
        const key = findingMappingKey(control, finding);
        if (seen.has(key)) return [];
        seen.add(key);
        return [
          {
            key,
            control,
            finding,
            suggestions: suggestFindingRequirements(finding, framework.requirements),
          },
        ];
      });
  }, [controls, framework.requirements]);
  const source = frameworkSources[framework.id];
  const pageCount = Math.ceil(rows.length / 10);
  const currentPage = Math.min(page, Math.max(0, pageCount - 1));
  const selectedCount = rows.filter((row) =>
    requirements.some((requirement) => requirement.reference === selections[row.key])
  ).length;
  const suggestedCount = rows.filter((row) => row.suggestions.length).length;

  function exportDraft() {
    const header = [
      'Finding',
      'Resource',
      'Severity',
      'Scanner control',
      'Framework',
      'Catalog version',
      'Selected requirement',
      'Requirement title',
      'Review state',
      'Official source',
      'Source checked on',
      'Connector generated at',
    ];
    const data = rows.map(({ key, control, finding }) => {
      const selected = requirements.find(
        (requirement) => requirement.reference === selections[key]
      );
      return [
        finding.title,
        findingResourceLabel(finding.resource),
        finding.severity,
        control.control_id,
        framework.name,
        framework.version,
        selected?.reference,
        selected?.title,
        selected ? 'Draft — review required' : 'Unmapped',
        source?.url,
        source?.checkedOn,
        generatedAt,
      ];
    });
    const blob = new Blob(
      [[header, ...data].map((row) => row.map(mappingCsvCell).join(',')).join('\r\n')],
      { type: 'text/csv;charset=utf-8;' }
    );
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `cloudguard-${framework.id}-mapping-draft.csv`;
    link.click();
    URL.revokeObjectURL(url);
  }

  return (
    <div className="mt-4">
      <p className="text-sm text-surface-600">
        Suggestions match finding topics to the selected catalog. They are not publisher-approved
        mappings or a compliance assessment. Selections form a review draft and do not change
        compliance scores or saved control mappings.
      </p>
      <p className="mt-2 text-xs text-surface-600">
        The connector provides sample findings, so this list may not include every vulnerability.
        Draft selections last until you change framework or leave this page.
      </p>
      {!rows.length ? (
        <p className="py-8 text-center text-sm text-surface-600">
          No live finding samples are available to map. Run a scanner job and refresh the connector.
        </p>
      ) : (
        <>
          <div className="my-4 flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-surface-900">
              {rows.length} finding samples · {suggestedCount} with suggestions · {selectedCount}{' '}
              selected
            </p>
            <Button type="button" variant="secondary" onClick={exportDraft}>
              Export mapping draft
            </Button>
          </div>
          <div className="overflow-x-auto rounded-lg border border-surface-200">
            <table className="min-w-full divide-y divide-surface-200 text-sm">
              <thead className="bg-surface-100 text-left text-xs uppercase text-surface-600">
                <tr>
                  <th className="px-4 py-3">Finding</th>
                  <th className="px-4 py-3">Suggested requirements</th>
                  <th className="px-4 py-3">Selected requirement</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-surface-200">
                {rows
                  .slice(currentPage * 10, currentPage * 10 + 10)
                  .map(({ key, control, finding, suggestions }) => (
                    <tr key={key}>
                      <td className="max-w-sm px-4 py-4 align-top">
                        <p className="font-medium text-surface-900">{finding.title}</p>
                        <p className="mt-1 text-xs text-surface-600">
                          {finding.severity} · {control.control_id}
                        </p>
                        {finding.resource && (
                          <p className="mt-1 break-all text-xs text-surface-600">
                            {findingResourceLabel(finding.resource)}
                          </p>
                        )}
                      </td>
                      <td className="max-w-md space-y-3 px-4 py-4 align-top">
                        {suggestions.length ? (
                          suggestions.map((suggestion) => (
                            <div key={suggestion.reference}>
                              <button
                                type="button"
                                onClick={() =>
                                  setSelections((previous) => ({
                                    ...previous,
                                    [key]: suggestion.reference,
                                  }))
                                }
                                className="text-left text-brand-600 underline"
                                aria-label={`Select ${suggestion.reference} for ${finding.title}`}
                              >
                                {suggestion.reference} — {suggestion.title}
                              </button>
                              <p className="mt-1 text-xs text-surface-600">{suggestion.reason}</p>
                            </div>
                          ))
                        ) : (
                          <p className="text-surface-600">
                            No suggestion. Review the catalog and select a requirement manually, or
                            leave unmapped.
                          </p>
                        )}
                      </td>
                      <td className="min-w-72 max-w-md px-4 py-4 align-top">
                        <SelectNative
                          aria-label={`Requirement for ${finding.title}`}
                          value={selections[key] || ''}
                          onChange={(event) =>
                            setSelections((previous) => ({
                              ...previous,
                              [key]: event.target.value,
                            }))
                          }
                        >
                          <option value="">Unmapped</option>
                          {requirements.map((requirement) => (
                            <option key={requirement.reference} value={requirement.reference}>
                              {requirement.reference} — {requirement.title}
                            </option>
                          ))}
                        </SelectNative>
                        <p className="mt-2 text-xs text-amber-700">Review required</p>
                        {selections[key] && (
                          <p className="mt-2 text-xs text-surface-600">
                            {
                              requirements.find(
                                (requirement) => requirement.reference === selections[key]
                              )?.description
                            }
                          </p>
                        )}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
          {pageCount > 1 && (
            <div className="mt-3 flex items-center justify-end gap-3 text-sm text-surface-600">
              <Button
                type="button"
                variant="secondary"
                disabled={!currentPage}
                onClick={() => setPage(currentPage - 1)}
              >
                Previous findings
              </Button>
              <span>
                Page {currentPage + 1} of {pageCount}
              </span>
              <Button
                type="button"
                variant="secondary"
                disabled={currentPage + 1 >= pageCount}
                onClick={() => setPage(currentPage + 1)}
              >
                Next findings
              </Button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

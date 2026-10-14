import { describe, expect, it } from 'vitest';
import iso27001 from '../../../services/controls/src/frameworks/catalog/iso27001-2022.json';
import nistCsf from '../../../services/controls/src/frameworks/catalog/nist-csf-2.json';
import {
  findingMappingKey,
  findingResourceLabel,
  flattenMappingRequirements,
  frameworkSources,
  mappingCsvCell,
  suggestFindingRequirements,
} from './cloudguard-framework-mapping';
import type { CloudGuardControl, CloudGuardFinding } from './api/cloudguard.api';

const finding: CloudGuardFinding = {
  control_id: 'vulnerability',
  severity: 'high',
  title: 'Unpatched CVE-2026-1234 in web server',
};

describe('finding-to-framework suggestions', () => {
  it('suggests technical vulnerability controls from the actual ISO catalog', () => {
    const results = suggestFindingRequirements(finding, iso27001.requirements);
    expect(results.some((result) => result.reference === 'A.8.8')).toBe(true);
    const references = flattenMappingRequirements(iso27001.requirements).map(
      (requirement) => requirement.reference
    );
    expect(results.every((result) => references.includes(result.reference))).toBe(true);
  });

  it('changes requirement references when NIST CSF is selected', () => {
    const results = suggestFindingRequirements(finding, nistCsf.requirements);
    expect(results.some((result) => result.reference === 'ID.RA-01')).toBe(true);
    expect(results.every((result) => !result.reference.startsWith('A.'))).toBe(true);
  });

  it('leaves unknown findings unmapped instead of inventing a control', () => {
    expect(
      suggestFindingRequirements(
        { ...finding, title: 'Unexpected scanner result', recommendation: 'Enable encryption' },
        iso27001.requirements
      )
    ).toEqual([]);
  });

  it('does not infer a mapping from an unrelated resource name', () => {
    expect(
      suggestFindingRequirements(
        { ...finding, title: 'Unexpected result', resource: 'network-backup-logging' },
        nistCsf.requirements
      )
    ).toEqual([]);
  });

  it('never offers category headings as requirements', () => {
    const results = suggestFindingRequirements(finding, [
      {
        reference: 'category',
        title: 'Vulnerability Management',
        description: '',
        isCategory: true,
      },
    ]);
    expect(results).toEqual([]);
  });

  it('keeps separate resources separate in review drafts', () => {
    const control = { control_id: 'control' } as CloudGuardControl;
    expect(findingMappingKey(control, { ...finding, resource: 'host-a' })).not.toBe(
      findingMappingKey(control, { ...finding, resource: 'host-b' })
    );
  });

  it('labels structured scanner resources without exposing their configuration', () => {
    const resource = {
      name: 'bucket-a',
      provider: 'aws',
      region: 'ap-south-1',
      resource_type: 's3',
      config: { secret: 'must-not-display' },
      is_public: true,
    };
    expect(findingResourceLabel(resource)).toBe('bucket-a · aws · ap-south-1 · s3');
    expect(findingResourceLabel({ config: resource.config })).toBe('Resource details unavailable');
    const control = { control_id: 'control' } as CloudGuardControl;
    expect(findingMappingKey(control, { ...finding, resource })).not.toContain('must-not-display');
    expect(findingMappingKey(control, { ...finding, resource })).not.toBe(
      findingMappingKey(control, { ...finding, resource: { ...resource, name: 'bucket-b' } })
    );
  });

  it('uses only HTTPS publisher references with an explicit check date', () => {
    expect(Object.keys(frameworkSources)).toHaveLength(14);
    expect(
      Object.values(frameworkSources).every(
        (source) => source.url.startsWith('https://') && source.checkedOn === '2026-10-12'
      )
    ).toBe(true);
  });

  it('neutralizes formulas and quotes external finding text in CSV', () => {
    expect(mappingCsvCell('=HYPERLINK("evil")')).toBe('"\'=HYPERLINK(""evil"")"');
    expect(mappingCsvCell(' \t+cmd')).toBe('"\' \t+cmd"');
    expect(mappingCsvCell('a,b\nc')).toBe('"a,b\nc"');
  });
});

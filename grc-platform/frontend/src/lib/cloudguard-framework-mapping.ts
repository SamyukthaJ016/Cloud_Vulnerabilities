import type { CloudGuardControl, CloudGuardFinding } from './api/cloudguard.api';
import type { CatalogRequirement } from './api/framework-catalog.api';

export interface FrameworkSource {
  publisher: string;
  url: string;
  checkedOn: string;
  note?: string;
}

// Publisher pages were checked manually. This is not a live synchronization of
// standards or a claim that publishers endorse the application mappings.
const checkedOn = '2026-10-12';
export const frameworkSources: Record<string, FrameworkSource> = {
  'soc2-type2': {
    publisher: 'AICPA & CIMA',
    checkedOn,
    url: 'https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services',
    note: 'AICPA lists the 2017 criteria with revised points of focus (2022).',
  },
  'iso27001-2022': {
    publisher: 'ISO',
    checkedOn,
    url: 'https://www.iso.org/standard/27001',
    note: 'The publisher lists the 2022 edition and an amendment. Use your licensed standard for detailed verification.',
  },
  'nist-csf-2': {
    publisher: 'NIST',
    checkedOn,
    url: 'https://www.nist.gov/cyberframework/informative-references',
  },
  hipaa: {
    publisher: 'HHS',
    checkedOn,
    url: 'https://www.hhs.gov/hipaa/for-professionals/security/index.html',
    note: 'Check whether the affected system processes electronic protected health information.',
  },
  'hitrust-csf': {
    publisher: 'HITRUST',
    checkedOn,
    url: 'https://hitrustalliance.net/advisories/haa-2026-007-csf-version-11.0-11.3-decommission-notice',
    note: 'HITRUST announced that maintenance support for v11.0 and v11.3 has ended. Review the assessment-version transition dates.',
  },
  gdpr: {
    publisher: 'EUR-Lex',
    checkedOn,
    url: 'https://eur-lex.europa.eu/eli/reg/2016/679/oj/eng/',
    note: 'Confirm personal-data scope and applicability before selecting a requirement.',
  },
  'pci-dss-4-0-1': {
    publisher: 'PCI SSC',
    checkedOn,
    url: 'https://blog.pcisecuritystandards.org/just-published-pci-dss-v4-0-1',
    note: 'Confirm cardholder-data environment scope before selecting a requirement.',
  },
  'cis-controls-v8': {
    publisher: 'CIS',
    checkedOn,
    url: 'https://www.cisecurity.org/controls/CIS-controls-navigator',
    note: 'The bundled catalog is v8.0. CIS also publishes v8.1; these suggestions use the bundled edition.',
  },
  'nist-800-53-r5': {
    publisher: 'NIST',
    checkedOn,
    url: 'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
    note: 'NIST lists release 5.2.0 updates. The bundled catalog has not been verified against every release update.',
  },
  'nist-800-171-r2': {
    publisher: 'NIST',
    checkedOn,
    url: 'https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final',
    note: 'NIST withdrew Rev. 2 and superseded it with Rev. 3. Confirm the revision required by your contract.',
  },
  'cmmc-2': {
    publisher: 'U.S. defense department',
    checkedOn,
    url: 'https://business.defense.gov/cmmc/',
    note: 'Check current program requirements, assessment level and contractual scope on the official site.',
  },
  iso27701: {
    publisher: 'ISO',
    checkedOn,
    url: 'https://www.iso.org/standard/27701',
    note: 'Use your licensed 2025 edition to verify the selected requirement.',
  },
  'ccpa-cpra': {
    publisher: 'California Department of Justice',
    checkedOn,
    url: 'https://www.oag.ca.gov/privacy/ccpa',
    note: 'Confirm personal-information scope and applicability before selecting a requirement.',
  },
  'csa-ccm-v4': {
    publisher: 'Cloud Security Alliance',
    checkedOn,
    url: 'https://cloudsecurityalliance.org/artifacts/cloud-controls-matrix-v4',
    note: 'The bundled catalog is v4.0. CSA now publishes v4.1; these suggestions use the bundled edition.',
  },
};

// Narrow issue signals deliberately omit generic terms such as "security",
// "resource", "data" and "risk". Unknown findings stay unmapped.
const topics = [
  {
    name: 'Vulnerability management',
    finding: /\b(cve-\d{4}-\d+|vulnerab\w*|unpatched|outdated|patch\w*)\b/i,
    requirement: /\b(vulnerab\w*|patch\w*|flaw remediation)\b/i,
  },
  {
    name: 'Authentication',
    finding: /\b(mfa|multi[- ]factor|password\w*|authentication|credential\w*)\b/i,
    requirement: /\b(authenticat\w*|password\w*|credential\w*|multi[- ]factor)\b/i,
  },
  {
    name: 'Access control',
    finding:
      /\b(iam|permission\w*|privilege\w*|unauthori[sz]ed|authori[sz]ation|access control|public\w*|exposed|anonymous|bola|idor)\b/i,
    requirement:
      /\b(access control|access rights|access restriction\w*|least privilege|authori[sz]\w*|permissions?)\b/i,
  },
  {
    name: 'Encryption',
    finding: /\b(encrypt\w*|unencrypted|plaintext|cleartext|tls|ssl|cryptograph\w*)\b/i,
    requirement:
      /\b(encrypt\w*|cryptograph\w*|transmission security|data in transit|data at rest)\b/i,
  },
  {
    name: 'Logging',
    finding: /\b(log\w*|cloudtrail|audit trail|audit logging)\b/i,
    requirement: /\b(log\w*|audit controls|audit records?|audit generation|audit trail)\b/i,
  },
  {
    name: 'Network protection',
    finding: /\b(firewall\w*|ingress|egress|ports?|security group|network|segmentation)\b/i,
    requirement: /\b(network\w*|firewall\w*|boundary protection|segmentation)\b/i,
  },
  {
    name: 'Secure configuration',
    finding: /\b(misconfigur\w*|configuration|default settings?|hardening|insecure defaults?)\b/i,
    requirement: /\b(configur\w*|hardening|secure settings?)\b/i,
  },
  {
    name: 'Recovery',
    finding: /\b(backup\w*|recovery|restore|resilience)\b/i,
    requirement: /\b(backup\w*|recovery|restore|resilience)\b/i,
  },
];

export function flattenMappingRequirements(nodes: CatalogRequirement[]): CatalogRequirement[] {
  return nodes.flatMap((node) => [
    ...(!node.isCategory ? [node] : []),
    ...flattenMappingRequirements(node.children || []),
  ]);
}

export interface MappingSuggestion {
  reference: string;
  title: string;
  reason: string;
}

export function suggestFindingRequirements(
  finding: CloudGuardFinding,
  requirements: CatalogRequirement[]
): MappingSuggestion[] {
  // Do not inherit topics from a broad parent control, recommendations or
  // resource names: those can suggest a subject absent from the finding itself.
  const matchedTopics = topics.filter((topic) => topic.finding.test(finding.title));
  if (!matchedTopics.length) return [];
  const candidates = flattenMappingRequirements(requirements).flatMap((requirement) => {
    const titleTopics = matchedTopics.filter((topic) => topic.requirement.test(requirement.title));
    const descriptionTopics = matchedTopics.filter((topic) =>
      topic.requirement.test(requirement.description)
    );
    if (!titleTopics.length && !descriptionTopics.length) return [];
    const matched = titleTopics.length ? titleTopics : descriptionTopics;
    return [
      {
        reference: requirement.reference,
        title: requirement.title,
        reason: `Related topic: ${matched.map((topic) => topic.name).join(', ')}. Verify scope and evidence.`,
        score: titleTopics.length * 3 + descriptionTopics.length,
      },
    ];
  });
  return candidates
    .sort((a, b) => b.score - a.score || a.reference.localeCompare(b.reference))
    .slice(0, 3)
    .map(({ reference, title, reason }) => ({ reference, title, reason }));
}

export function findingMappingKey(control: CloudGuardControl, finding: CloudGuardFinding): string {
  // Connector exposes samples without a durable finding ID. Keys are only for
  // this review draft, never used as persisted scanner finding identities.
  return JSON.stringify([
    control.control_id,
    finding.control_id,
    finding.title,
    finding.resource || '',
    finding.severity,
    finding.recommendation || '',
  ]);
}

export function mappingCsvCell(value: unknown): string {
  let text = String(value ?? '');
  // Findings are external text. Prevent spreadsheet formula execution on export.
  const firstVisible = Array.from(text).find(
    (character) => character.charCodeAt(0) > 31 && !/\s/.test(character)
  );
  if (firstVisible && '=+@-'.includes(firstVisible)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

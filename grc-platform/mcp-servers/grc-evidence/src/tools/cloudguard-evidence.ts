type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

interface CloudGuardFinding {
  id?: string;
  title?: string;
  name?: string;
  severity?: Severity | string;
  source?: string;
  provider?: string;
  service?: string;
  resource?: string;
  evidence?: unknown;
  remediation?: string;
  cve?: string;
  cves?: string[];
  risk_score?: number;
  url?: string;
  host?: string;
  port?: string | number;
}

interface CloudGuardEvidenceParams {
  sourceName?: string;
  scanId?: string;
  target?: string;
  findings?: CloudGuardFinding[];
  raw?: {
    findings?: CloudGuardFinding[];
    vulnerabilities?: CloudGuardFinding[];
    results?: CloudGuardFinding[];
    summary?: string;
    target?: string;
    domains?: unknown[];
    subdomains?: unknown[];
    urls?: unknown[];
    ports?: unknown[];
    open_ports?: unknown[];
    services?: unknown[];
    technologies?: unknown[];
    risk_score?: number;
  };
}

const CONTROL_RULES = [
  {
    family: 'Access Control',
    keywords: ['iam', 'mfa', 'role', 'policy', 'privilege', 'permission', 'wildcard', 'credential'],
  },
  {
    family: 'Network Security',
    keywords: ['security group', 'firewall', '0.0.0.0/0', 'ssh', 'rdp', 'open port', 'public ip'],
  },
  {
    family: 'Data Protection',
    keywords: ['s3', 'bucket', 'database', 'rds', 'sql', 'encryption', 'public', 'storage'],
  },
  {
    family: 'Logging and Monitoring',
    keywords: ['cloudtrail', 'logging', 'monitoring', 'audit log', 'guardduty', 'alert'],
  },
  {
    family: 'Vulnerability Management',
    keywords: ['cve', 'vulnerability', 'nuclei', 'nikto', 'trivy', 'zap', 'outdated'],
  },
  {
    family: 'Asset Management',
    keywords: ['asset', 'inventory', 'kubernetes', 'pod', 'namespace', 'container', 'service'],
  },
  {
    family: 'Incident Response',
    keywords: ['incident', 'response', 'forensic', 'containment', 'recovery'],
  },
  {
    family: 'Policy and Governance',
    keywords: ['policy', 'governance', 'compliance', 'approval', 'exception'],
  },
];

function normalizeSeverity(value?: string): Severity {
  const severity = value?.toLowerCase();
  if (severity === 'critical' || severity === 'high' || severity === 'medium' || severity === 'low') {
    return severity;
  }
  return 'info';
}

function mapControl(finding: CloudGuardFinding): string {
  const haystack = [
    finding.title,
    finding.name,
    finding.source,
    finding.provider,
    finding.service,
    finding.resource,
    finding.remediation,
  ]
    .filter(Boolean)
    .join(' ')
    .toLowerCase();

  return CONTROL_RULES.find((rule) => rule.keywords.some((keyword) => haystack.includes(keyword)))?.family
    || 'Policy and Governance';
}

function extractFindings(params: CloudGuardEvidenceParams): CloudGuardFinding[] {
  const explicitFindings = (
    params.findings
    || params.raw?.findings
    || params.raw?.vulnerabilities
    || params.raw?.results
    || []
  );

  if (explicitFindings.length > 0) {
    return explicitFindings;
  }

  const raw = params.raw;
  if (!raw) {
    return [];
  }

  const reconFindings: CloudGuardFinding[] = [];
  const target = params.target || raw.target || 'scanner target';

  const addReconFinding = (title: string, source: string, count: number, severity: Severity) => {
    if (count > 0) {
      reconFindings.push({
        id: source.toLowerCase().replace(/\s+/g, '-'),
        title,
        severity,
        source: 'local-mcp-recon',
        provider: 'Ishan MCP Scanner',
        service: source,
        resource: String(target),
        evidence: { count },
        remediation: 'Review discovered assets, remove unused exposure, and validate with confirmed vulnerability tools.',
      });
    }
  };

  addReconFinding('Subdomains discovered by MCP reconnaissance', 'Subfinder', raw.subdomains?.length || raw.domains?.length || 0, 'medium');
  addReconFinding('URLs discovered for attack surface review', 'httpx/ffuf', raw.urls?.length || 0, 'medium');
  addReconFinding('Open ports discovered on target', 'naabu/nmap', raw.open_ports?.length || raw.ports?.length || 0, 'high');
  addReconFinding('Services and technologies fingerprinted', 'whatweb/httpx', raw.services?.length || raw.technologies?.length || 0, 'medium');

  if (typeof raw.summary === 'string' && raw.summary.trim()) {
    reconFindings.push({
      id: 'executive-recon-summary',
      title: 'Executive reconnaissance summary received from local MCP scanner',
      severity: typeof raw.risk_score === 'number' && raw.risk_score >= 70 ? 'high' : 'medium',
      source: 'local-mcp-recon',
      provider: 'Ishan MCP Scanner',
      service: 'scan_summary.json',
      resource: String(target),
      evidence: raw.summary.slice(0, 2000),
      remediation: 'Use this reconnaissance evidence to prioritize CVE enrichment, exposure validation, and owner review.',
    });
  }

  return reconFindings;
}

export async function normalizeCloudGuardEvidence(params: CloudGuardEvidenceParams) {
  const findings = extractFindings(params);
  const sourceName = params.sourceName || 'CloudGuard';
  const collectedAt = new Date().toISOString();

  const evidence = findings.map((finding, index) => {
    const severity = normalizeSeverity(finding.severity);
    const controlFamily = mapControl(finding);
    const cves = finding.cves || (finding.cve ? [finding.cve] : []);

    return {
      evidenceId: `cg-${params.scanId || 'scan'}-${finding.id || index + 1}`,
      sourceSystem: sourceName,
      scannerType: finding.provider || finding.source || 'cloudguard',
      target: params.target || finding.resource || finding.host || finding.url || 'unknown',
      title: finding.title || finding.name || 'CloudGuard finding',
      severity,
      status: severity === 'critical' || severity === 'high' ? 'needs_review' : 'evidence_collected',
      auditStatus: severity === 'critical' ? 'failed' : 'needs_review',
      msmeControlFamily: controlFamily,
      cves,
      remediation:
        finding.remediation
        || 'Review the affected resource, reduce exposure, and attach remediation evidence after fixing.',
      payload: finding,
      collectedAt,
    };
  });

  const summary = evidence.reduce(
    (acc, item) => {
      acc.total += 1;
      acc.bySeverity[item.severity] = (acc.bySeverity[item.severity] || 0) + 1;
      acc.byControl[item.msmeControlFamily] = (acc.byControl[item.msmeControlFamily] || 0) + 1;
      return acc;
    },
    {
      total: 0,
      bySeverity: {} as Record<string, number>,
      byControl: {} as Record<string, number>,
    }
  );

  return {
    sourceName,
    scanId: params.scanId || null,
    target: params.target || null,
    normalizedAt: collectedAt,
    framework: 'CERT-In MSME Cybersecurity',
    summary,
    evidence,
  };
}

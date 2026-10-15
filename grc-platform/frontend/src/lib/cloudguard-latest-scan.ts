import type { CloudGuardControl, CloudGuardScanSnapshot } from './api/cloudguard.api';

export function latestScanControls(scan?: CloudGuardScanSnapshot | null): CloudGuardControl[] {
  const groups = new Map<string, CloudGuardControl>();
  for (const finding of scan?.findings || []) {
    let control = groups.get(finding.control_id);
    if (!control) {
      control = {
        control_id: finding.control_id, control_name: finding.control_id,
        framework: scan!.provider, status: 'no_evidence', evidence_count: 0,
        finding_count: 0, severity_counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        sources: [], sample_findings: [],
      };
      groups.set(finding.control_id, control);
    }
    control.finding_count++;
    control.severity_counts[finding.severity]++;
    control.sample_findings.push(finding);
    const source = finding.tool || finding.provider;
    if (!control.sources.includes(source)) control.sources.push(source);
    control.status = control.severity_counts.critical || control.severity_counts.high ? 'non_compliant' : 'partial';
  }
  return [...groups.values()];
}

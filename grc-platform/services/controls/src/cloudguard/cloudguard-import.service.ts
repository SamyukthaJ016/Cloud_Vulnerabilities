import { BadGatewayException, ConflictException, Inject, Injectable, NotFoundException } from '@nestjs/common';
import { createHash } from 'crypto';
import { RiskLevel } from '@prisma/client';
import { CacheKeys, CacheService, STORAGE_PROVIDER, StorageProvider } from '@gigachad-grc/shared';
import { PrismaService } from '../prisma/prisma.service';
import { AuditService } from '../audit/audit.service';
import { CloudGuardService } from './cloudguard.service';

type Finding = {
  id: number; severity: string; title: string; description: string;
  resource: string; resource_type: string; provider: string; recommendation?: string;
};
type Scan = {
  id: number; provider: string; account_id: string; started_at: string | null;
  resource_count: number; finding_count: number; findings: Finding[];
};

function hash(value: string) { return createHash('sha256').update(value).digest('hex'); }

export function scanEvidenceId(organizationId: string, scanId: number) {
  const hex = hash(`cloudguard\0${organizationId}\0${scanId}`);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-a${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

export function findingRiskId(scan: Scan, finding: Finding) {
  const description = finding.description.replace(/^(?:\[[^\]]+\]\s*)+/, '').trim();
  return `CG-${hash(JSON.stringify([scan.provider, scan.account_id, finding.resource_type, finding.resource, description])).slice(0, 24).toUpperCase()}`;
}

@Injectable()
export class CloudGuardImportService {
  constructor(
    private readonly cloudguard: CloudGuardService,
    private readonly prisma: PrismaService,
    private readonly audit: AuditService,
    private readonly cache: CacheService,
    @Inject(STORAGE_PROVIDER) private readonly storage: StorageProvider,
  ) {}

  async importLatest(organizationId: string, userId: string, scanId: number) {
    const dashboard = await this.cloudguard.getDashboard(organizationId);
    if (dashboard.tenant_id !== organizationId) throw new BadGatewayException('CloudGuard returned data for a different organization.');
    const scan = dashboard.latest_scan as Scan | null | undefined;
    if (!scan) throw new NotFoundException('No completed CloudGuard scan is available.');
    if (scan.id !== scanId) throw new ConflictException('A newer scan has completed. Refresh and review it before importing.');
    if (!Array.isArray(scan.findings) || scan.finding_count !== scan.findings.length || scan.findings.some(f =>
      !Number.isInteger(f.id) || typeof f.resource !== 'string' || typeof f.description !== 'string' ||
      typeof f.title !== 'string' || !['critical', 'high', 'medium', 'low', 'info'].includes(f.severity))) {
      throw new BadGatewayException('CloudGuard returned an invalid scan report.');
    }

    const evidenceId = scanEvidenceId(organizationId, scan.id);
    const report = Buffer.from(JSON.stringify({ source: 'CloudGuard', scan }, null, 2));
    const checksum = hash(report.toString());
    const filename = `cloudguard-scan-${scan.id}.json`;
    const storagePath = `evidence/${organizationId}/${evidenceId}/${checksum}/${filename}`;
    // Reports are immutable and include no connector credentials or resource configuration secrets.
    if (!(await this.storage.exists(storagePath))) {
      await this.storage.upload(report, storagePath, { contentType: 'application/json' });
    }

    const result = await this.prisma.$transaction(async tx => {
      await tx.$executeRaw`SELECT pg_advisory_xact_lock(hashtext(${`cloudguard-import:${organizationId}`}))`;
      const existingEvidence = await tx.evidence.findUnique({ where: { id: evidenceId } });
      if (existingEvidence && (existingEvidence.organizationId !== organizationId || existingEvidence.deletedAt)) {
        throw new ConflictException('This scan evidence is unavailable or was deleted. It will not be recreated automatically.');
      }
      if (existingEvidence && (existingEvidence.metadata as Record<string, unknown>)?.sha256 !== checksum) {
        throw new ConflictException('The imported scan report has changed. Existing evidence will not be overwritten.');
      }
      if (!existingEvidence) {
        await tx.evidence.create({ data: {
          id: evidenceId, organizationId, title: `CloudGuard scan #${scan.id} — ${scan.provider}`,
          description: `${scan.finding_count} scanner findings across ${scan.resource_count} resources. Informational observations are retained in this report but are not registered as risks.`,
          type: 'report', source: 'cloudguard', status: 'pending_review', filename,
          mimeType: 'application/json', size: report.length, storagePath,
          collectedAt: scan.started_at ? new Date(scan.started_at) : new Date(),
          validFrom: new Date(), tags: ['cloudguard', `scan:${scan.id}`, scan.provider],
          metadata: { scanId: scan.id, sha256: checksum, findingCount: scan.finding_count },
          createdBy: userId, updatedBy: userId,
        } });
      }
      let createdRisks = 0, existingRisks = 0, deletedRisksSkipped = 0, newObservations = 0;
      const risks: Array<{ id: string; riskId: string }> = [];
      const seen = new Set<string>();
      for (const finding of scan.findings) {
        if (finding.severity === 'info') continue;
        const riskId = findingRiskId(scan, finding);
        if (seen.has(riskId)) continue;
        seen.add(riskId);
        let risk = await tx.risk.findUnique({ where: { organizationId_riskId: { organizationId, riskId } } });
        if (risk?.deletedAt) { deletedRisksSkipped++; continue; }
        if (!risk) {
          risk = await tx.risk.create({ data: {
            organizationId, riskId, title: finding.title,
            description: `${finding.description}\n\nResource: ${finding.resource}\nCloudGuard scan #${scan.id}, finding #${finding.id}\nEvidence report: /evidence/${evidenceId}\n\nRemediation: ${finding.recommendation || 'Review the affected resource and scanner guidance.'}`,
            category: 'security', source: 'internal_security_reviews', status: 'risk_identified',
            initialSeverity: finding.severity === 'critical' ? RiskLevel.very_high : finding.severity as RiskLevel,
            reporterId: userId, createdBy: userId,
            tags: ['cloudguard', scan.provider],
            documentation: [{ type: 'evidence', evidenceId, url: `/evidence/${evidenceId}`, source: 'cloudguard', scanId: scan.id, findingId: finding.id }],
          } });
          createdRisks++;
        } else {
          // Preserve assessments, workflow, ownership, treatment, severity and review decisions.
          existingRisks++;
        }
        const notes = `CloudGuard scan #${scan.id}, finding #${finding.id}. Evidence: /evidence/${evidenceId}`;
        const observation = await tx.riskHistory.findFirst({ where: { riskId: risk.id, action: 'cloudguard_observed', notes } });
        if (!observation) {
          await tx.riskHistory.create({ data: { riskId: risk.id, action: 'cloudguard_observed', notes, changedBy: userId } });
          newObservations++;
        }
        risks.push({ id: risk.id, riskId: risk.riskId });
      }
      return { scanId: scan.id, evidenceId, evidenceCreated: !existingEvidence, createdRisks, existingRisks, deletedRisksSkipped,
        informationalFindings: scan.findings.filter(f => f.severity === 'info').length, risks, newObservations };
    }, { timeout: 30_000 });

    if (result.evidenceCreated || result.newObservations) {
      await this.audit.log({ organizationId, userId, action: 'cloudguard_scan_imported',
        entityType: 'evidence', entityId: evidenceId, entityName: filename,
        description: `Imported CloudGuard scan #${scan.id}: ${result.createdRisks} new risks, ${result.existingRisks} existing risks.`,
        metadata: { scanId: scan.id, createdRisks: result.createdRisks, existingRisks: result.existingRisks },
      });
    }
    await Promise.all([
      `dashboard:full:${organizationId}`, CacheKeys.dashboard(organizationId),
      `risk:dashboard:${organizationId}`, CacheKeys.riskMatrix(organizationId), CacheKeys.riskList(organizationId),
    ].map(key => this.cache.del(key)));
    return result;
  }
}

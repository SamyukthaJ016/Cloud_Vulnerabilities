import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  FindingStatus,
  Prisma,
  ScanStatus,
  ScannerAvailability,
  Severity,
} from '@prisma/client';
import axios from 'axios';
import { createHash } from 'crypto';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { NormalizerService } from './normalizer.service';
import { ArtifactsService } from './artifacts.service';

const CLOUD_SCANNER_KEY = 'cloud';
const CLOUD_SCANNER_NAME = 'CloudGuard';
const CLOUD_SCANNER_BASE_ENV_KEY = 'CLOUDGUARD_BASE_URL';
const CLOUD_SYNC_TTL_MS = 20_000;
const CLOUD_SYNC_SCAN_LIMIT = 20;
const CLOUD_SYNC_REQUEST_TIMEOUT_MS = 20_000;
const DEFAULT_SEVERITY_COUNTS = {
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  INFO: 0,
} as const;

interface CloudguardScanRow {
  id: number | string;
  cloud: string;
  account_id: string | null;
  status: string;
  started_at: string | null;
  duration_seconds: number | null;
  resource_count: number | null;
  finding_count: number | null;
  critical_count: number | null;
}

interface CloudguardScansResponse {
  status?: string;
  scans?: CloudguardScanRow[];
}

interface CloudguardFindingRow {
  resource_name: string | null;
  cloud: string | null;
  severity: string;
  description: string | null;
  tool: string | null;
  timestamp: string | null;
}

interface CloudguardFindingsResponse {
  status?: string;
  data?: CloudguardFindingRow[];
}

interface RecentSummaryDto {
  metrics: {
    scansLast30Days: number;
    openFindings: number;
    activeScanners: number;
    totalFindings: number;
  };
  recent: {
    scans: Array<{
      id: string;
      scannerKey: string;
      status: ScanStatus;
      completedAt: string | null;
      summary: Record<Severity, number> | null;
    }>;
    findings: Array<{
      id: string;
      title: string;
      severity: Severity;
      scannerKey: string;
      createdAt: string;
    }>;
  };
}

@Injectable()
export class FindingsService {
  private readonly logger = new Logger(FindingsService.name);
  private readonly syncState = new Map<string, number>();

  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
    private readonly normalizer: NormalizerService,
    private readonly artifacts: ArtifactsService,
  ) {}

  /**
   * Flow K1 → M1. Reserved for v2 — scanner v1 redirects to the scanner's own
   * dashboard rather than ingesting findings into CP.
   * Normalizes, tags with orgId/scanJobId/scannerKey, stores findings + artifacts.
   *
   * Must be idempotent: if called twice for the same callback, the second call
   * should not duplicate findings (dedupe by (scanJobId, externalId) or by
   * (scanJobId, title) if externalId is missing).
   */
  async ingestFromCallback(
    scanJob: { id: string; orgId: string; scannerKey: string },
    rawFindings: unknown,
  ): Promise<void> {
    const normalized = this.normalizer.normalize(scanJob.scannerKey, rawFindings);
    await this.syncScanFindings(scanJob.orgId, scanJob.id, scanJob.scannerKey, normalized);
  }

  /** Flow T1 → V1. */
  async listForOrg(orgId: string, userId: string, params: {
    scanJobId?: string;
    severity?: string[];
    status?: string[];
    scannerKey?: string;
    page?: number;
    pageSize?: number;
  }) {
    await this.syncCloudMirror(orgId, userId);

    const where: Prisma.FindingWhereInput = { orgId };
    if (params.scanJobId) where.scanJobId = params.scanJobId;
    if (params.scannerKey) where.scannerKey = params.scannerKey;
    if (params.severity?.length) where.severity = { in: params.severity as Severity[] };
    if (params.status?.length) where.status = { in: params.status as FindingStatus[] };

    const findings = await this.prisma.finding.findMany({
      where,
      orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
      take: params.pageSize ?? 100,
      skip: params.page && params.pageSize ? (params.page - 1) * params.pageSize : undefined,
    });

    return findings.map(toFindingDto);
  }

  async getById(orgId: string, userId: string, id: string) {
    await this.syncCloudMirror(orgId, userId);

    const finding = await this.prisma.finding.findFirst({
      where: { id, orgId },
    });
    if (!finding) throw new NotFoundException('Finding not found');
    return toFindingDto(finding);
  }

  /** For dashboard (flow X5 / W). */
  async getRecentSummary(orgId: string, userId: string): Promise<RecentSummaryDto> {
    await this.syncCloudMirror(orgId, userId);

    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const [scansLast30Days, openFindings, activeScanners, totalFindings, recentScans, recentFindings] =
      await Promise.all([
        this.prisma.scanJob.count({
          where: {
            orgId,
            scanner: { key: CLOUD_SCANNER_KEY },
            queuedAt: { gte: thirtyDaysAgo },
          },
        }),
        this.prisma.finding.count({
          where: {
            orgId,
            status: { notIn: [FindingStatus.RESOLVED, FindingStatus.FALSE_POSITIVE] },
          },
        }),
        this.prisma.scanner.count({
          where: {
            availability: ScannerAvailability.AVAILABLE,
            key: { not: CLOUD_SCANNER_KEY },
          },
        }),
        this.prisma.finding.count({ where: { orgId } }),
        this.prisma.scanJob.findMany({
          where: { orgId, scanner: { key: CLOUD_SCANNER_KEY } },
          orderBy: [{ queuedAt: 'desc' }, { id: 'desc' }],
          take: 5,
        }),
        this.prisma.finding.findMany({
          where: { orgId },
          orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
          take: 5,
        }),
      ]);

    return {
      metrics: {
        scansLast30Days,
        openFindings,
        activeScanners,
        totalFindings,
      },
      recent: {
        scans: recentScans.map((scan) => ({
          id: scan.id,
          scannerKey: CLOUD_SCANNER_KEY,
          status: scan.status,
          completedAt: scan.completedAt?.toISOString() ?? null,
          summary: toSummaryRecord(scan.summary),
        })),
        findings: recentFindings.map((finding) => ({
          id: finding.id,
          title: finding.title,
          severity: finding.severity,
          scannerKey: finding.scannerKey,
          createdAt: finding.createdAt.toISOString(),
        })),
      },
    };
  }

  async updateStatus(orgId: string, id: string, status: string) {
    if (!isFindingStatus(status)) {
      throw new NotFoundException(`Invalid finding status '${status}'`);
    }

    const finding = await this.prisma.finding.findFirst({
      where: { id, orgId },
    });
    if (!finding) throw new NotFoundException('Finding not found');

    const updated = await this.prisma.finding.update({
      where: { id },
      data: { status },
    });
    return toFindingDto(updated);
  }

  async syncCloudMirror(orgId: string, userId: string, force = false): Promise<void> {
    const lastSyncedAt = this.syncState.get(orgId) ?? 0;
    const now = Date.now();
    if (!force && now - lastSyncedAt < CLOUD_SYNC_TTL_MS) {
      return;
    }
    this.syncState.set(orgId, now);

    try {
      const scanner = await this.ensureCloudScanner();
      const scans = await this.fetchCloudguardScans();

      for (const scan of scans) {
        await this.syncCloudguardScan(orgId, userId, scanner.id, scan);
      }
    } catch (error) {
      this.logger.warn(
        `CloudGuard mirror sync failed for org ${orgId}: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }

  private async ensureCloudScanner() {
    const baseUrl = this.getCloudguardBaseUrl();
    return this.prisma.scanner.upsert({
      where: { key: CLOUD_SCANNER_KEY },
      create: {
        key: CLOUD_SCANNER_KEY,
        name: CLOUD_SCANNER_NAME,
        description: 'Mirrored CloudGuard cloud scan results',
        version: '1.0.0',
        category: 'cloud',
        baseUrlEnvKey: CLOUD_SCANNER_BASE_ENV_KEY,
        credentialSchema: {},
        dashboardBaseUrl: `${baseUrl}/dashboard`,
        availability: ScannerAvailability.AVAILABLE,
        manifestFetchedAt: new Date(),
      },
      update: {
        name: CLOUD_SCANNER_NAME,
        description: 'Mirrored CloudGuard cloud scan results',
        category: 'cloud',
        baseUrlEnvKey: CLOUD_SCANNER_BASE_ENV_KEY,
        dashboardBaseUrl: `${baseUrl}/dashboard`,
        availability: ScannerAvailability.AVAILABLE,
        lastError: null,
        manifestFetchedAt: new Date(),
      },
    });
  }

  private async fetchCloudguardScans(): Promise<CloudguardScanRow[]> {
    const response = await axios.get<CloudguardScansResponse>(
      `${this.getCloudguardBaseUrl()}/api/scans`,
      {
        params: {
          user_id: this.getCloudguardUserId(),
          limit: CLOUD_SYNC_SCAN_LIMIT,
          offset: 0,
        },
        timeout: CLOUD_SYNC_REQUEST_TIMEOUT_MS,
      },
    );
    return response.data.scans ?? [];
  }

  private async fetchCloudguardFindings(scanId: string, limit: number): Promise<CloudguardFindingRow[]> {
    if (limit <= 0) return [];
    const response = await axios.get<CloudguardFindingsResponse>(
      `${this.getCloudguardBaseUrl()}/api/latest-findings`,
      {
        params: {
          user_id: this.getCloudguardUserId(),
          scan_ids: scanId,
          limit,
        },
        timeout: CLOUD_SYNC_REQUEST_TIMEOUT_MS,
      },
    );
    return response.data.data ?? [];
  }

  private async syncCloudguardScan(
    orgId: string,
    userId: string,
    scannerId: string,
    scan: CloudguardScanRow,
  ) {
    const externalScanId = String(scan.id);
    const startedAt = scan.started_at ? new Date(scan.started_at) : null;
    const durationSeconds = Number(scan.duration_seconds ?? 0);
    const completedAt =
      startedAt && durationSeconds > 0
        ? new Date(startedAt.getTime() + durationSeconds * 1000)
        : startedAt;
    const status = toScanStatus(scan.status);

    const existing = await this.prisma.scanJob.findFirst({
      where: {
        orgId,
        scannerId,
        externalScanId,
      },
    });

    const job = existing
      ? await this.prisma.scanJob.update({
          where: { id: existing.id },
          data: {
            status,
            queuedAt: startedAt ?? existing.queuedAt,
            startedAt: startedAt ?? existing.startedAt,
            completedAt: status === ScanStatus.COMPLETED || status === ScanStatus.FAILED ? completedAt : null,
            metadata: {
              source: 'cloudguard',
              cloudProvider: scan.cloud,
              accountId: scan.account_id,
              resourceCount: scan.resource_count ?? 0,
              totalFindings: scan.finding_count ?? 0,
            },
          },
        })
      : await this.prisma.scanJob.create({
          data: {
            orgId,
            scannerId,
            triggeredById: userId,
            externalScanId,
            status,
            queuedAt: startedAt ?? new Date(),
            startedAt,
            completedAt: status === ScanStatus.COMPLETED || status === ScanStatus.FAILED ? completedAt : null,
            metadata: {
              source: 'cloudguard',
              cloudProvider: scan.cloud,
              accountId: scan.account_id,
              resourceCount: scan.resource_count ?? 0,
              totalFindings: scan.finding_count ?? 0,
            },
          },
        });

    const mirroredFindings = await this.fetchCloudguardFindings(
      externalScanId,
      Math.min(Math.max(Number(scan.finding_count ?? 0), 0), 500),
    );
    const normalized = mirroredFindings.map((finding) =>
      normalizeCloudguardFinding(externalScanId, finding),
    );
    const severitySummary = countSeverities(normalized);

    await this.prisma.scanJob.update({
      where: { id: job.id },
      data: {
        summary: severitySummary,
      },
    });

    await this.syncScanFindings(orgId, job.id, CLOUD_SCANNER_KEY, normalized);
  }

  private async syncScanFindings(
    orgId: string,
    scanJobId: string,
    scannerKey: string,
    findings: NormalizedDbFinding[],
  ) {
    const existing = await this.prisma.finding.findMany({
      where: { orgId, scanJobId },
    });
    const existingByKey = new Map(existing.map((finding) => [buildFindingKey(finding), finding]));
    const seen = new Set<string>();

    for (const finding of findings) {
      const key = buildFindingKey(finding);
      const previous = existingByKey.get(key);
      seen.add(key);

      if (previous) {
        await this.prisma.finding.update({
          where: { id: previous.id },
          data: {
            externalId: finding.externalId ?? previous.externalId,
            title: finding.title,
            description: finding.description ?? null,
            severity: finding.severity,
            resource: finding.resource ?? null,
            evidence: toNullableJsonValue(finding.evidence),
            recommendation: finding.recommendation ?? null,
            tags: finding.tags,
          },
        });
        continue;
      }

      await this.prisma.finding.create({
        data: {
          orgId,
          scanJobId,
          scannerKey,
          externalId: finding.externalId ?? null,
          title: finding.title,
          description: finding.description ?? null,
          severity: finding.severity,
          resource: finding.resource ?? null,
          evidence: toNullableJsonValue(finding.evidence),
          recommendation: finding.recommendation ?? null,
          tags: finding.tags,
        },
      });
    }

    const staleIds = existing
      .filter((finding) => !seen.has(buildFindingKey(finding)))
      .map((finding) => finding.id);

    if (staleIds.length) {
      await this.prisma.finding.deleteMany({
        where: { id: { in: staleIds } },
      });
    }
  }

  private getCloudguardBaseUrl(): string {
    return this.config.get<string>('cloudguard.baseUrl') || 'https://cloud-vulnerabilities.vercel.app';
  }

  private getCloudguardUserId(): string {
    return this.config.get<string>('cloudguard.userId') || 'anonymous';
  }
}

interface NormalizedDbFinding {
  externalId?: string;
  title: string;
  description?: string;
  severity: Severity;
  resource?: string;
  evidence?: Record<string, unknown>;
  recommendation?: string;
  tags: string[];
}

function normalizeCloudguardFinding(
  scanId: string,
  finding: CloudguardFindingRow,
): NormalizedDbFinding {
  const title = finding.description?.split('. ')[0]?.trim() || 'Cloud finding';
  const timestamp = finding.timestamp ?? '';
  const externalId = createHash('sha1')
    .update([scanId, finding.resource_name ?? '', finding.severity, finding.description ?? '', timestamp].join('|'))
    .digest('hex');

  return {
    externalId,
    title,
    description: finding.description ?? undefined,
    severity: toSeverity(finding.severity),
    resource: finding.resource_name ?? undefined,
    evidence: {
      source: 'cloudguard',
      cloud: finding.cloud,
      tool: finding.tool,
      timestamp: finding.timestamp,
    },
    tags: [CLOUD_SCANNER_KEY, finding.cloud, finding.tool].filter(Boolean) as string[],
  };
}

function countSeverities(findings: NormalizedDbFinding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  };
  for (const finding of findings) {
    counts[finding.severity] += 1;
  }
  return counts;
}

function buildFindingKey(
  finding:
    | NormalizedDbFinding
    | {
        externalId: string | null;
        title: string;
        resource: string | null;
        severity: Severity;
      },
) {
  return finding.externalId || [finding.title, finding.resource ?? '', finding.severity].join('|');
}

function toFindingDto(finding: {
  id: string;
  scanJobId: string;
  scannerKey: string;
  externalId: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  resource: string | null;
  evidence: Prisma.JsonValue | null;
  recommendation: string | null;
  status: FindingStatus;
  tags: string[];
  createdAt: Date;
  updatedAt: Date;
}) {
  return {
    id: finding.id,
    scanJobId: finding.scanJobId,
    scannerKey: finding.scannerKey,
    externalId: finding.externalId,
    title: finding.title,
    description: finding.description,
    severity: finding.severity,
    resource: finding.resource,
    evidence: (finding.evidence as Record<string, unknown> | null) ?? null,
    recommendation: finding.recommendation,
    status: finding.status,
    tags: finding.tags,
    createdAt: finding.createdAt.toISOString(),
    updatedAt: finding.updatedAt.toISOString(),
  };
}

function toSeverity(value: string): Severity {
  switch (String(value).toUpperCase()) {
    case 'CRITICAL':
      return Severity.CRITICAL;
    case 'HIGH':
      return Severity.HIGH;
    case 'MEDIUM':
      return Severity.MEDIUM;
    case 'LOW':
      return Severity.LOW;
    default:
      return Severity.INFO;
  }
}

function toSummaryRecord(summary: Prisma.JsonValue | null): Record<Severity, number> | null {
  if (!summary || typeof summary !== 'object' || Array.isArray(summary)) {
    return null;
  }
  const source = summary as Record<string, unknown>;
  return {
    CRITICAL: Number(source.CRITICAL ?? source.critical ?? DEFAULT_SEVERITY_COUNTS.CRITICAL),
    HIGH: Number(source.HIGH ?? source.high ?? DEFAULT_SEVERITY_COUNTS.HIGH),
    MEDIUM: Number(source.MEDIUM ?? source.medium ?? DEFAULT_SEVERITY_COUNTS.MEDIUM),
    LOW: Number(source.LOW ?? source.low ?? DEFAULT_SEVERITY_COUNTS.LOW),
    INFO: Number(source.INFO ?? source.info ?? DEFAULT_SEVERITY_COUNTS.INFO),
  };
}

function toNullableJsonValue(
  value: Record<string, unknown> | undefined,
): Prisma.NullableJsonNullValueInput | Prisma.InputJsonValue | undefined {
  if (value === undefined) {
    return undefined;
  }
  return value as Prisma.InputJsonValue;
}

function toScanStatus(status: string): ScanStatus {
  switch (String(status).toUpperCase()) {
    case 'RUNNING':
      return ScanStatus.RUNNING;
    case 'FAILED':
      return ScanStatus.FAILED;
    case 'COMPLETED':
      return ScanStatus.COMPLETED;
    default:
      return ScanStatus.DISPATCHED;
  }
}

function isFindingStatus(status: string): status is FindingStatus {
  return [
    FindingStatus.OPEN,
    FindingStatus.TRIAGED,
    FindingStatus.ACCEPTED,
    FindingStatus.RESOLVED,
    FindingStatus.FALSE_POSITIVE,
  ].includes(status as FindingStatus);
}

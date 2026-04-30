import { Injectable } from '@nestjs/common';
import { BaseConnector } from './base-connector';

export interface CloudGuardConfig {
  baseUrl: string;
  cloudguardUserId?: string;
  latestOnly?: boolean;
  scanLimit?: number | string;
  findingLimit?: number | string;
}

interface CloudGuardScan {
  id: number;
  cloud: string;
  account_id?: string | null;
  status?: string;
  started_at?: string | null;
  duration_seconds?: number | null;
  resource_count?: number;
  finding_count?: number;
  critical_count?: number;
}

interface CloudGuardFinding {
  resource_name?: string;
  cloud?: string;
  severity?: string;
  description?: string;
  tool?: string | null;
  timestamp?: string | null;
}

interface CloudGuardInfo {
  app_name?: string;
  version?: string;
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, '');
}

function parsePositiveInt(value: number | string | undefined, fallback: number): number {
  if (value === undefined || value === null || value === '') {
    return fallback;
  }

  const parsed = typeof value === 'number' ? value : parseInt(String(value), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

@Injectable()
export class CloudGuardConnector extends BaseConnector {
  constructor() {
    super('CloudGuardConnector');
  }

  private createCloudGuardClient(config: CloudGuardConfig) {
    const headers: Record<string, string> = {
      Accept: 'application/json',
    };

    if (config.cloudguardUserId) {
      headers.Cookie = `cloudguard_user_id=${config.cloudguardUserId}`;
    }

    // CloudGuard runs on Vercel and can take longer on cold starts,
    // especially before the worker-backed scan data endpoints warm up.
    return this.createClient(normalizeBaseUrl(config.baseUrl), headers, 90000);
  }

  async testConnection(config: CloudGuardConfig): Promise<{ success: boolean; message: string; details?: any }> {
    if (!config.baseUrl) {
      return { success: false, message: 'Base URL is required' };
    }

    try {
      const client = this.createCloudGuardClient(config);
      const [healthResult, infoResult] = await Promise.all([
        this.get<any>('/health', { client }),
        this.get<CloudGuardInfo>('/api/info', { client }),
      ]);

      if (healthResult.error) {
        return { success: false, message: healthResult.error };
      }

      if (infoResult.error) {
        return { success: false, message: infoResult.error };
      }

      return {
        success: true,
        message: `Connected to CloudGuard at ${normalizeBaseUrl(config.baseUrl)}`,
        details: {
          health: healthResult.data,
          info: infoResult.data,
        },
      };
    } catch (error: any) {
      return { success: false, message: error.message || 'Connection test failed' };
    }
  }

  async sync(config: CloudGuardConfig): Promise<any> {
    const baseUrl = normalizeBaseUrl(config.baseUrl || '');
    if (!baseUrl) {
      throw new Error('Base URL is required');
    }

    const client = this.createCloudGuardClient(config);
    const latestOnly = config.latestOnly !== false;
    const scanLimit = parsePositiveInt(config.scanLimit, 20);
    const findingLimit = parsePositiveInt(config.findingLimit, 250);

    const scansPath = latestOnly
      ? `/api/scans?latest_only=true&limit=${scanLimit}`
      : `/api/scans?limit=${scanLimit}`;

    const scansResult = await this.get<{ scans?: CloudGuardScan[] }>(scansPath, { client });
    if (scansResult.error) {
      throw new Error(`Failed to fetch scans: ${scansResult.error}`);
    }

    const scans = scansResult.data?.scans || [];
    const scanIds = scans.map((scan) => scan.id).filter(Boolean).join(',');
    const findingsPath = scanIds
      ? `/api/latest-findings?limit=${findingLimit}&scan_ids=${scanIds}`
      : `/api/latest-findings?limit=${findingLimit}`;

    const findingsResult = await this.get<{ data?: CloudGuardFinding[] }>(findingsPath, { client });
    if (findingsResult.error) {
      throw new Error(`Failed to fetch findings: ${findingsResult.error}`);
    }

    const findings = findingsResult.data?.data || [];
    const severityCounts = findings.reduce(
      (counts, finding) => {
        const severity = String(finding.severity || '').toUpperCase();
        if (severity === 'CRITICAL') counts.critical += 1;
        else if (severity === 'HIGH') counts.high += 1;
        else if (severity === 'MEDIUM' || severity === 'NORMAL') counts.medium += 1;
        else counts.low += 1;
        return counts;
      },
      { critical: 0, high: 0, medium: 0, low: 0 }
    );

    const resourceTotal = scans.reduce(
      (sum, scan) => sum + (Number(scan.resource_count) || 0),
      0
    );
    const findingTotalAcrossScans = scans.reduce(
      (sum, scan) => sum + (Number(scan.finding_count) || 0),
      0
    );
    const criticalTotalAcrossScans = scans.reduce(
      (sum, scan) => sum + (Number(scan.critical_count) || 0),
      0
    );

    return {
      summary: {
        totalRecords: findings.length,
      },
      scans: {
        total: scans.length,
        resourceTotal,
        findingTotalAcrossScans,
        criticalTotalAcrossScans,
        items: scans,
      },
      findings: {
        total: findings.length,
        critical: severityCounts.critical,
        high: severityCounts.high,
        medium: severityCounts.medium,
        low: severityCounts.low,
        items: findings,
      },
      resources: {
        total: resourceTotal,
      },
      collectedAt: new Date().toISOString(),
      sourceUrl: baseUrl,
      errors: [],
    };
  }
}

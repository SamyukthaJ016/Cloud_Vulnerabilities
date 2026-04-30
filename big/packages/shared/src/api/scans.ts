import type { ScanStatus, Severity } from '../enums';

export interface RunScanDto {
  scannerKey: string;
  credentials: Record<string, unknown>;
}

export interface ScanJobDto {
  id: string;
  scannerKey: string;
  status: ScanStatus;
  queuedAt: string;
  startedAt: string | null;
  completedAt: string | null;
  error: string | null;
  externalScanId: string | null;
  summary: Record<Severity, number> | null;
  triggeredBy: { id: string; name: string | null; email: string };
}

export interface RunScanResponse {
  jobId: string;
}

export interface ScanReportRedirectDto {
  redirectUrl: string;
}

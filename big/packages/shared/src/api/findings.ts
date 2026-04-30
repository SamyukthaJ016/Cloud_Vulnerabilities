import type { FindingStatus, Severity } from '../enums';

export interface FindingDto {
  id: string;
  scanJobId: string;
  scannerKey: string;
  externalId: string | null;
  title: string;
  description: string | null;
  severity: Severity;
  resource: string | null;
  evidence: Record<string, unknown> | null;
  recommendation: string | null;
  status: FindingStatus;
  tags: string[];
  createdAt: string;
  updatedAt: string;
}

export interface UpdateFindingStatusDto {
  status: FindingStatus;
}

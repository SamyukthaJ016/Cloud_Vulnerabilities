import type { ScannerAvailability } from '../enums';

export interface ScannerDto {
  id: string;
  key: string;
  name: string;
  description: string | null;
  version: string;
  category: string | null;
  iconUrl: string | null;
  dashboardBaseUrl: string | null;
  credentialSchema: Record<string, unknown>;
  availability: ScannerAvailability;
  lastError: string | null;
}

export interface RefreshScannerResultDto {
  key: string;
  availability: ScannerAvailability;
  error: string | null;
}

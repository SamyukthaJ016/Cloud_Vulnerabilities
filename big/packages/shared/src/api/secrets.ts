import type { SecretStatus } from '../enums';

// App DB stores metadata only — value lives in Vault.
export interface SecretMetadataDto {
  id: string;
  scannerKey: string | null;
  key: string;
  status: SecretStatus;
  createdAt: string;
  updatedAt: string;
  rotatedAt: string | null;
  createdBy: { id: string; name: string | null; email: string };
}

export interface CreateSecretDto {
  scannerKey?: string;
  key: string;
  value: string; // sent to backend; never returned
}

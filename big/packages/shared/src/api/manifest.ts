export interface ScannerManifest {
  key: string;
  name: string;
  description?: string;
  version: string;
  category?: string;
  iconUrl?: string;
  dashboardBaseUrl: string;
  credentialSchema: Record<string, unknown>; // JSON Schema (draft-07)
}

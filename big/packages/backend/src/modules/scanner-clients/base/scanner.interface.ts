export interface ScannerRunRequest {
  jobId: string;
  orgId: string;
  callbackUrl: string;
  nonce: string;
  credentials: Record<string, unknown>;
}

export interface ScannerRunAck {
  scanId: string;
  status: 'accepted';
}

export interface ScannerViewTokenResponse {
  viewSecret: string;
}

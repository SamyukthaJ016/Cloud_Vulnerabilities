import type { ScanStatus, Severity, SubscriptionStatus } from './enums';

// WebSocket event names the backend emits via NotificationsGateway.
// Every event payload includes `orgId` so frontend can verify scope.
export type NotificationEvent =
  | 'scan.dispatched'
  | 'scan.completed'
  | 'scan.failed'
  | 'finding.created'
  | 'billing.updated'
  | 'secret.changed';

export interface ScanDispatchedPayload {
  orgId: string;
  scanJobId: string;
  scannerKey: string;
}

export interface ScanCompletedPayload {
  orgId: string;
  scanJobId: string;
  status: Extract<ScanStatus, 'COMPLETED'>;
  summary: Record<Severity, number>;
}

export interface ScanFailedPayload {
  orgId: string;
  scanJobId: string;
  error: string;
}

export interface FindingCreatedPayload {
  orgId: string;
  findingId: string;
  severity: Severity;
  scannerKey: string;
  scanJobId: string;
}

export interface BillingUpdatedPayload {
  orgId: string;
  subscription: {
    planKey: string;
    status: SubscriptionStatus;
  };
}

export interface SecretChangedPayload {
  orgId: string;
  secretId: string;
  action: 'create' | 'revoke';
}

export type NotificationPayloadMap = {
  'scan.dispatched': ScanDispatchedPayload;
  'scan.completed': ScanCompletedPayload;
  'scan.failed': ScanFailedPayload;
  'finding.created': FindingCreatedPayload;
  'billing.updated': BillingUpdatedPayload;
  'secret.changed': SecretChangedPayload;
};

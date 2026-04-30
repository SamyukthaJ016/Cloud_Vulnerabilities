// Mirror of Prisma enums from packages/backend/prisma/schema.prisma.
// Kept as string unions so the frontend doesn't pull @prisma/client.

export type SsoProvider = 'GOOGLE';

export type UserStatus = 'PENDING' | 'ACTIVE' | 'SUSPENDED' | 'UNASSIGNED';

export type OrgStatus = 'ACTIVE' | 'SUSPENDED' | 'DELETED';

export type MembershipStatus = 'ACTIVE' | 'INVITED' | 'SUSPENDED';

export type BillingInterval = 'MONTHLY';

export type SubscriptionStatus = 'TRIAL' | 'ACTIVE' | 'PAST_DUE' | 'CANCELED' | 'EXPIRED';

export type PaymentStatus = 'CREATED' | 'ATTEMPTED' | 'PAID' | 'FAILED' | 'REFUNDED';

export type WebhookEventStatus = 'PENDING' | 'PROCESSED' | 'FAILED' | 'REJECTED';

export type SecretStatus = 'ACTIVE' | 'ROTATING' | 'REVOKED';

export type ScanStatus = 'DISPATCHED' | 'RUNNING' | 'COMPLETED' | 'FAILED';

export type ScannerAvailability = 'AVAILABLE' | 'UNAVAILABLE';

export type Severity = 'INFO' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type FindingStatus =
  | 'OPEN'
  | 'TRIAGED'
  | 'ACCEPTED'
  | 'RESOLVED'
  | 'FALSE_POSITIVE';

export type DeliveryStatus = 'PENDING' | 'DELIVERED' | 'FAILED' | 'ABANDONED';

// System role keys — must match packages/backend/src/modules/rbac/permissions.catalog.ts
export const SYSTEM_ROLE_KEYS = {
  ORG_ADMIN: 'org_admin',
  ORG_MEMBER: 'org_member',
  VIEWER: 'viewer',
  SCANNER_OPERATOR: 'scanner_operator',
} as const;

export type SystemRoleKey = (typeof SYSTEM_ROLE_KEYS)[keyof typeof SYSTEM_ROLE_KEYS];

// Permission keys — add here + in backend catalog together
export type PermissionKey =
  | 'org.read'
  | 'org.manage'
  | 'member.read'
  | 'member.manage'
  | 'billing.read'
  | 'billing.manage'
  | 'secret.read'
  | 'secret.write'
  | 'scan.run'
  | 'scan.read'
  | 'finding.read'
  | 'finding.triage'
  | 'audit.read';

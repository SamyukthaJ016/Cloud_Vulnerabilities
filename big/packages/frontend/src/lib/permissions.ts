/**
 * Permission key constants — mirror of
 * packages/backend/src/modules/rbac/permissions.catalog.ts.
 *
 * Prefer importing `PermissionKey` type from @cloudguard/shared and use
 * these constants to avoid typos when calling `usePermissions().has(...)`.
 */
import type { PermissionKey } from '@cloudguard/shared';

export const PERMISSIONS = {
  ORG_READ: 'org.read',
  ORG_MANAGE: 'org.manage',
  MEMBER_READ: 'member.read',
  MEMBER_MANAGE: 'member.manage',
  BILLING_READ: 'billing.read',
  BILLING_MANAGE: 'billing.manage',
  SECRET_READ: 'secret.read',
  SECRET_WRITE: 'secret.write',
  SCAN_RUN: 'scan.run',
  SCAN_READ: 'scan.read',
  FINDING_READ: 'finding.read',
  FINDING_TRIAGE: 'finding.triage',
  AUDIT_READ: 'audit.read',
} as const satisfies Record<string, PermissionKey>;

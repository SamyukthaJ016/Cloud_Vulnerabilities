/**
 * Static catalog of permissions and role → permissions mapping.
 * Seeded into the DB by `prisma/seed.ts` — this file is the source of truth.
 *
 * Permission key shape: `<resource>.<action>` (resource singular, lowercase)
 */

import { SYSTEM_ROLE_KEYS } from '../../common/enums';

export const PERMISSIONS = {
  // org
  ORG_READ: { key: 'org.read', resource: 'org', action: 'read' },
  ORG_MANAGE: { key: 'org.manage', resource: 'org', action: 'manage' },

  // users / members
  MEMBER_READ: { key: 'member.read', resource: 'member', action: 'read' },
  MEMBER_MANAGE: { key: 'member.manage', resource: 'member', action: 'manage' },

  // billing
  BILLING_READ: { key: 'billing.read', resource: 'billing', action: 'read' },
  BILLING_MANAGE: { key: 'billing.manage', resource: 'billing', action: 'manage' },

  // secrets
  SECRET_READ: { key: 'secret.read', resource: 'secret', action: 'read' },
  SECRET_WRITE: { key: 'secret.write', resource: 'secret', action: 'write' },

  // scans
  SCAN_RUN: { key: 'scan.run', resource: 'scan', action: 'run' },
  SCAN_READ: { key: 'scan.read', resource: 'scan', action: 'read' },

  // findings
  FINDING_READ: { key: 'finding.read', resource: 'finding', action: 'read' },
  FINDING_TRIAGE: { key: 'finding.triage', resource: 'finding', action: 'write' },

  // audit
  AUDIT_READ: { key: 'audit.read', resource: 'audit', action: 'read' },
} as const;

export const ROLE_PERMISSIONS: Record<string, (typeof PERMISSIONS)[keyof typeof PERMISSIONS][]> = {
  [SYSTEM_ROLE_KEYS.ORG_ADMIN]: Object.values(PERMISSIONS),
  [SYSTEM_ROLE_KEYS.ORG_MEMBER]: [
    PERMISSIONS.ORG_READ,
    PERMISSIONS.MEMBER_READ,
    PERMISSIONS.BILLING_READ,
    PERMISSIONS.SECRET_READ,
    PERMISSIONS.SCAN_RUN,
    PERMISSIONS.SCAN_READ,
    PERMISSIONS.FINDING_READ,
    PERMISSIONS.FINDING_TRIAGE,
    PERMISSIONS.AUDIT_READ,
  ],
  [SYSTEM_ROLE_KEYS.VIEWER]: [
    PERMISSIONS.ORG_READ,
    PERMISSIONS.SCAN_READ,
    PERMISSIONS.FINDING_READ,
  ],
  [SYSTEM_ROLE_KEYS.SCANNER_OPERATOR]: [
    PERMISSIONS.ORG_READ,
    PERMISSIONS.SCAN_RUN,
    PERMISSIONS.SCAN_READ,
    PERMISSIONS.FINDING_READ,
    PERMISSIONS.SECRET_READ,
  ],
};

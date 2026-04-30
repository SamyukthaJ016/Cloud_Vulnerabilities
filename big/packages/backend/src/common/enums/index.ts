/**
 * Runtime enums that are NOT backed by a Prisma enum.
 * Prisma enums (ScanStatus, Severity, Role keys, etc.) should be imported
 * directly from '@prisma/client' — don't redefine them here.
 */

export const SYSTEM_ROLE_KEYS = {
  ORG_ADMIN: 'org_admin',
  ORG_MEMBER: 'org_member',
  VIEWER: 'viewer',
  SCANNER_OPERATOR: 'scanner_operator',
} as const;

export type SystemRoleKey = (typeof SYSTEM_ROLE_KEYS)[keyof typeof SYSTEM_ROLE_KEYS];

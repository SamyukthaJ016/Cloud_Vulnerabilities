import type { PermissionKey, UserStatus } from '../enums';

/** Response from GET /auth/me. */
export interface MeDto {
  userId: string;
  email: string;
  orgId: string | null;
  roleKey: string | null;
  permissions: PermissionKey[];
}

export interface UserSummaryDto {
  id: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
  status: UserStatus;
  lastLoginAt: string | null;
}

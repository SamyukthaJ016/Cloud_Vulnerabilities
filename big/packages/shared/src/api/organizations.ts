import type { MembershipStatus, OrgStatus, SystemRoleKey } from '../enums';
import type { UserDto } from './users';
import type { RoleDto } from './rbac';

export interface OrganizationDto {
  id: string;
  name: string;
  slug: string;
  domain: string | null;
  status: OrgStatus;
  createdAt: string;
  updatedAt: string;
}

export interface OrgMemberDto {
  id: string;
  user: Pick<UserDto, 'id' | 'email' | 'name' | 'avatarUrl'>;
  role: Pick<RoleDto, 'key' | 'name'>;
  status: MembershipStatus;
  joinedAt: string;
}

export interface CreateOrganizationDto {
  name: string;
  slug: string;
  domain?: string;
}

export interface CreateOrganizationResponse {
  organization: OrganizationDto;
  roleKey: SystemRoleKey;
}

export interface InviteMemberDto {
  email: string;
  roleKey: SystemRoleKey;
}

export interface ChangeMemberRoleDto {
  roleKey: SystemRoleKey;
}

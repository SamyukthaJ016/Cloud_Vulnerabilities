import type { UserStatus } from '../enums';

export interface UserDto {
  id: string;
  email: string;
  name: string | null;
  avatarUrl: string | null;
  status: UserStatus;
  lastLoginAt: string | null;
  createdAt: string;
  updatedAt: string;
}

export interface UpdateProfileDto {
  name?: string;
  avatarUrl?: string;
}

import type { PermissionKey } from '../enums';

export interface RoleDto {
  id: string;
  key: string;
  name: string;
  description: string | null;
  isSystem: boolean;
  permissions: PermissionKey[];
}

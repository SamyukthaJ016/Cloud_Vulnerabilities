import { IsIn } from 'class-validator';
import { SYSTEM_ROLE_KEYS, SystemRoleKey } from '../../../common/enums';

const ROLE_KEYS = Object.values(SYSTEM_ROLE_KEYS) as SystemRoleKey[];

export class ChangeMemberRoleDto {
  @IsIn(ROLE_KEYS)
  roleKey!: SystemRoleKey;
}

import { IsEmail, IsIn, MaxLength } from 'class-validator';
import { SYSTEM_ROLE_KEYS, SystemRoleKey } from '../../../common/enums';

const ROLE_KEYS = Object.values(SYSTEM_ROLE_KEYS) as SystemRoleKey[];

export class InviteMemberDto {
  @IsEmail()
  @MaxLength(254)
  email!: string;

  @IsIn(ROLE_KEYS, { message: `roleKey must be one of: ${ROLE_KEYS.join(', ')}` })
  roleKey!: SystemRoleKey;
}

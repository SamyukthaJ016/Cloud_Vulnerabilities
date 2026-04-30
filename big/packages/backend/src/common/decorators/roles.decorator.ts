import { SetMetadata } from '@nestjs/common';

export const ROLES_KEY = 'roles';

/**
 * Gate a route by one or more role keys.
 * Usage: `@Roles('org_admin')` or `@Roles('org_admin', 'scanner_operator')`
 * Works together with RolesGuard.
 */
export const Roles = (...roleKeys: string[]) => SetMetadata(ROLES_KEY, roleKeys);

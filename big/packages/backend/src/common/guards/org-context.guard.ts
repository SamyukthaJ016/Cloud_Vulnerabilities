import { CanActivate, ExecutionContext, ForbiddenException, Injectable } from '@nestjs/common';

/**
 * Verifies the authenticated user has an orgId attached (i.e. is assigned to an org).
 * Flow node N: users in UNASSIGNED state are rejected here.
 *
 * Attach to any tenant-scoped endpoint. JwtAuthGuard must run first.
 */
@Injectable()
export class OrgContextGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const { user } = context.switchToHttp().getRequest();
    if (!user?.orgId) {
      throw new ForbiddenException('User is not assigned to an organization');
    }
    return true;
  }
}

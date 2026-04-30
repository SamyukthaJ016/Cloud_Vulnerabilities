import { createParamDecorator, ExecutionContext } from '@nestjs/common';

/**
 * Shortcut for `req.user.orgId`. Set by TenantContextMiddleware.
 * Every tenant-scoped query must filter by this (flow TS3).
 */
export const OrgId = createParamDecorator((_data: unknown, ctx: ExecutionContext): string => {
  const req = ctx.switchToHttp().getRequest();
  return req.user?.orgId;
});

import { Injectable, NestMiddleware } from '@nestjs/common';
import { NextFunction, Request, Response } from 'express';

/**
 * Enforces flow nodes TS1-TS2: "Every request carries user identity" and
 * "Backend maps identity to org_id".
 *
 * TODO (platform lead):
 *   - after JwtStrategy runs, req.user has orgId. This middleware can add
 *     request-scoped context (e.g. via AsyncLocalStorage) so that the
 *     Prisma tenant extension can read orgId without prop-drilling it.
 *   - register this middleware in AppModule.configure() AFTER auth runs.
 */
@Injectable()
export class TenantContextMiddleware implements NestMiddleware {
  use(_req: Request, _res: Response, next: NextFunction) {
    // const orgId = req.user?.orgId;
    // TenantAls.run({ orgId }, () => next());
    next();
  }
}

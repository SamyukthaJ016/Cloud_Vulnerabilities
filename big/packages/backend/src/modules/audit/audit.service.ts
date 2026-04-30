import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

/**
 * Flow node TS6. The single point of truth for audit logging.
 * Other modules call `record(...)` directly OR rely on the `@AuditAction`
 * decorator + `AuditInterceptor`.
 *
 * Never inline `prisma.auditLog.create` in a feature module — always go through here.
 */
@Injectable()
export class AuditService {
  constructor(private readonly prisma: PrismaService) {}

  async record(_entry: {
    orgId?: string | null;
    actorUserId?: string | null;
    action: string;   // e.g. 'secret.create', 'scan.run', 'billing.update'
    resource: string; // e.g. 'secret', 'scan', 'billing'
    resourceId?: string | null;
    ipAddress?: string | null;
    userAgent?: string | null;
    details?: Record<string, unknown> | null;
  }): Promise<void> {
    // TODO: prisma.auditLog.create({ data: entry })
    // Never throw from here — a failed audit write must not break the request.
    //   Log the error, increment a metric, continue.
  }

  async listForOrg(_orgId: string, _params: {
    action?: string;
    resource?: string;
    actorUserId?: string;
    from?: Date;
    to?: Date;
    page?: number;
    pageSize?: number;
  }) {
    // TODO — strict orgId filter
  }
}

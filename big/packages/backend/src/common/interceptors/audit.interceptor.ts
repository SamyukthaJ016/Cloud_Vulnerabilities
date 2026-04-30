import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Observable, tap } from 'rxjs';
import { AUDIT_ACTION_KEY, AuditActionMeta } from '../decorators/audit-action.decorator';

/**
 * Writes an AuditLog row on successful completion of any handler
 * decorated with @AuditAction({ action, resource }).
 *
 * TODO (audit-module owner):
 *   - inject AuditService and call `audit.record({ ... })` in the `tap` below
 *   - capture actor (from req.user), orgId, ip, userAgent, and any handler-provided details
 *
 * Flow nodes: TS6, AF, BK, P1
 */
@Injectable()
export class AuditInterceptor implements NestInterceptor {
  constructor(private readonly reflector: Reflector) {}

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const meta = this.reflector.getAllAndOverride<AuditActionMeta | undefined>(AUDIT_ACTION_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (!meta) return next.handle();

    // const req = context.switchToHttp().getRequest();
    return next.handle().pipe(
      tap(() => {
        // AuditService.record({ action: meta.action, resource: meta.resource, actor: req.user, ... })
      }),
    );
  }
}

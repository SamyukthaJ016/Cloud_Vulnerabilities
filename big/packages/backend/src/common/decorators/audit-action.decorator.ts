import { SetMetadata } from '@nestjs/common';

export const AUDIT_ACTION_KEY = 'auditAction';

export interface AuditActionMeta {
  action: string;   // e.g. 'secret.create', 'scan.run'
  resource: string; // e.g. 'secret', 'scan'
}

/**
 * Annotate a controller method to auto-write an AuditLog row
 * on successful completion (flow TS6). Picked up by AuditInterceptor.
 *
 * Usage: `@AuditAction({ action: 'secret.create', resource: 'secret' })`
 */
export const AuditAction = (meta: AuditActionMeta) => SetMetadata(AUDIT_ACTION_KEY, meta);

export interface AuditLogDto {
  id: string;
  orgId: string | null;
  actor: { id: string; name: string | null; email: string } | null;
  action: string;
  resource: string;
  resourceId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  details: Record<string, unknown> | null;
  createdAt: string;
}

export interface AuditLogFilters {
  action?: string;
  resource?: string;
  actorUserId?: string;
  from?: string;
  to?: string;
}

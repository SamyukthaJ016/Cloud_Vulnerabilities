import { useQuery } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { AuditLogDto, AuditLogFilters } from '@cloudguard/shared';

export function useAuditLogsQuery(filters: AuditLogFilters = {}) {
  return useQuery({
    queryKey: ['audit', filters],
    queryFn: async () =>
      (await http.get<AuditLogDto[]>('/audit', { params: filters })).data,
  });
}

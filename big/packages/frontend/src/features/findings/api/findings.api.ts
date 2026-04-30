import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { FindingDto, UpdateFindingStatusDto } from '@cloudguard/shared';

export function useFindingsQuery(filters: {
  scanJobId?: string;
  severity?: string[];
  status?: string[];
  scannerKey?: string;
} = {}) {
  return useQuery({
    queryKey: ['findings', filters],
    queryFn: async () => {
      const params: Record<string, string> = {};
      if (filters.scanJobId) params.scanJobId = filters.scanJobId;
      if (filters.scannerKey) params.scannerKey = filters.scannerKey;
      if (filters.severity) params.severity = filters.severity.join(',');
      if (filters.status) params.status = filters.status.join(',');
      return (await http.get<FindingDto[]>('/findings', { params })).data;
    },
  });
}

export function useFindingQuery(id: string | undefined) {
  return useQuery({
    queryKey: ['findings', 'detail', id],
    enabled: !!id,
    queryFn: async () => (await http.get<FindingDto>(`/findings/${id}`)).data,
  });
}

export function useUpdateFindingStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, dto }: { id: string; dto: UpdateFindingStatusDto }) => {
      await http.patch(`/findings/${id}/status`, dto);
    },
    onSuccess: (_data, { id }) => {
      qc.invalidateQueries({ queryKey: ['findings'] });
      qc.invalidateQueries({ queryKey: ['findings', 'detail', id] });
    },
  });
}

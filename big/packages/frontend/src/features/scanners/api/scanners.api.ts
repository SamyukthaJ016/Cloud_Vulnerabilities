import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { RefreshScannerResultDto, ScannerDto } from '@cloudguard/shared';

export function useScannersQuery() {
  return useQuery({
    queryKey: ['scanners'],
    queryFn: async () => (await http.get<ScannerDto[]>('/scanners')).data,
  });
}

export function useRefreshScanners() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () =>
      (await http.post<RefreshScannerResultDto[]>('/admin/scanners/refresh')).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scanners'] }),
  });
}

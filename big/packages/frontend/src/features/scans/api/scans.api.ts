import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import type {
  RunScanDto,
  RunScanResponse,
  ScanJobDto,
  ScanReportRedirectDto,
} from '@cloudguard/shared';

export function useScansQuery(filters: { scannerKey?: string; status?: string } = {}) {
  return useQuery({
    queryKey: ['scans', filters],
    queryFn: async () => (await http.get<ScanJobDto[]>('/scans', { params: filters })).data,
  });
}

export function useScanQuery(id: string | undefined) {
  return useQuery({
    queryKey: ['scans', 'detail', id],
    enabled: !!id,
    queryFn: async () => (await http.get<ScanJobDto>(`/scans/${id}`)).data,
  });
}

export function useRunScan() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (dto: RunScanDto) =>
      (await http.post<RunScanResponse>('/scans/run', dto)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['scans'] }),
  });
}

export async function fetchScanReportUrl(jobId: string): Promise<string> {
  const { data } = await http.get<ScanReportRedirectDto>(`/scans/${jobId}/report`);
  return data.redirectUrl;
}

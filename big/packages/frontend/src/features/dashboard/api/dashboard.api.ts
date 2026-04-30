import { useQuery } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { DashboardBootstrapDto } from '@cloudguard/shared';

export function useDashboardBootstrap() {
  return useQuery({
    queryKey: ['dashboard', 'bootstrap'],
    queryFn: async () => (await http.get<DashboardBootstrapDto>('/dashboard/bootstrap')).data,
  });
}

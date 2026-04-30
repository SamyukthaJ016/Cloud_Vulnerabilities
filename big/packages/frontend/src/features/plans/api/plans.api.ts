import { useQuery } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { PlanDto } from '@cloudguard/shared';

export function usePlansQuery() {
  return useQuery({
    queryKey: ['plans'],
    queryFn: async () => (await http.get<PlanDto[]>('/plans')).data,
    staleTime: 5 * 60_000, // plan catalog rarely changes
  });
}

import { useQuery } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { SubscriptionDto } from '@cloudguard/shared';

export function useCurrentSubscription() {
  return useQuery({
    queryKey: ['subscriptions', 'current'],
    queryFn: async () =>
      (await http.get<SubscriptionDto | null>('/subscriptions/current')).data,
  });
}

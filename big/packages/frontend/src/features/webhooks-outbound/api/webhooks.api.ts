import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import type {
  CreateWebhookSubscriptionDto,
  WebhookSubscriptionDto,
  WebhookSubscriptionWithSecretDto,
} from '@cloudguard/shared';

export function useWebhookSubscriptionsQuery() {
  return useQuery({
    queryKey: ['webhooks', 'outbound'],
    queryFn: async () =>
      (await http.get<WebhookSubscriptionDto[]>('/webhooks/outbound')).data,
  });
}

/** Response includes the HMAC secret — shown ONCE in the UI, never again. */
export function useCreateWebhookSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (dto: CreateWebhookSubscriptionDto) =>
      (await http.post<WebhookSubscriptionWithSecretDto>('/webhooks/outbound', dto)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks', 'outbound'] }),
  });
}

export function useDeleteWebhookSubscription() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await http.delete(`/webhooks/outbound/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['webhooks', 'outbound'] }),
  });
}

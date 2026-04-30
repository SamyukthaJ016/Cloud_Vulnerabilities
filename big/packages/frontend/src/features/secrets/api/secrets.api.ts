import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { CreateSecretDto, SecretMetadataDto } from '@cloudguard/shared';

export function useSecretsQuery() {
  return useQuery({
    queryKey: ['secrets'],
    queryFn: async () => (await http.get<SecretMetadataDto[]>('/secrets')).data,
  });
}

export function useCreateSecret() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (dto: CreateSecretDto) =>
      (await http.post<SecretMetadataDto>('/secrets', dto)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secrets'] }),
  });
}

export function useRevokeSecret() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      await http.delete(`/secrets/${id}`);
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['secrets'] }),
  });
}

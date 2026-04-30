import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import type { UpdateProfileDto, UserDto } from '@cloudguard/shared';

export function useMeProfileQuery() {
  return useQuery({
    queryKey: ['users', 'me'],
    queryFn: async () => (await http.get<UserDto>('/users/me')).data,
  });
}

export function useUpdateProfile() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (dto: UpdateProfileDto) =>
      (await http.patch<UserDto>('/users/me', dto)).data,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['users', 'me'] }),
  });
}

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { http } from '@/api/http';
import type {
  ChangeMemberRoleDto,
  CreateOrganizationDto,
  CreateOrganizationResponse,
  InviteMemberDto,
  OrganizationDto,
  OrgMemberDto,
  SystemRoleKey,
} from '@cloudguard/shared';

export function useCurrentOrgQuery(enabled = true) {
  return useQuery({
    queryKey: ['organizations', 'current'],
    enabled,
    queryFn: async () =>
      (await http.get<OrganizationDto>('/organizations/current')).data,
  });
}

export function useMembersQuery(enabled = true) {
  return useQuery({
    queryKey: ['organizations', 'current', 'members'],
    enabled,
    queryFn: async () =>
      (await http.get<OrgMemberDto[]>('/organizations/current/members')).data,
  });
}

/**
 * Self-serve org creation. After success the backend has set a fresh JWT cookie
 * with the new orgId, so we invalidate ['me'] to refetch the session.
 */
export function useCreateOrganization() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (dto: CreateOrganizationDto) =>
      (await http.post<CreateOrganizationResponse>('/organizations', dto)).data,
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ['me'] });
      await qc.invalidateQueries({ queryKey: ['organizations'] });
    },
  });
}

export function useInviteMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (dto: InviteMemberDto) =>
      (await http.post<OrgMemberDto>('/organizations/current/members', dto)).data,
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['organizations', 'current', 'members'] }),
  });
}

export function useRemoveMember() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (userId: string) => {
      await http.delete(`/organizations/current/members/${userId}`);
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['organizations', 'current', 'members'] }),
  });
}

export function useChangeMemberRole() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ userId, roleKey }: { userId: string; roleKey: SystemRoleKey }) => {
      const dto: ChangeMemberRoleDto = { roleKey };
      const { data } = await http.patch<OrgMemberDto>(
        `/organizations/current/members/${userId}/role`,
        dto,
      );
      return data;
    },
    onSuccess: () =>
      qc.invalidateQueries({ queryKey: ['organizations', 'current', 'members'] }),
  });
}

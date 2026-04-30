import {
  ConflictException,
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { MembershipStatus, Prisma, UserStatus } from '@prisma/client';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { UsersService } from '../users/users.service';
import { SYSTEM_ROLE_KEYS, SystemRoleKey } from '../../common/enums';

export interface ResolvedMembership {
  orgId: string;
  roleId: string;
  roleKey: string;
}

@Injectable()
export class OrganizationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly users: UsersService,
  ) {}

  /**
   * Flow node M → N. Resolves the user's effective org membership.
   *   1. existing ACTIVE membership → return it
   *   2. INVITED membership → activate it and return it
   *   3. domain-based auto-join → create ACTIVE membership and return it
   *   4. nothing matched → null (caller marks user UNASSIGNED — flow N1)
   */
  async resolveForUser(userId: string, emailDomain: string): Promise<ResolvedMembership | null> {
    const active = await this.prisma.orgMember.findFirst({
      where: { userId, status: MembershipStatus.ACTIVE },
      include: { role: true },
    });
    if (active) {
      return { orgId: active.orgId, roleId: active.roleId, roleKey: active.role.key };
    }

    const invited = await this.prisma.orgMember.findFirst({
      where: { userId, status: MembershipStatus.INVITED },
      include: { role: true },
    });
    if (invited) {
      await this.prisma.orgMember.update({
        where: { id: invited.id },
        data: { status: MembershipStatus.ACTIVE },
      });
      await this.prisma.user.update({
        where: { id: userId },
        data: { status: UserStatus.ACTIVE },
      });
      return { orgId: invited.orgId, roleId: invited.roleId, roleKey: invited.role.key };
    }

    if (emailDomain) {
      const org = await this.prisma.organization.findUnique({
        where: { domain: emailDomain },
      });
      const defaultRole = await this.prisma.role.findUnique({
        where: { key: SYSTEM_ROLE_KEYS.ORG_MEMBER },
      });
      if (org && org.status === 'ACTIVE' && defaultRole) {
        const member = await this.prisma.orgMember.create({
          data: {
            orgId: org.id,
            userId,
            roleId: defaultRole.id,
            status: MembershipStatus.ACTIVE,
          },
        });
        await this.prisma.user.update({
          where: { id: userId },
          data: { status: UserStatus.ACTIVE },
        });
        return { orgId: member.orgId, roleId: defaultRole.id, roleKey: defaultRole.key };
      }
    }

    return null;
  }

  async getById(orgId: string) {
    const org = await this.prisma.organization.findUnique({ where: { id: orgId } });
    if (!org) throw new NotFoundException('Organization not found');
    return org;
  }

  /**
   * Self-serve org creation. Transactionally:
   *   - creates the Organization
   *   - creates an OrgMember(role=org_admin, status=ACTIVE) for the requesting user
   *   - flips the user's status to ACTIVE
   *
   * Caller must have no existing ACTIVE membership (enforced here).
   */
  async createWithFirstAdmin(input: {
    userId: string;
    name: string;
    slug: string;
    domain?: string;
  }): Promise<{ orgId: string; roleId: string; roleKey: string }> {
    const existing = await this.prisma.orgMember.findFirst({
      where: { userId: input.userId, status: MembershipStatus.ACTIVE },
    });
    if (existing) {
      throw new ConflictException('User is already a member of an organization');
    }

    const adminRole = await this.prisma.role.findUnique({
      where: { key: SYSTEM_ROLE_KEYS.ORG_ADMIN },
    });
    if (!adminRole) {
      throw new Error('System role org_admin missing — run prisma:seed');
    }

    try {
      const org = await this.prisma.$transaction(async (tx) => {
        const created = await tx.organization.create({
          data: {
            name: input.name,
            slug: input.slug,
            domain: input.domain ?? null,
          },
        });
        await tx.orgMember.create({
          data: {
            orgId: created.id,
            userId: input.userId,
            roleId: adminRole.id,
            status: MembershipStatus.ACTIVE,
          },
        });
        await tx.user.update({
          where: { id: input.userId },
          data: { status: UserStatus.ACTIVE },
        });
        return created;
      });

      return { orgId: org.id, roleId: adminRole.id, roleKey: adminRole.key };
    } catch (e) {
      if (e instanceof Prisma.PrismaClientKnownRequestError && e.code === 'P2002') {
        const target = (e.meta?.target as string[] | undefined)?.[0] ?? 'field';
        throw new ConflictException(`Organization ${target} already taken`);
      }
      throw e;
    }
  }

  /**
   * Admin-driven invite. Pre-creates User row by email if needed, then creates
   * OrgMember(status=INVITED). When the invitee signs in with Google, the
   * placeholder is linked to the real SSO identity by email match in
   * UsersService.findOrCreateFromSso, then activated by resolveForUser above.
   */
  async inviteMember(input: { orgId: string; email: string; roleKey: SystemRoleKey }) {
    const role = await this.prisma.role.findUnique({ where: { key: input.roleKey } });
    if (!role) throw new NotFoundException(`Role '${input.roleKey}' not found`);

    const user = await this.users.findOrCreateInvited(input.email);

    const existing = await this.prisma.orgMember.findUnique({
      where: { orgId_userId: { orgId: input.orgId, userId: user.id } },
    });
    if (existing) {
      throw new ConflictException(
        existing.status === MembershipStatus.ACTIVE
          ? 'User is already a member of this organization'
          : 'User has a pending invitation to this organization',
      );
    }

    return this.prisma.orgMember.create({
      data: {
        orgId: input.orgId,
        userId: user.id,
        roleId: role.id,
        status: MembershipStatus.INVITED,
      },
      include: {
        user: { select: { id: true, email: true, name: true, avatarUrl: true } },
        role: { select: { key: true, name: true } },
      },
    });
  }

  async removeMember(input: { orgId: string; targetUserId: string; actorUserId: string }) {
    if (input.targetUserId === input.actorUserId) {
      throw new ForbiddenException('Cannot remove yourself');
    }
    const member = await this.prisma.orgMember.findUnique({
      where: { orgId_userId: { orgId: input.orgId, userId: input.targetUserId } },
    });
    if (!member) throw new NotFoundException('Member not found in this organization');

    await this.prisma.orgMember.delete({ where: { id: member.id } });
    return { ok: true };
  }

  async changeRole(input: {
    orgId: string;
    targetUserId: string;
    actorUserId: string;
    newRoleKey: SystemRoleKey;
  }) {
    if (input.targetUserId === input.actorUserId) {
      throw new ForbiddenException('Cannot change your own role');
    }
    const newRole = await this.prisma.role.findUnique({ where: { key: input.newRoleKey } });
    if (!newRole) throw new NotFoundException(`Role '${input.newRoleKey}' not found`);

    const member = await this.prisma.orgMember.findUnique({
      where: { orgId_userId: { orgId: input.orgId, userId: input.targetUserId } },
    });
    if (!member) throw new NotFoundException('Member not found in this organization');

    return this.prisma.orgMember.update({
      where: { id: member.id },
      data: { roleId: newRole.id },
      include: {
        user: { select: { id: true, email: true, name: true, avatarUrl: true } },
        role: { select: { key: true, name: true } },
      },
    });
  }
}

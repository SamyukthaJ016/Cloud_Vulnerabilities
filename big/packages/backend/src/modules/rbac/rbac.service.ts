import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

@Injectable()
export class RbacService {
  constructor(private readonly prisma: PrismaService) {}

  /**
   * Returns role + flat permission keys for an org member.
   * Used by `auth` during login to embed role info in the JWT.
   */
  async resolveForMember(
    orgMemberId: string,
  ): Promise<{ roleKey: string; permissions: string[] } | null> {
    const member = await this.prisma.orgMember.findUnique({
      where: { id: orgMemberId },
      include: {
        role: {
          include: { permissions: { include: { permission: true } } },
        },
      },
    });
    if (!member) return null;
    return {
      roleKey: member.role.key,
      permissions: member.role.permissions.map((rp) => rp.permission.key),
    };
  }

  /** Hot-path lookup of permissions for a role key — used by /auth/me. */
  async permissionsForRoleKey(roleKey: string): Promise<string[]> {
    const role = await this.prisma.role.findUnique({
      where: { key: roleKey },
      include: { permissions: { include: { permission: true } } },
    });
    return role?.permissions.map((rp) => rp.permission.key) ?? [];
  }

  /** Returns the catalog for the admin UI. */
  async listRoles() {
    return this.prisma.role.findMany({
      include: { permissions: { include: { permission: true } } },
      orderBy: { key: 'asc' },
    });
  }
}

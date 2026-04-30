import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';

@Injectable()
export class MembershipsService {
  constructor(private readonly prisma: PrismaService) {}

  async listMembers(orgId: string) {
    return this.prisma.orgMember.findMany({
      where: { orgId },
      include: {
        user: { select: { id: true, email: true, name: true, avatarUrl: true } },
        role: { select: { key: true, name: true } },
      },
      orderBy: [{ status: 'asc' }, { joinedAt: 'asc' }],
    });
  }
}

import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { OrganizationsService } from '../organizations/organizations.service';
import { ScannersService } from '../scanners/scanners.service';
import { FindingsService } from '../findings/findings.service';

/**
 * Composes data from many modules to build the dashboard bootstrap payload.
 * Runs in parallel where possible — this endpoint is the first thing the
 * dashboard loads after login and blocks render.
 *
 * Flow nodes: R → X5
 */
@Injectable()
export class DashboardService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly orgs: OrganizationsService,
    private readonly scanners: ScannersService,
    private readonly findings: FindingsService,
  ) {}

  async bootstrap(orgId: string, userId: string) {
    const [organization, membership, scanners, recentSummary] = await Promise.all([
      this.orgs.getById(orgId),
      this.prisma.orgMember.findUnique({
        where: { orgId_userId: { orgId, userId } },
        include: {
          role: {
            include: {
              permissions: {
                include: { permission: true },
              },
            },
          },
        },
      }),
      this.scanners.list(),
      this.findings.getRecentSummary(orgId, userId),
    ]);

    return {
      organization: {
        id: organization.id,
        name: organization.name,
        slug: organization.slug,
        domain: organization.domain,
        status: organization.status,
        createdAt: organization.createdAt.toISOString(),
        updatedAt: organization.updatedAt.toISOString(),
      },
      role: membership
        ? { key: membership.role.key, name: membership.role.name }
        : { key: 'viewer', name: 'Viewer' },
      permissions: membership?.role.permissions.map((item) => item.permission.key) ?? [],
      subscription: null,
      scanners,
      secrets: [],
      recent: recentSummary.recent,
      metrics: recentSummary.metrics,
    };
  }
}

import { Controller, Get, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { SYSTEM_ROLE_KEYS } from '../../common/enums';
import { AuditService } from './audit.service';

@UseGuards(JwtAuthGuard, OrgContextGuard, RolesGuard)
@Controller('audit')
export class AuditController {
  constructor(private readonly auditService: AuditService) {}

  /** Flow node X5: audit / recent activity tile. */
  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN, SYSTEM_ROLE_KEYS.ORG_MEMBER)
  @Get()
  list(
    @OrgId() orgId: string,
    @Query('action') action?: string,
    @Query('resource') resource?: string,
    @Query('actorUserId') actorUserId?: string,
    @Query('from') from?: string,
    @Query('to') to?: string,
  ) {
    return this.auditService.listForOrg(orgId, {
      action,
      resource,
      actorUserId,
      from: from ? new Date(from) : undefined,
      to: to ? new Date(to) : undefined,
    });
  }
}

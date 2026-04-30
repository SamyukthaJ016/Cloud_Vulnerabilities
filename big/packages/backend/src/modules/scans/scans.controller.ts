import { Body, Controller, Get, Param, Post, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../common/types/authenticated-user';
import { AuditAction } from '../../common/decorators/audit-action.decorator';
import { SYSTEM_ROLE_KEYS } from '../../common/enums';
import { ScansService } from './scans.service';

@UseGuards(JwtAuthGuard, OrgContextGuard, RolesGuard)
@Controller('scans')
export class ScansController {
  constructor(private readonly scansService: ScansService) {}

  @Roles(
    SYSTEM_ROLE_KEYS.ORG_ADMIN,
    SYSTEM_ROLE_KEYS.ORG_MEMBER,
    SYSTEM_ROLE_KEYS.SCANNER_OPERATOR,
  )
  @AuditAction({ action: 'scan.run.requested', resource: 'scan' })
  @Post('run')
  run(
    @OrgId() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: { scannerKey: string; credentials: Record<string, unknown> },
  ) {
    return this.scansService.requestRun({
      orgId,
      userId: user.userId,
      scannerKey: body.scannerKey,
      credentials: body.credentials,
    });
  }

  @Get(':id')
  getById(@OrgId() orgId: string, @Param('id') id: string) {
    return this.scansService.getById(orgId, id);
  }

  @Get(':id/report')
  getReport(@OrgId() orgId: string, @Param('id') id: string) {
    return this.scansService.getReportRedirect(orgId, id);
  }

  @Get()
  list(
    @OrgId() orgId: string,
    @Query('scannerKey') scannerKey?: string,
    @Query('status') status?: string,
  ) {
    return this.scansService.listForOrg(orgId, { scannerKey, status });
  }
}

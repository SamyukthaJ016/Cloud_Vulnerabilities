import { Body, Controller, Get, Param, Patch, Query, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuditAction } from '../../common/decorators/audit-action.decorator';
import { AuthenticatedUser } from '../../common/types/authenticated-user';
import { FindingsService } from './findings.service';

@UseGuards(JwtAuthGuard, OrgContextGuard)
@Controller('findings')
export class FindingsController {
  constructor(private readonly findingsService: FindingsService) {}

  @Get()
  list(
    @OrgId() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Query('scanJobId') scanJobId?: string,
    @Query('severity') severity?: string,
    @Query('status') status?: string,
    @Query('scannerKey') scannerKey?: string,
  ) {
    return this.findingsService.listForOrg(orgId, user.userId, {
      scanJobId,
      severity: severity?.split(','),
      status: status?.split(','),
      scannerKey,
    });
  }

  /** Flow T1 → V1. */
  @Get(':id')
  getById(
    @OrgId() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Param('id') id: string,
  ) {
    return this.findingsService.getById(orgId, user.userId, id);
  }

  @AuditAction({ action: 'finding.triage', resource: 'finding' })
  @Patch(':id/status')
  updateStatus(
    @OrgId() orgId: string,
    @Param('id') id: string,
    @Body() body: { status: string },
  ) {
    return this.findingsService.updateStatus(orgId, id, body.status);
  }
}

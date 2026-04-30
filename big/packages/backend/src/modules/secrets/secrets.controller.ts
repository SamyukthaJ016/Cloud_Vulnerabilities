import { Body, Controller, Delete, Get, Param, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { AuditAction } from '../../common/decorators/audit-action.decorator';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../common/types/authenticated-user';
import { SYSTEM_ROLE_KEYS } from '../../common/enums';
import { SecretsService } from './secrets.service';

@UseGuards(JwtAuthGuard, OrgContextGuard, RolesGuard)
@Controller('secrets')
export class SecretsController {
  constructor(private readonly secretsService: SecretsService) {}

  @Get()
  list(@OrgId() orgId: string) {
    return this.secretsService.listMetadataForOrg(orgId);
  }

  /** Flow node Y → AG. */
  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @AuditAction({ action: 'secret.create', resource: 'secret' })
  @Post()
  create(
    @OrgId() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateSecretDto,
  ) {
    return this.secretsService.createOrUpdate({
      orgId,
      userId: user.userId,
      scannerKey: body.scannerKey,
      key: body.key,
      value: body.value,
    });
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @AuditAction({ action: 'secret.revoke', resource: 'secret' })
  @Delete(':id')
  revoke(@OrgId() orgId: string, @Param('id') id: string) {
    return this.secretsService.revoke(orgId, id);
  }
}

// TODO: move to ./dto/
export interface CreateSecretDto {
  scannerKey?: string;
  key: string;
  value: string;
}

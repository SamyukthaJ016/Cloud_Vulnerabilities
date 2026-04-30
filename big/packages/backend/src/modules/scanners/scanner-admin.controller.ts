import { Controller, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { AuditAction } from '../../common/decorators/audit-action.decorator';
import { SYSTEM_ROLE_KEYS } from '../../common/enums';
import { ScannerSyncService } from './scanner-sync.service';

@UseGuards(JwtAuthGuard, OrgContextGuard, RolesGuard)
@Controller('admin/scanners')
export class ScannerAdminController {
  constructor(private readonly sync: ScannerSyncService) {}

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @AuditAction({ action: 'scanner.manifest.refresh', resource: 'scanner' })
  @Post('refresh')
  refresh() {
    return this.sync.refreshAll();
  }
}

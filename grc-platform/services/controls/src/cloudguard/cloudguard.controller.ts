import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrentUser, Roles, RolesGuard, UserContext } from '@gigachad-grc/shared';
import { JwtAuthGuard } from '../auth/dev-auth.guard';
import { CloudGuardService } from './cloudguard.service';
import { CloudGuardImportService } from './cloudguard-import.service';
import { ImportCloudGuardScanDto } from './cloudguard-import.dto';
import { PermissionGuard } from '../auth/permission.guard';
import { RequirePermission } from '../auth/decorators/require-permission.decorator';
import { Action, Resource } from '../permissions/dto/permission.dto';

@ApiTags('CloudGuard')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('api/cloudguard')
export class CloudGuardController {
  constructor(private readonly cloudGuardService: CloudGuardService,
              private readonly importService: CloudGuardImportService) {}

  @Get('dashboard')
  @ApiOperation({ summary: 'Get live CloudGuard evidence and compliance data' })
  getDashboard(@CurrentUser() user: UserContext) {
    return this.cloudGuardService.getDashboard(user.organizationId);
  }

  @Post('import')
  @UseGuards(RolesGuard, PermissionGuard)
  @Roles('admin', 'compliance_manager')
  @RequirePermission(Resource.RISK, Action.CREATE)
  @ApiOperation({ summary: 'Import the latest completed scan into native evidence and risks' })
  importLatest(@CurrentUser() user: UserContext, @Body() request: ImportCloudGuardScanDto) {
    return this.importService.importLatest(user.organizationId, user.userId, request.scanId);
  }
}

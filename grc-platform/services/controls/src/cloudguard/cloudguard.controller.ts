import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { CurrentUser, UserContext } from '@gigachad-grc/shared';
import { JwtAuthGuard } from '../auth/dev-auth.guard';
import { CloudGuardService } from './cloudguard.service';

@ApiTags('CloudGuard')
@ApiBearerAuth()
@UseGuards(JwtAuthGuard)
@Controller('api/cloudguard')
export class CloudGuardController {
  constructor(private readonly cloudGuardService: CloudGuardService) {}

  @Get('dashboard')
  @ApiOperation({ summary: 'Get live CloudGuard evidence and compliance data' })
  getDashboard(@CurrentUser() user: UserContext) {
    return this.cloudGuardService.getDashboard(user.organizationId);
  }
}

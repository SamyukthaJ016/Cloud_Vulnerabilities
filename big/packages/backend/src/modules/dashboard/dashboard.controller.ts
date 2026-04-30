import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../common/types/authenticated-user';
import { DashboardService } from './dashboard.service';

@UseGuards(JwtAuthGuard, OrgContextGuard)
@Controller('dashboard')
export class DashboardController {
  constructor(private readonly dashboardService: DashboardService) {}

  /**
   * Flow node R. Single aggregate endpoint the frontend calls after login.
   * Returns everything needed to render the dashboard shell.
   */
  @Get('bootstrap')
  bootstrap(@CurrentUser() user: AuthenticatedUser) {
    return this.dashboardService.bootstrap(user.orgId!, user.userId);
  }
}

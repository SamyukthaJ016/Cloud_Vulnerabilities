import { Controller, Get, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { SubscriptionsService } from './subscriptions.service';

@UseGuards(JwtAuthGuard, OrgContextGuard)
@Controller('subscriptions')
export class SubscriptionsController {
  constructor(private readonly subsService: SubscriptionsService) {}

  @Get('current')
  getCurrent(@OrgId() orgId: string) {
    return this.subsService.getForOrg(orgId);
  }
}

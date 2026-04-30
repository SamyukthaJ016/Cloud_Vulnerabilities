import { Body, Controller, Get, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { CurrentUser } from '../../common/decorators/current-user.decorator';
import { AuthenticatedUser } from '../../common/types/authenticated-user';
import { AuditAction } from '../../common/decorators/audit-action.decorator';
import { SYSTEM_ROLE_KEYS } from '../../common/enums';
import { BillingService } from './billing.service';

@UseGuards(JwtAuthGuard, OrgContextGuard, RolesGuard)
@Controller('billing')
export class BillingController {
  constructor(private readonly billingService: BillingService) {}

  /** Flow node BA → BC: frontend posts here to start checkout. */
  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @AuditAction({ action: 'billing.checkout.start', resource: 'billing' })
  @Post('checkout')
  createCheckoutOrder(
    @OrgId() orgId: string,
    @CurrentUser() user: AuthenticatedUser,
    @Body() body: CreateCheckoutDto,
  ) {
    return this.billingService.createCheckoutOrder({
      orgId,
      userId: user.userId,
      planKey: body.planKey,
    });
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @Get('orders')
  listOrders(@OrgId() orgId: string) {
    return this.billingService.listOrders(orgId);
  }
}

export interface CreateCheckoutDto {
  planKey: string;
}

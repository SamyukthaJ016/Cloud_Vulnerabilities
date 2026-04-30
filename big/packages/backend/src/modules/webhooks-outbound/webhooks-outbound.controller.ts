import { Body, Controller, Delete, Get, Param, Post, UseGuards } from '@nestjs/common';
import { JwtAuthGuard } from '../../common/guards/jwt-auth.guard';
import { OrgContextGuard } from '../../common/guards/org-context.guard';
import { RolesGuard } from '../../common/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { OrgId } from '../../common/decorators/org-id.decorator';
import { AuditAction } from '../../common/decorators/audit-action.decorator';
import { SYSTEM_ROLE_KEYS } from '../../common/enums';
import { WebhooksOutboundService } from './webhooks-outbound.service';

@UseGuards(JwtAuthGuard, OrgContextGuard, RolesGuard)
@Controller('webhooks/outbound')
export class WebhooksOutboundController {
  constructor(private readonly service: WebhooksOutboundService) {}

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @Get()
  list(@OrgId() orgId: string) {
    return this.service.listSubscriptions(orgId);
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @AuditAction({ action: 'webhook.subscription.create', resource: 'webhook_subscription' })
  @Post()
  create(@OrgId() orgId: string, @Body() body: { url: string; events: string[] }) {
    return this.service.createSubscription(orgId, body);
  }

  @Roles(SYSTEM_ROLE_KEYS.ORG_ADMIN)
  @AuditAction({ action: 'webhook.subscription.delete', resource: 'webhook_subscription' })
  @Delete(':id')
  remove(@OrgId() orgId: string, @Param('id') id: string) {
    return this.service.deleteSubscription(orgId, id);
  }
}

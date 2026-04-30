import { Global, Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { WebhooksOutboundController } from './webhooks-outbound.controller';
import { WebhooksOutboundService } from './webhooks-outbound.service';
import { WebhookDeliveryWorker } from './delivery.worker';
import { QUEUE_NAMES } from '../../infra/queue/queues.constants';

@Global()
@Module({
  imports: [BullModule.registerQueue({ name: QUEUE_NAMES.WEBHOOK_DELIVERY })],
  controllers: [WebhooksOutboundController],
  providers: [WebhooksOutboundService, WebhookDeliveryWorker],
  exports: [WebhooksOutboundService],
})
export class WebhooksOutboundModule {}

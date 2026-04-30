import { Module } from '@nestjs/common';
import { BillingWebhooksController } from './billing-webhooks.controller';
import { SignatureVerifierService } from './signature-verifier.service';
import { WebhookProcessorService } from './webhook-processor.service';
import { SubscriptionsModule } from '../subscriptions/subscriptions.module';

@Module({
  imports: [SubscriptionsModule],
  controllers: [BillingWebhooksController],
  providers: [SignatureVerifierService, WebhookProcessorService],
})
export class BillingWebhooksModule {}

import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { SubscriptionsService } from '../subscriptions/subscriptions.service';

/**
 * Processes Razorpay webhook events AFTER signature + replay checks pass.
 * Flow nodes BI → BK.
 */
@Injectable()
export class WebhookProcessorService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly subscriptions: SubscriptionsService,
  ) {}

  async process(_event: { id: string; event: string; payload: unknown }) {
    // TODO:
    //   - switch on event.event:
    //       'payment.captured'        → update PaymentOrder.status = PAID + mint/refresh Subscription
    //       'payment.failed'          → PaymentOrder.status = FAILED
    //       'subscription.activated'  → subscriptions.upsertFromPayment
    //       'subscription.halted'    → subscriptions status = PAST_DUE
    //       'subscription.cancelled'  → subscriptions.cancel
    //   - every branch writes an AuditLog row with action='billing.<event>'
  }
}

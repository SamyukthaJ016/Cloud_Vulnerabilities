import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { PrismaService } from '../../infra/prisma/prisma.service';
import { QUEUE_NAMES } from '../../infra/queue/queues.constants';

@Injectable()
export class WebhooksOutboundService {
  constructor(
    private readonly prisma: PrismaService,
    @InjectQueue(QUEUE_NAMES.WEBHOOK_DELIVERY) private readonly queue: Queue,
  ) {}

  async listSubscriptions(_orgId: string) {
    // TODO
  }

  async createSubscription(_orgId: string, _input: { url: string; events: string[] }) {
    // TODO — generate HMAC secret, persist, return (secret shown ONCE to caller)
  }

  async deleteSubscription(_orgId: string, _id: string) {
    // TODO
  }

  /**
   * Called by other modules (scans, findings, billing-webhooks) when an event
   * should be fanned out to matching customer webhooks.
   *
   * Flow node Q1 (external side).
   */
  async enqueueEvent(_orgId: string, _eventType: string, _payload: Record<string, unknown>) {
    // TODO:
    //   - list active subscriptions matching eventType
    //   - for each, create a WebhookDelivery row (PENDING)
    //   - queue.add('deliver', { deliveryId })
  }
}

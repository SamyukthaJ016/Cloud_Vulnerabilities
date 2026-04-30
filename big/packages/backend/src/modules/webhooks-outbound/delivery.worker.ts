import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Logger } from '@nestjs/common';
import { Job } from 'bullmq';
import { QUEUE_NAMES } from '../../infra/queue/queues.constants';

/**
 * BullMQ worker that actually POSTs to customer URLs.
 * HMAC-signed requests, exponential backoff, caps retries after N attempts.
 */
@Processor(QUEUE_NAMES.WEBHOOK_DELIVERY)
export class WebhookDeliveryWorker extends WorkerHost {
  private readonly logger = new Logger(WebhookDeliveryWorker.name);

  async process(job: Job<{ deliveryId: string }>): Promise<void> {
    this.logger.log(`Delivering webhook ${job.data.deliveryId}`);
    // TODO:
    //   - load WebhookDelivery + its Subscription
    //   - build HMAC signature over body with subscription.secret
    //   - axios.post(url, payload, { headers: { 'X-CloudGuard-Signature': sig } })
    //   - on 2xx: status=DELIVERED, deliveredAt=now
    //   - on 4xx (non-429): status=FAILED, don't retry
    //   - on 5xx/timeout: bump attemptCount, schedule next attempt (exp backoff), status=PENDING
    //   - after N attempts: status=ABANDONED
  }
}

/**
 * Centralized queue name constants. Reference these everywhere instead of
 * string-typing queue names — renaming a queue should be a single-file change.
 */
export const QUEUE_NAMES = {
  WEBHOOK_DELIVERY: 'webhook-delivery', // webhooks-outbound worker
} as const;

export type QueueName = (typeof QUEUE_NAMES)[keyof typeof QUEUE_NAMES];

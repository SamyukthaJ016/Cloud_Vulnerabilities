import type { DeliveryStatus, NotificationEvent } from '../index';

export interface WebhookSubscriptionDto {
  id: string;
  url: string;
  events: NotificationEvent[];
  isActive: boolean;
  createdAt: string;
}

export interface CreateWebhookSubscriptionDto {
  url: string;
  events: NotificationEvent[];
}

/** Returned ONCE on creation — the HMAC secret the customer will verify with. */
export interface WebhookSubscriptionWithSecretDto extends WebhookSubscriptionDto {
  secret: string;
}

export interface WebhookDeliveryDto {
  id: string;
  eventType: NotificationEvent;
  status: DeliveryStatus;
  responseStatus: number | null;
  attemptCount: number;
  deliveredAt: string | null;
  createdAt: string;
}

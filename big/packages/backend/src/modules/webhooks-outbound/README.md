# webhooks-outbound/

Customer-configured webhooks. When something interesting happens in an org (scan completes, finding created, billing state changes), we POST a signed payload to URLs they've registered.

## Flow diagram coverage

- Q1 (external half) — "external webhooks"

## Responsibility

Two halves:

1. **Admin API** — org admins manage their webhook subscriptions (CRUD).
2. **Delivery pipeline** — internal events enqueue `WebhookDelivery` rows, a BullMQ worker POSTs them with HMAC signature, retries on failure.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/webhooks/outbound` | `org_admin` | List subscriptions for current org |
| POST | `/webhooks/outbound` | `org_admin` | Create subscription (response includes HMAC secret — shown **once**) |
| DELETE | `/webhooks/outbound/:id` | `org_admin` | Delete subscription |

## Internal services (exposed — `@Global`)

- `WebhooksOutboundService.enqueueEvent(orgId, eventType, payload)` — called by `scanner-callbacks`, `findings`, `billing-webhooks`.

## Dependencies

- `PrismaService`
- BullMQ queue `webhook-delivery` (producer + consumer both live here)
- `axios` (via `@nestjs/axios`) for delivery POSTs

## Depended on by

- `scanner-callbacks`
- `findings`
- `billing-webhooks`

## DB tables owned

- `WebhookSubscription`
- `WebhookDelivery`

## Event types (outbound)

Mirror the internal notifications events, scoped per org:

```
scan.dispatched
scan.completed
scan.failed
finding.created
billing.updated
```

## Delivery contract

Each POST includes:

```
X-CloudGuard-Event: <eventType>
X-CloudGuard-Delivery: <deliveryId>
X-CloudGuard-Signature: hex(HMAC-SHA256(rawBody, subscription.secret))
Content-Type: application/json
```

Body:
```json
{
  "eventType": "scan.completed",
  "orgId": "uuid",
  "occurredAt": "ISO-8601",
  "data": { ... event payload ... }
}
```

## Retry policy

- Attempt 1 immediately, 2 after 30s, 3 after 5min, 4 after 30min, 5 after 2h.
- 2xx → DELIVERED.
- Non-429 4xx → FAILED (customer misconfig — don't retry).
- 429 / 5xx / timeout → bump `attemptCount`, schedule next attempt.
- After 5 attempts → ABANDONED.

## Implementation checklist

- [ ] Subscription CRUD with generated HMAC secret (returned once, never again)
- [ ] `WebhooksOutboundService.enqueueEvent` — fan out to subscriptions matching eventType
- [ ] `WebhookDeliveryWorker`:
  - [ ] HMAC signing
  - [ ] HTTP POST with axios + 10s timeout
  - [ ] status state machine above
  - [ ] exponential backoff with jitter
- [ ] Integration test: end-to-end dispatch → customer mock receives signed POST
- [ ] Integration test: flaky customer (5xx twice then 200) delivers successfully on attempt 3

## Out of scope

- Per-event filtering beyond `events` array — v2
- Webhook replay UI (re-send a failed delivery) — v2
- Per-subscription rate limits — v2

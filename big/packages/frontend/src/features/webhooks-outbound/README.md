# webhooks-outbound/

Customer-configured outbound webhooks (admin only).

## Flow diagram coverage

- Q1 (external half) — customers register URLs that receive signed POSTs on scan/finding/billing events

## Responsibility

CRUD UI for webhook subscriptions. The HMAC signing secret is shown exactly once on creation and never retrievable — the UI emphasizes this.

## Routes owned

- `/settings/webhooks` → `WebhooksPage` (RequireRole org_admin)

## Backend endpoints consumed

- `GET /api/webhooks/outbound`
- `POST /api/webhooks/outbound` (returns `secret` once)
- `DELETE /api/webhooks/outbound/:id`

## Public hooks

- `useWebhookSubscriptionsQuery()`
- `useCreateWebhookSubscription()`
- `useDeleteWebhookSubscription()`

## Implementation checklist

- [ ] `WebhooksTable` — url, events badges, active toggle, delete
- [ ] `CreateWebhookDialog` — url input + events multi-select
- [ ] `SecretRevealDialog` — shown after create: secret + copy-to-clipboard + warning ("shown once")
- [ ] Confirm dialog on delete
- [ ] Docs link pointing to signing spec (re-use backend `webhooks-outbound/README.md`)

## Out of scope

- Delivery history view — v2
- Webhook replay — v2
- Per-event rate limits UI — v2

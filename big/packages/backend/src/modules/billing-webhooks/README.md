# billing-webhooks/

Inbound Razorpay webhooks. Public, raw-body, signature-verified, idempotent.

## Flow diagram coverage

- BF — gateway sends webhook to backend
- BG — backend validates signature
- BH — webhook valid + not replayed?
- BH1 — reject + alert/log on fail
- BI — update payment record
- BJ — update subscription / entitlements / plan limits
- BK — audit log for billing change
- BL — refresh dashboard billing state (emits notification → `notifications` module)

## Responsibility

Receive Razorpay webhooks and mutate billing state atomically. This is the ONLY module allowed to write `Subscription` based on payment state.

## Public API

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/webhooks/razorpay` | **public** (signature-verified) | Razorpay webhook receiver |

## Security critical

1. **Route is public** — no JWT guard. Declared `@Public()`.
2. **Raw body required** — the JSON body parser in `main.ts` must skip this route. Signature is computed over raw bytes, not re-serialized JSON.
3. **Signature verification** uses `crypto.timingSafeEqual` to prevent timing attacks.
4. **Replay protection** uses `WebhookEvent.eventId` unique constraint. On violation, return 200 OK — Razorpay retries until it gets 2xx.
5. **Always return 200** after successful persistence; never leak exceptions to Razorpay (retry storm risk). Unexpected errors → 500 only after `WebhookEvent.status = FAILED` is persisted.

## Internal services (exposed)

None externally — this module is a sink, not a source.

## Dependencies

- `PrismaService`
- `SubscriptionsModule` — `SubscriptionsService.upsertFromPayment`
- `AuditService` (global)
- `NotificationsService` (global) — emit `billing.updated` to refresh dashboard

## Depended on by

Nothing. Payment providers call it directly.

## DB tables owned (writes)

- `WebhookEvent` (create)
- `PaymentOrder` (status update)
- `Subscription` (via `SubscriptionsService.upsertFromPayment`)

## Events handled

| Razorpay event | Action |
|---|---|
| `payment.captured` | `PaymentOrder.status = PAID`, mint/refresh `Subscription` |
| `payment.failed` | `PaymentOrder.status = FAILED` |
| `subscription.activated` | `Subscription.status = ACTIVE` + set `currentPeriodEnd` |
| `subscription.halted` | `Subscription.status = PAST_DUE` |
| `subscription.cancelled` | `Subscription.cancel` |
| `subscription.charged` | renew `currentPeriodEnd` |

Unknown events are still persisted (`WebhookEvent.status = PROCESSED`) but skipped.

## Environment variables

- `RAZORPAY_WEBHOOK_SECRET`

## Implementation checklist

- [ ] Raw body wiring in `main.ts` (already in place — verify)
- [ ] `SignatureVerifierService.verify` (HMAC SHA256, timing-safe)
- [ ] Idempotency: `WebhookEvent.create({ eventId })` — catch unique-violation and short-circuit
- [ ] `WebhookProcessorService.process` switch on event types above
- [ ] Each event type writes an `AuditLog` row
- [ ] Each successful mutation emits `billing.updated` on `NotificationsService`
- [ ] Integration test: replay of same event returns 200 without duplicating state
- [ ] Negative test: bad signature returns 401 + persists nothing

## Out of scope

- Subscription upgrades mid-cycle — v2
- Dunning emails for PAST_DUE — v2 (see `notifications` module for hook)

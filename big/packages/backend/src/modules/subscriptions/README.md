# subscriptions/

Per-org active subscription. Source of truth for "what plan is this org on right now".

## Flow diagram coverage

- X2 — "Billing / Subscription" dashboard tile reads from here
- BJ — webhook handler calls `upsertFromPayment` to reflect a completed payment
- CG / CH — scan authz reads the plan + entitlements through this module

## Responsibility

Hold the Subscription row per org. Used by dashboards and scan authorization. Writes come from `billing-webhooks` (after a webhook confirms payment).

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/subscriptions/current` | any member | Current subscription + plan |

## Internal services (exposed)

- `SubscriptionsService.getForOrg(orgId)` — used by `dashboard`, `rbac/entitlements`.
- `SubscriptionsService.upsertFromPayment(...)` — **called only by `billing-webhooks`** after a verified payment.
- `SubscriptionsService.cancel(orgId)` — admin/self-serve cancel.

## Dependencies

- `PrismaService`

## Depended on by

- `dashboard`
- `rbac` (EntitlementsService)
- `billing-webhooks`

## DB tables owned

- `Subscription`

## State machine

```
TRIAL → ACTIVE → (PAST_DUE | CANCELED | EXPIRED)
ACTIVE ↔ PAST_DUE   // PAST_DUE can recover to ACTIVE if payment retries succeed
```

## Implementation checklist

- [ ] `SubscriptionsService.getForOrg` — include plan + entitlements
- [ ] `SubscriptionsService.upsertFromPayment` — idempotent on `razorpaySubscriptionId`
- [ ] `SubscriptionsService.cancel` — sets status + `canceledAt`, retains `currentPeriodEnd`
- [ ] Unit tests for state transitions
- [ ] Integration test with billing-webhooks flow end-to-end

## Out of scope

- Proration / upgrades mid-period — v2
- Multi-currency — v2 (INR only for v1)

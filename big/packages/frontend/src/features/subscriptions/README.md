# subscriptions/

Current-org subscription — hook-only feature (no pages).

## Flow diagram coverage

- X2 — Billing / Subscription tile on dashboard (reads via this hook)
- BJ — backend updates after Razorpay webhook; we just re-query on `billing.updated` WS event

## Responsibility

Expose `useCurrentSubscription` for `dashboard` and `billing`. That's it.

## Backend endpoints consumed

- `GET /api/subscriptions/current`

## Public hooks

- `useCurrentSubscription()`

## WebSocket events consumed

- `billing.updated` → invalidate `['subscriptions', 'current']` (usually handled by the billing feature's WS listener which already invalidates this key too)

## Out of scope

- Any UI — belongs in `features/billing` or `features/dashboard`

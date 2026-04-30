# billing/

Checkout flow (Razorpay) + current-billing view.

## Flow diagram coverage

- X2 — Billing tile on dashboard (reads `useCurrentSubscription`; this feature owns the full page)
- BA — admin views plan or starts payment
- BB — frontend calls billing service
- BC — backend creates Razorpay order
- BD — frontend redirects to Razorpay Checkout modal
- BE — user pays in the Razorpay modal
- (BF→BL — backend-only; frontend listens for `billing.updated` WS event)

## Responsibility

- `/billing` page shows current subscription + payment history.
- `useCheckout` mutation: create order → open Razorpay Checkout → trust backend webhook for final state.

## Routes owned

- `/billing` → `BillingPage`

## Backend endpoints consumed

- `POST /api/billing/checkout`
- `GET /api/billing/orders`

## External SDK

- `razorpay` Checkout JS loaded lazily by `api/razorpay.ts` when the user starts checkout. Not in `index.html`.

## Public hooks

- `useCheckout()` — mutation kicks off the whole flow

## WebSocket events consumed

- `billing.updated` → invalidate `['subscriptions', 'current']` + `['dashboard', 'bootstrap']` + `['billing', 'orders']`

## Trust boundary

**The frontend never trusts the Razorpay modal result.** When the modal closes successfully, we wait for the `billing.updated` WS event (fired after backend processes the webhook). If the WS event doesn't arrive in ~30s, the page shows a "processing" banner.

## Implementation checklist

- [ ] `BillingPage` — current subscription card + recent orders table
- [ ] `useCheckout` — create order, open modal, handle cancel
- [ ] Lazy SDK load via `loadScript`; cache so re-opens don't re-download
- [ ] `billing.updated` listener invalidates queries + shows success toast
- [ ] Link from `/` dashboard "Upgrade" CTA → `/billing/plans`
- [ ] Test plan change end-to-end with razorpay test keys

## Out of scope

- Refunds — v2
- Invoices PDF download — v2
- Failed-payment retry UX — v2 (backend sets PAST_DUE; banner is enough for v1)

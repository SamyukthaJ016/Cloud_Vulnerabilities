# plans/

Plan catalog UI — pricing page + upgrade chooser.

## Flow diagram coverage

- Supports BA (admin views plan) — the pricing / upgrade picker. Actual checkout lives in `features/billing`.

## Responsibility

Read-only presentation of active plans. Clicking "Upgrade" opens Razorpay Checkout via the `billing` feature's `useCheckout` hook.

## Routes owned

- `/billing/plans` → `PlansPage`

## Backend endpoints consumed

- `GET /api/plans` (public — no auth)

## Public hooks

- `usePlansQuery()`

## Implementation checklist

- [ ] `PlanCard` — name, price (paise → INR via `formatPaise`), entitlement summary
- [ ] Highlight the current plan (compare with `useCurrentSubscription`)
- [ ] "Upgrade" CTA → `useCheckout().mutate({ planKey })` from `features/billing`
- [ ] Disable current plan's button

## Out of scope

- Coupons / promo codes — v2
- Plan comparison table — v2

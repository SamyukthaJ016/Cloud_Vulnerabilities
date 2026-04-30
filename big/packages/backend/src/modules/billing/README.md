# billing/

Razorpay integration: creates payment orders, returns checkout config for the frontend.

## Flow diagram coverage

- X2 — "Billing / Subscription" dashboard tile
- BA — admin views plan / starts payment
- BB — frontend calls billing service
- BC — create payment order / checkout session
- BD — frontend redirects to Razorpay Checkout (frontend concern; backend returns keyId + orderId for the SDK)

Post-payment events (BE → BL) are handled by the sibling **`billing-webhooks`** module — keep them separate because webhook routes are public + raw-body + different auth.

## Responsibility

Create Razorpay orders and the `PaymentOrder` correlation row. Return the minimum data the frontend needs to open Razorpay Checkout.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/billing/checkout` | `org_admin` | Create Razorpay order for selected plan |
| GET | `/billing/orders` | `org_admin` | List historical orders for the current org |

`POST /billing/checkout` response:
```json
{
  "orderId": "order_xxx",
  "amountInPaise": 499900,
  "currency": "INR",
  "keyId": "rzp_test_xxx",
  "planKey": "pro"
}
```

The frontend passes these to Razorpay Checkout SDK.

## Internal services (exposed)

- `BillingService.createCheckoutOrder(...)` — used by controller above.
- `RazorpayService.createOrder(...)` / `createSubscription(...)` — lower-level Razorpay calls; callable from `billing-webhooks` if needed (e.g. to re-fetch an order).

## Dependencies

- `PrismaService`
- `PlansModule` (resolve plan amount)

## Depended on by

- `billing-webhooks` (re-uses `RazorpayService` client)

## DB tables owned

- `PaymentOrder` (create only; status updates come from `billing-webhooks`)

## Environment variables

- `RAZORPAY_KEY_ID`
- `RAZORPAY_KEY_SECRET`

## Implementation checklist

- [ ] `RazorpayClient` wraps the SDK
- [ ] `RazorpayService.createOrder` — translate SDK error codes to our errors
- [ ] `BillingService.createCheckoutOrder`:
  - [ ] resolve plan amount
  - [ ] create razorpay order
  - [ ] persist `PaymentOrder` with `status: CREATED`
  - [ ] return minimal checkout config
- [ ] `BillingService.listOrders`
- [ ] DTOs with `class-validator`
- [ ] Audit log on checkout start (via `@AuditAction`)
- [ ] Unit tests with a mocked `RazorpayService`

## Out of scope

- Subscription billing (recurring) — scaffolded in `RazorpayService.createSubscription`, wire once one-time billing is proven
- Refunds — v2
- Invoices / GST receipts — v2

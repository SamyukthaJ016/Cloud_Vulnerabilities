# plans/

Plan catalog (read-only from an API perspective). Plans are seeded, not user-created.

## Flow diagram coverage

Indirect — referenced by X2 (billing tile), CG/CH (entitlement check).

## Responsibility

Expose the plan catalog. Plans themselves are seeded via `prisma/seed.ts`.

## Public API

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/plans` | public | List active plans (for pricing page + upgrade UI) |

## Internal services (exposed)

- `PlansService.listActive()` — used by `billing` to present checkout options.
- `PlansService.getByKey(key)` — resolve a plan by key during order creation.

## DB tables owned

- `Plan`
- `PlanEntitlement`

## Seed format

See `prisma/seed.ts` → `seedPlans()`. Each plan gets an entitlement set:

- `max_scans_per_month` (int)
- `max_concurrent_scans` (int)
- `scanner.<scanner_key>.enabled` (bool) — one per scanner

Example (free plan):
```
max_scans_per_month=10, max_concurrent_scans=1,
scanner.scanner_1.enabled=true, scanner.scanner_2.enabled=false, ...
```

## Implementation checklist

- [ ] `PlansService.listActive` — include entitlements
- [ ] `PlansService.getByKey`
- [ ] Seed: free / pro / enterprise with realistic entitlements
- [ ] Unit test

## Out of scope

- Admin UI for editing plans — v2; for now, plan changes require a code + seed update
- Coupons / discounts — v2

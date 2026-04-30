# dashboard/

Single bootstrap endpoint that aggregates everything the dashboard shell needs on first render.

## Flow diagram coverage

- R — `GET /dashboard/bootstrap` called after login
- S — load organization context
- T — load role + permissions
- U — load subscription / billing status
- V — load enabled scanner catalog
- W — load org profile + secret metadata + recent scan history
- X → X5 — shape the payload so the frontend can render tiles:
  - X1 Organization Profile
  - X2 Billing / Subscription
  - X3 API Key / Secret Configuration
  - X4 Scanner Tiles (SA1..SAN)
  - X5 Audit / Recent Activity

## Responsibility

**Compose, don't compute.** This module doesn't own any tables — it just calls services from other modules (in parallel via `Promise.all`) and assembles the response.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/dashboard/bootstrap` | any authenticated + org-assigned user | Aggregate bootstrap payload |

## Response shape (stable contract with frontend)

```ts
{
  organization: { id, name, slug, status },
  role: { key, name },
  permissions: string[],
  subscription: { plan: { key, name }, status, currentPeriodEnd },
  scanners: [{ id, key, name, category, availability, dashboardBaseUrl }],
  secrets: [{ id, key, scannerKey, status, createdAt }],  // metadata only
  recent: {
    scans: [{ id, scannerKey, status, completedAt, summary: { critical, high, medium, low, info } | null }],
    findings: [{ id, title, severity, scannerKey, createdAt }],
  },
}
```

## Dependencies

- `OrganizationsModule`
- `RbacModule` (global)
- `SubscriptionsModule`
- `ScannersModule`
- `SecretsModule`
- `FindingsModule`

## DB tables owned

None.

## Implementation checklist

- [ ] `DashboardService.bootstrap(orgId, userId)` — parallel fetch via Promise.all
- [ ] Timeout each sub-call to 2s — if any fails, return partial data with a `warnings` array
- [ ] Cache per `(orgId, userId)` for 5s to avoid hammering services on rapid refreshes
- [ ] E2E test: bootstrap returns the right shape for a seeded org

## Out of scope

- Scanner-specific dashboards — those are separate endpoints in `scanners`/`findings`
- Streaming updates — see `notifications` module

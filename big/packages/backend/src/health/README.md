# health/

Liveness + readiness probes for the control plane.

## Endpoint

- `GET /health` — returns `{ status: 'ok', details: {...} }` or 503 with failing indicator details.

## Indicators to implement

| Indicator | Check |
|---|---|
| `postgres` | `prisma.$queryRaw\`SELECT 1\`` |
| `redis` | BullMQ client ping |
| `vault` | `vault.health()` |
| `razorpay` | optional — reachability of the API (only if `NODE_ENV === 'production'`) |
| `scanner_1..N` | optional — each scanner service's `/health` endpoint |

## Rules

- Health endpoint is `@Public()` — no auth required.
- Keep it fast (< 500ms) — Kubernetes/load balancers probe frequently.
- Don't expose sensitive info in the response body.

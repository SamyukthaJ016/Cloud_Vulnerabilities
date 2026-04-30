# notifications/

Internal event bus + WebSocket gateway for real-time dashboard updates.

## Flow diagram coverage

- Q1 (internal half) — "Trigger dashboard refresh / notifications"
- CQ — "Frontend polls / subscribes for job updates" (WebSocket subscribers)

## Responsibility

In-process pub/sub for significant events, plus a Socket.IO gateway that relays them to connected frontend clients (scoped by `orgId`).

**This is NOT for external webhooks** — those are in `webhooks-outbound/`.

## Connection

Frontend connects to `/ws` with a JWT:
```
io(baseUrl, { path: '/ws', auth: { token: <jwt> } })
```

The gateway verifies the JWT, extracts `orgId`, and joins the socket to the room `org:<orgId>`. All outbound messages are emitted only to the matching room — never cross-tenant leak.

## Events

| Event | Source | Payload (`{ orgId, ... }`) |
|---|---|---|
| `scan.dispatched` | `scans` | `{ orgId, scanJobId, scannerKey }` |
| `scan.completed` | `scanner-callbacks` | `{ orgId, scanJobId, status, summary }` |
| `scan.failed` | `scanner-callbacks` | `{ orgId, scanJobId, error }` |
| `finding.created` | `findings` | `{ orgId, findingId, severity, scannerKey }` (may be batched) |
| `billing.updated` | `billing-webhooks` | `{ orgId, subscription: { status, planKey } }` |
| `secret.changed` | `secrets` | `{ orgId, secretId, action: 'create'\|'revoke' }` |

## Internal services (exposed — `@Global`)

- `NotificationsService.emit(event, payload)` — anything interesting that changes state.
- `NotificationsService.on(event, handler)` — used by the gateway to fan out to sockets.

## Dependencies

- `socket.io` via `@nestjs/platform-socket.io`

## Depended on by

- `scans` / `scanner-callbacks`
- `findings`
- `billing-webhooks`
- `secrets`

## Implementation checklist

- [ ] `NotificationsService` — node `EventEmitter` is sufficient for v1
- [ ] `NotificationsGateway`:
  - [ ] handshake auth — reject connection if JWT missing/invalid
  - [ ] join `org:<orgId>` room
  - [ ] wire service `.on(...)` → `server.to(room).emit(...)`
- [ ] Scale note: if we run multiple API pods, swap EventEmitter for Redis pub/sub (already have Redis) — leave a comment in the service for the migration path
- [ ] Unit test: emit → room-scoped fan-out

## Out of scope

- Email / SMS notifications — v2
- Persistent notification inbox — v2

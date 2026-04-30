# notifications/

WebSocket client plumbing. No routes — mounted once in `app/providers.tsx`.

## Flow diagram coverage

- Q1 (internal half) — "Trigger dashboard refresh / notifications"
- CQ — "Frontend polls / subscribes for job updates" (we use subscribe, not poll)

## Responsibility

Connect to the backend Socket.IO gateway once the user is authenticated, fan events into the realtime ring buffer, and expose a `useWsEvent` hook (in `@/hooks`) so features can subscribe declaratively.

## Public API

- `<WebSocketProvider>` — mounted by `app/providers.tsx`
- `useWebSocket()` — returns current `Socket | null`
- `useWsEvent(event, handler)` — **in `@/hooks/use-ws-event`**, not here, but it depends on this provider

## WebSocket event shapes

Defined in `@cloudguard/shared/events.ts`. Each payload includes `orgId` — the backend already scopes by room, but checking `payload.orgId === user.orgId` in handlers is a reasonable belt-and-braces check.

## Dependencies

- `socket.io-client`
- `@/stores/realtime.store`
- `@/hooks/use-current-user`

## Depended on by

- `app/providers.tsx` mounts the provider
- `features/scans`, `features/findings`, `features/billing`, `features/secrets` subscribe to specific events via `useWsEvent`

## Implementation checklist

- [ ] Connect on `user.orgId` change; reconnect on transport drop (socket.io handles reconnection automatically — verify)
- [ ] Ring buffer in `realtime.store.ts` caps at 100 events
- [ ] Notification bell component in `TopBar` reads from the ring buffer
- [ ] Per-event toasts (opt-in per feature via `useWsEvent` + `toast.success`)
- [ ] Unit test: event received → pushed to store

## Out of scope

- Email / SMS — v2
- Persistent in-app inbox — v2
- Cross-tab coordination (BroadcastChannel) — v2

# app/

App shell — providers, router, query client, error boundary.

This is the **only place** that composes the full app. Feature modules never wrap the app or mount providers. Adding a new provider? It goes here.

## Files

- `providers.tsx` — React Query + WebSocket + toast + error boundary.
- `query-client.ts` — TanStack Query config (stale time, retry rules).
- `router.tsx` — every route in one file so the URL space is easy to audit.
- `error-boundary.tsx` — last-resort catch.

## Rules

- **One router file.** Don't split routes per feature; keep `router.tsx` as the whole map.
- **Route elements live in `features/<module>/pages/`** and are re-exported via each feature's `index.ts`. Router imports from the barrel only.
- **Guards are components**, not route properties. `<RequireAuth>` and `<RequireRole>` wrap the children of a route element.
- **No data fetching here.** Providers don't load data. Pages do.

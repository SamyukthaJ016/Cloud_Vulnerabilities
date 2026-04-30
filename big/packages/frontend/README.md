# @cloudguard/frontend

React dashboard for the CloudGuard control plane.

**Stack:** Vite · React 18 · TypeScript · Tailwind CSS + shadcn/ui · TanStack Query · Zustand · React Router 6 · Socket.IO.

## Quick start

From the repo root:

```bash
pnpm install
cp packages/frontend/.env.example packages/frontend/.env
pnpm dev:frontend       # Vite on :5173; proxies /api + /ws to :3000
```

Backend must be running on `:3000` (or proxy target adjusted in `vite.config.ts`).

## Folder map

```
src/
├── main.tsx
├── App.tsx
├── app/                     # providers, router, query client, error boundary
├── api/                     # axios + websocket + error utilities
├── components/
│   ├── ui/                  # shadcn primitives (copy-in; install via CLI)
│   └── layout/              # AppShell, AuthLayout, TopBar, Sidebar
├── hooks/                   # use-current-user, use-org-id, use-permissions, use-ws-event
├── lib/                     # utils.ts, permissions.ts
├── stores/                  # Zustand: auth.store, realtime.store
├── styles/globals.css
└── features/                # one folder per backend module (flow-domain mirror)
    ├── auth/                # sign in, guards, /onboarding
    ├── users/               # /settings/profile
    ├── organizations/       # /settings/organization, /settings/members
    ├── rbac/                # hook-only — README for symmetry with backend
    ├── dashboard/           # /  (bootstrap + tiles)
    ├── secrets/             # /secrets
    ├── plans/               # /billing/plans
    ├── subscriptions/       # hook-only — used by dashboard + billing
    ├── billing/             # /billing (Razorpay Checkout)
    ├── scanners/            # /scanners (tiles + run modal)
    ├── scans/               # /scans, /scans/:id
    ├── findings/            # /findings, /findings/:id
    ├── audit/               # /audit
    ├── notifications/       # WebSocketProvider (no routes)
    └── webhooks-outbound/   # /settings/webhooks
```

Every folder under `features/` has a **`README.md`** with: flow-node coverage, routes owned, endpoints consumed, public hooks, implementation checklist, out-of-scope.

## Feature → backend mapping

1:1 with `packages/backend/src/modules/` except `billing-webhooks` and `scanner-callbacks`, which are backend-only (inbound webhook / callback endpoints).

## Import paths

```ts
import { Button } from '@/components/ui/button';
import { useScansQuery } from '@/features/scans';
import { formatPaise } from '@/lib/utils';
import { Severity, ScanJobDto } from '@cloudguard/shared';
```

## Rules

1. **Feature A never imports from `features/B/`** — use each feature's `index.ts` barrel, or move shared data to a hook in the owning feature.
2. **No raw `fetch` / `axios`.** Always `http` from `@/api/http`. Every feature's api layer uses TanStack Query hooks, not bare promises.
3. **No feature-specific UI in `components/`.** Generic primitives + layout only.
4. **Route pages are thin.** They compose hooks + presentational components. No business logic.
5. **All types that cross the wire come from `@cloudguard/shared`.**

## Adding a shadcn/ui primitive

```bash
cd packages/frontend
pnpm dlx shadcn-ui@latest add <name>   # e.g. button, dialog, table, badge, toast, sheet, tabs
```

Commit the file under `src/components/ui/`.

## Verification

1. `pnpm dev:backend` on :3000
2. `pnpm dev:frontend` on :5173
3. `http://localhost:5173/login` — renders Google sign-in button
4. Sign in → lands on `/` dashboard shell (or `/onboarding` if UNASSIGNED)
5. `pnpm build` builds without errors
6. Open any feature folder's `README.md` — it's the ticket spec for that slice

## Scripts

```bash
pnpm dev           # vite dev server
pnpm build         # tsc -b && vite build
pnpm preview       # preview built bundle
pnpm lint          # eslint --fix
pnpm format        # prettier --write
pnpm test          # vitest run
```

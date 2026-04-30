# CloudGuard Control Plane

Multi-tenant SaaS control plane for security scanning. Google SSO, Razorpay billing, Vault-backed secrets, async scans via external scanner services.

**Monorepo** — pnpm workspaces.

```
cloudguard-control-plane/
├── packages/
│   ├── backend/       # NestJS + Postgres + Prisma 6
│   ├── frontend/      # Vite + React + Tailwind + shadcn/ui
│   └── shared/        # @cloudguard/shared — wire-contract types (DTOs, enums, events)
├── docker-compose.yml # postgres + redis + vault-dev for local
└── Flow-Diagram.mmd   # authoritative flow spec — every module maps to its nodes
```

## Quick start

```bash
# install everything
pnpm install

# infra (postgres + redis + vault-dev)
docker compose up -d

# backend env
cp packages/backend/.env.example packages/backend/.env
# fill in GOOGLE_*, RAZORPAY_*, JWT_SECRET, SCANNER_N_*

# frontend env
cp packages/frontend/.env.example packages/frontend/.env

# db setup (once)
pnpm prisma:migrate
pnpm prisma:seed

# run both
pnpm dev:all
# or one at a time:
pnpm dev:backend        # :3000
pnpm dev:frontend       # :5173
```

## Packages

| Package | What | README |
|---|---|---|
| `backend` | NestJS API + Prisma + BullMQ workers | [packages/backend/README.md](./packages/backend/README.md) — via its own `README.md` copied over during scaffold |
| `frontend` | React dashboard SPA | [packages/frontend/README.md](./packages/frontend/README.md) |
| `shared` | Types used by both | [packages/shared/README.md](./packages/shared/README.md) |

> **Note:** the original root-level `README.md` for the backend was moved into `packages/backend/`. Open that for deep backend docs. The file you're reading now is the monorepo overview.

## Team workflow

- Split by **flow-diagram domain**, not by headcount. Every backend module (`packages/backend/src/modules/<name>/`) has a matching frontend feature (`packages/frontend/src/features/<name>/`).
- Each module/feature folder has its own `README.md` with flow-node coverage + implementation checklist — copy it into your PR description.
- Branch convention: `feat/<scope>-<short-desc>` where `<scope>` is one of `auth`, `billing`, `scanners`, `scans`, `fe-dashboard`, `fe-findings`, etc. (prefix `fe-` for frontend-only changes in that feature).

## Scripts

All scripts run from the repo root; pnpm filters to the right package.

| Command | What |
|---|---|
| `pnpm dev:backend` | NestJS watch mode |
| `pnpm dev:frontend` | Vite dev server |
| `pnpm dev:all` | Both in parallel |
| `pnpm build` | Build every package |
| `pnpm lint` | Lint every package |
| `pnpm test` | Run tests in every package |
| `pnpm prisma:migrate` | Create + run a dev migration |
| `pnpm prisma:seed` | Seed roles/permissions/plans/scanners |
| `pnpm prisma:studio` | Open Prisma Studio |

## Flow-diagram-first

The authoritative spec is [Flow-Diagram.mmd](./Flow-Diagram.mmd). Every module (frontend and backend) documents exactly which nodes it owns. Before adding a new route/endpoint, find the matching flow node first — if there isn't one, the diagram should be updated first.

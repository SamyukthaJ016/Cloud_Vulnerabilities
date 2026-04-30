# @cloudguard/shared

Wire-contract types shared between `backend` and `frontend`.

## What lives here

- **Enums** — Prisma enum values as string unions (so the frontend doesn't depend on `@prisma/client`).
- **API DTOs** — request/response shapes for every HTTP endpoint, grouped by module.
- **Event shapes** — WebSocket event names + payloads.
- **Pagination types** — `PaginatedResult<T>`, `PaginationParams`.

## What does NOT live here

- Class-validator decorators — those stay in `packages/backend/src/modules/*/dto/`. Backend DTO classes `implements` the plain interface from here.
- React components / hooks — those belong in `packages/frontend/`.
- Business logic — it's a types-only package.

## Import path

Both packages reference this via:

```ts
import { Severity, ScanJobDto } from '@cloudguard/shared';
```

pnpm workspaces link the source directly — no build step needed in dev. Changes here are picked up immediately by both packages.

## Rules

1. **Every backend DTO used in a response has a matching type here.** If a backend controller returns something, its shape is declared here.
2. **Enums are the single source of truth.** Prisma generates enum names; we mirror them as string unions so the frontend gates on the same strings.
3. **No `class-validator`, no `class-transformer`, no Prisma imports.** This package compiles with zero runtime dependencies.
4. **Never rename a field without PR-ing both packages.** Changes are coordinated — that's why shared types exist.

## Files

- `index.ts` — barrel of everything below
- `enums.ts` — all enum string unions
- `pagination.ts` — paginated response + query params
- `events.ts` — WebSocket event names + payload shapes
- `api/` — one file per backend module with request/response DTOs

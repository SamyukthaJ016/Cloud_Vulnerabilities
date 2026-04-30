# common/

Shared infrastructure used by every feature module. Owned by the **platform lead** — feature-module authors should consume these, not add new ones.

## Structure

```
common/
├── decorators/      # @CurrentUser @OrgId @Roles @Public @AuditAction
├── guards/          # JwtAuthGuard, RolesGuard, OrgContextGuard
├── interceptors/    # LoggingInterceptor, AuditInterceptor
├── filters/         # HttpExceptionFilter (global)
├── pipes/           # (add custom pipes if needed)
├── enums/           # Runtime enums not backed by Prisma (Prisma enums come from @prisma/client)
├── types/           # RequestWithUser, JwtPayload, PaginatedResult, etc.
└── utils/           # Pure helper functions (no DI, no state)
```

## What belongs here

**Yes:**
- Cross-cutting concerns used by 3+ modules
- Decorators/guards/interceptors wired via `APP_*` providers
- Shared types that multiple modules import

**No:**
- Business logic — that belongs in a feature module
- Single-use helpers — keep those next to their consumer
- Domain-specific constants (plan keys, scanner keys, etc.) — those belong in their domain module

## Rules for the team

1. **Don't add to `common/` without review** — growing this folder silently is how projects turn into tangled messes.
2. **Never import a feature module from `common/`** — dependency must flow one way: `common → infra → modules`.
3. **Keep `utils/` pure** — no classes with state, no DI, just functions. Anything with a dependency becomes a service in a module.

## Key contracts

### `@CurrentUser()` decorator
Returns `{ userId, orgId, roleKey }` from the authenticated JWT. Use in any authenticated controller method.

### `@OrgId()` decorator
Shortcut that returns just `orgId` — useful for tenant-scoped queries.

### `@Roles(...keys)` + `RolesGuard`
Gate an endpoint by role key(s). Combined with `JwtAuthGuard` for auth.

### `@Public()` decorator
Opt out of the global `JwtAuthGuard` (login page, health, webhooks).

### `@AuditAction(action, resource)` decorator + `AuditInterceptor`
Auto-writes an `AuditLog` row on successful request completion. Action + resource are the free-form strings stored on the row (e.g. `'secret.create'`, `'secret'`).

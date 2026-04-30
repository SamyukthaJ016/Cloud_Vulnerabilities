# users/

User profile management.

## Flow diagram coverage

- I — extract user identity from SSO claims
- J — check if user exists in DB
- K — create user profile (PENDING, default role)
- L — load existing user profile

## Responsibility

Own the `User` table. Provides idempotent `findOrCreateFromSso` used by `auth` module. Also exposes a thin CRUD surface for the frontend to read/update the logged-in user's profile.

## Public API

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/users/me` | ✓ | Return current user profile |
| PATCH | `/users/me` | ✓ | Update name / avatar |

## Internal services (exposed)

- `UsersService.findOrCreateFromSso(profile)` — called by `AuthService` during login (flow J/K/L).
- `UsersService.findById(userId)` — used by other modules that need user details.

## Dependencies

- `PrismaService` (via global `PrismaModule`)

## Depended on by

- `auth`

## DB tables owned

- `User`

## Implementation checklist

- [ ] `UsersService.findOrCreateFromSso`:
  - [ ] findUnique by `(ssoProvider, ssoSubject)`
  - [ ] if missing, create with `status: PENDING`, minimal profile
  - [ ] if present, update `lastLoginAt`, `name`, `avatarUrl` if changed
- [ ] `UsersService.findById`
- [ ] `UsersService.updateProfile`
- [ ] DTOs with `class-validator` in `./dto/`
- [ ] Unit tests
- [ ] Integration tests (hit a real Postgres — see `test/` strategy)

## Out of scope

- Org mapping — that's `organizations/`
- Role assignment — that's `rbac/`
- Admin-facing user search / invite — v2

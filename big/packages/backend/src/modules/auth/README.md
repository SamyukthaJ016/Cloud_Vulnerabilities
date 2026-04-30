# auth/

Google SSO sign-in, app session JWT issuance, and token validation.

## Flow diagram coverage

**Owns:** A → P (login path)
- A/B/C — frontend concern; this module exposes the endpoints the frontend hits
- D — `GET /auth/google` starts the OAuth redirect
- E — Google authenticates the user
- F — `GET /auth/google/callback` receives Google's ID token + profile
- G/H — ID token validation (signature, audience, expiry)
- I → L — user identity resolution (delegates to `users` module)
- M/N — org resolution (delegates to `organizations` module)
- O — role + entitlements resolution (delegates to `rbac` module)
- P — JWT issuance + cookie set

Also owns **TS1** (every request carries identity) via `JwtAuthGuard` + `JwtStrategy`.

## Responsibility

End-to-end Google SSO login. The module itself does no business logic for user/org/role resolution — it composes the other identity modules.

## Public API

| Method | Path | Description |
|---|---|---|
| GET | `/auth/google` | Redirects to Google OAuth consent screen |
| GET | `/auth/google/callback` | Google redirect target — issues app JWT + redirects to frontend dashboard |
| GET | `/auth/me` | Returns the authenticated user (from JWT) |
| GET | `/auth/logout` | Clears session cookie |

## Internal services (exposed)

- `AuthService.completeLogin(profile)` — runs the full F→P flow; returns `{ accessToken }`.
- `AuthService.signAccessToken(payload)` — used by modules that need to mint a new JWT (e.g. after org-switch).

## Dependencies

- `UsersModule` — `UsersService.findOrCreateFromSso(profile)`
- `OrganizationsModule` — `OrganizationsService.resolveForUser(userId, emailDomain)`
- `RbacModule` — `RbacService.resolveForMember(orgMemberId)`
- `AuditService` (global) — writes `user.login` / `user.login.failed`

## DB tables owned

- `User` (updates `lastLoginAt`, `status`)
- Reads: `OrgMember`, `Role`, `Organization`

## Environment variables

- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_CALLBACK_URL`
- `JWT_SECRET`
- `JWT_EXPIRES_IN`
- `JWT_REFRESH_SECRET`
- `JWT_REFRESH_EXPIRES_IN`

## Implementation checklist

- [ ] Wire `GoogleStrategy` with env-driven config
- [ ] Wire `JwtStrategy` (extract from cookie OR `Authorization: Bearer`)
- [ ] Implement `AuthService.completeLogin(profile)`:
  - [ ] validate email present + verified
  - [ ] call `UsersService.findOrCreateFromSso`
  - [ ] call `OrganizationsService.resolveForUser` — may return null (UNASSIGNED)
  - [ ] call `RbacService.resolveForMember` — get roleKey
  - [ ] sign JWT with `{ sub, email, orgId, roleKey }`
  - [ ] write audit log
- [ ] Implement `/auth/google/callback`:
  - [ ] set HTTP-only `access_token` cookie
  - [ ] redirect to `${FRONTEND_BASE_URL}/dashboard` (or `/onboarding` if UNASSIGNED)
- [ ] Implement `/auth/logout` — clear cookie
- [ ] Register `JwtAuthGuard` as global `APP_GUARD`
- [ ] Unit tests for `AuthService.completeLogin`
- [ ] E2E test for Google callback (mock Google response)

## Out of scope

- Refresh-token rotation — deferred to a follow-up ticket
- Org switching (user in multiple orgs) — v2; for v1 each user belongs to exactly one org
- Password reset / local auth — never, SSO only

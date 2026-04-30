# auth/

Google SSO sign-in flow + route guards + session bootstrap.

## Flow diagram coverage

- A — user opens app
- B — login page renders
- C — user clicks sign in
- D (redirect to SSO) — frontend issues a full-page redirect to backend `/auth/google`
- EF1 — `/auth/error` on failure
- F–P (backend half) — backend handles callback + JWT
- P (frontend half) — `/auth/callback` reads user via `/auth/me`, populates store, redirects to `/`
- N1 — UNASSIGNED user landed on `/onboarding`

## Responsibility

Own login/logout UX, all auth-related route guards, and the client-side session cache (via `auth.store.ts`). This module is the only one that directly populates `useAuthStore`.

## Routes owned

- `/login` → `LoginPage`
- `/auth/callback` → `AuthCallbackPage`
- `/auth/error` → `AuthErrorPage`
- `/onboarding` → `OnboardingPage`

## Backend endpoints consumed

- `GET /api/auth/google` (link, not fetch) — starts OAuth
- `GET /api/auth/me` — session bootstrap
- `GET /api/auth/logout`

## Public hooks / components

- `useMeQuery()` — cached session fetch, populates auth store
- `useLogout()` — clear store + redirect
- `<RequireAuth>` — wraps protected routes
- `<RequireRole role="...">` — gates by role key

## Client state

- Populates `stores/auth.store.ts` with `{ user, permissions }`.
- Clears it on logout.

## WebSocket events consumed

None. Auth is request-scoped.

## Dependencies

- `@/api/http` + `@/stores/auth.store`
- `@cloudguard/shared` for types

## Implementation checklist

- [ ] `useMeQuery` populates permissions (backend needs to add them to `/auth/me` response, or a separate `/rbac/me` endpoint — coordinate with backend auth/rbac modules)
- [ ] `LoginPage` handles `?error=` query param with inline message
- [ ] `AuthCallbackPage` preserves `?next=` across redirect
- [ ] `RequireAuth` shows a branded loading state (skeleton-ish) instead of plain text
- [ ] `RequireRole` supports array of roles
- [ ] Logout hits backend and clears both the auth store and the React Query cache
- [ ] Topbar user menu with sign-out
- [ ] Respect `UNASSIGNED` status → onboarding page
- [ ] Unit tests for guards

## Out of scope

- Refresh token rotation — backend owns it; frontend just sees 401 and bounces to `/login`
- Multi-org switcher — v2
- Password / magic-link auth — never, SSO only

# rbac/

No routes, no pages. This feature exists for README-level symmetry with the backend's `rbac` module and to house future role/permission UI.

## Flow diagram coverage

- O — backend resolves roles/entitlements during login; frontend consumes the result via `useAuthStore`.
- AB, CF — permission checks are enforced on the backend, mirrored in UI via `usePermissions`.

## Responsibility

**None currently.** The permission constants (`@/lib/permissions.ts`) and the `usePermissions` hook (`@/hooks/use-permissions`) live at the top level because every feature uses them.

When v2 adds a platform-admin UI to view all roles/permissions or to customize roles, that UI lives here.

## Depended on by (indirectly)

Every other feature, via `usePermissions()`.

## Implementation checklist (v2, not v1)

- [ ] Admin-only `/settings/roles` page listing role → permissions matrix
- [ ] If custom roles are allowed: create/edit role form

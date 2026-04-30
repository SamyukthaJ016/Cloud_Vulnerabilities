# organizations/

Organization settings + member management.

## Flow diagram coverage

- X1 — Organization Profile tile (read via `dashboard` feature's bootstrap; this feature owns the full-page edit view)
- M — org resolution is backend-only

## Responsibility

Admin-only CRUD UI for the current org and its members. Regular members see profile but can't edit.

## Routes owned

- `/settings/organization` → `OrgSettingsPage` (RequireRole org_admin)
- `/settings/members` → `MembersPage` (RequireRole org_admin)

## Backend endpoints consumed

- `GET /api/organizations/current`
- `GET /api/organizations/current/members`
- `PATCH /api/organizations/current/members/:userId/role` (TBD — coordinate with backend)
- `POST /api/organizations/current/members` (invite)
- `DELETE /api/organizations/current/members/:userId`

## Public hooks

- `useCurrentOrgQuery()`
- `useMembersQuery()`
- `useChangeMemberRole()`

## Implementation checklist

- [ ] `OrgSettingsPage` — editable name + domain, read-only slug + status
- [ ] `MembersPage` — table with role dropdown + invite modal + remove confirm
- [ ] Invite flow: email + role select
- [ ] Confirm dialog on role change (uses shadcn AlertDialog)
- [ ] Toast on success/failure

## Out of scope

- Multi-org support — v2
- Team folders within org — v2

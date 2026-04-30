# organizations/

Organization (tenant) entity + membership management.

## Flow diagram coverage

- J — user-org mapping lookup
- M — resolve organization mapping
- N — mapping found / not found decision
- N1 — mark user UNASSIGNED when no mapping (handled in auth module; we just return null here)
- K1 (partial) — tag context with `org_id`

## Responsibility

Own `Organization` and `OrgMember` tables. Primary responsibility: given a user identity, resolve which org they belong to (flow M/N). Secondary: admin CRUD for managing orgs and members.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/organizations/current` | any member | Current org details |
| GET | `/organizations/current/members` | `org_admin` | List members |
| POST | `/organizations` | platform admin | Create org (v1: seeded or admin-only) |
| POST | `/organizations/current/members` | `org_admin` | Invite / add member |
| DELETE | `/organizations/current/members/:userId` | `org_admin` | Remove member |

## Internal services (exposed)

- `OrganizationsService.resolveForUser(userId, emailDomain)` — flow M/N. Returns `{ orgId, roleId } | null`.
- `OrganizationsService.getById(orgId)` — used by `dashboard` module during bootstrap.
- `MembershipsService.*` — member CRUD.

## Dependencies

- `PrismaService`

## Depended on by

- `auth` (login flow)
- `dashboard` (bootstrap)
- `rbac` (to load role via membership)

## DB tables owned

- `Organization`
- `OrgMember`

## Resolution strategy (flow M)

Priority order when `OrganizationsService.resolveForUser` is called:

1. **Existing membership** — if the user already has an `OrgMember` row with status `ACTIVE`, return that org (v1 assumes exactly one active membership per user).
2. **Domain-based auto-assign** — if `user.email` ends with an `Organization.domain` (e.g. `@acme.com`), create an `OrgMember` with default role `org_member` and return that org.
3. **Return null** — caller (auth module) marks user as `UNASSIGNED` and sends to onboarding.

## Implementation checklist

- [ ] `OrganizationsService.resolveForUser` — covers priority order above
- [ ] `OrganizationsService.getById`
- [ ] `OrganizationsService.create` (admin-only)
- [ ] `MembershipsService.addMember` — transactional (create membership + audit log)
- [ ] `MembershipsService.listMembers` — includes role + user profile
- [ ] `MembershipsService.removeMember`
- [ ] `MembershipsService.changeRole` — writes audit log
- [ ] DTOs with `class-validator`
- [ ] Unit tests

## Out of scope

- Multi-org per user (v1 assumes one) — v2
- Org billing state — handled by `subscriptions` module
- Inviting non-signed-up users via email — v2

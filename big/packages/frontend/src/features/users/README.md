# users/

Profile settings.

## Flow diagram coverage

- I–L — backend handles user profile CRUD; frontend just reads/writes

## Responsibility

Render `/settings/profile` with the current user's editable fields (name, avatar).

## Routes owned

- `/settings/profile` → `ProfileSettingsPage`

## Backend endpoints consumed

- `GET /api/users/me`
- `PATCH /api/users/me`

## Public hooks

- `useMeProfileQuery()`
- `useUpdateProfile()`

## Implementation checklist

- [ ] `ProfileForm` with `react-hook-form` + `zod` schema
- [ ] Name input + avatar URL field (v1 — accepts URL only; upload in v2)
- [ ] Success toast via `sonner`; error toast via `useApiErrorToast`
- [ ] Disable submit while pending
- [ ] Email is read-only (SSO-owned)

## Out of scope

- Email change — SSO-bound; requires admin support
- Delete account — v2

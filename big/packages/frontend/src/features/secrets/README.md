# secrets/

Create, list, and revoke scanner credentials. App DB stores metadata; values live in Vault.

## Flow diagram coverage

- X3 — Secrets tile on dashboard (quick summary)
- Y → AG — full CRUD flow on `/secrets` page

## Responsibility

UI for managing secrets. `SecretsPage` lists metadata and exposes create + revoke actions. **Never displays a secret value** — backend never returns one after creation.

## Routes owned

- `/secrets` → `SecretsPage`

## Backend endpoints consumed

- `GET /api/secrets`
- `POST /api/secrets` — request has `value`; response never includes it
- `DELETE /api/secrets/:id`

## Public hooks

- `useSecretsQuery()`
- `useCreateSecret()`
- `useRevokeSecret()`

## WebSocket events consumed

- `secret.changed` → invalidate `['secrets']` + dashboard bootstrap

## Security rules

1. **Never stash the plaintext value anywhere client-side.** It's in the form state while the dialog is open, cleared on submit/cancel.
2. **Never log it.** Including to the React Query devtools — the mutation input is ephemeral.
3. **Use `<Input type="password">`** for the value field; autocomplete off.

## Implementation checklist

- [ ] `SecretsTable` — key, scannerKey, status badge, createdBy, createdAt, actions
- [ ] `CreateSecretDialog` — scannerKey select (from `features/scanners`), key input, value `<Input type="password">`
- [ ] Revoke confirm using shadcn AlertDialog
- [ ] Success toast includes key name (never value)
- [ ] Disable create button without `secret.write` permission
- [ ] Empty state CTA pointing to scanner config

## Out of scope

- Bulk import — v2
- Rotation reminders — v2
- Bring-your-own-vault — v2

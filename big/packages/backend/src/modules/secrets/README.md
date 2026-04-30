# secrets/

Secret/API-key management. App DB stores **metadata only**; actual values live in Vault.

## Flow diagram coverage

- X3 — frontend tile: "API Key / Secret Configuration"
- Y — admin adds or updates a credential
- Z — frontend sends secret securely to backend
- AA — backend validates request + org ownership + role
- AB — authorization check (role has `secret.write`)
- AC — encrypt in transit / avoid logging plaintext
- AD — store secret in Vault
- AE — store metadata only in app DB
- AF — audit log for create/update
- AG — refresh dashboard secret status

> Scanner v1 does **not** read secrets through this module — credentials are
> entered in the per-scan modal and forwarded once. The `readValue` /
> `listForScanner` paths below are reserved for v2.

## Responsibility

CRUD for secret metadata, plus orchestrating Vault writes/reads. Never log or persist plaintext values anywhere in app DB.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/secrets` | any member | List secret metadata for current org |
| POST | `/secrets` | `org_admin` | Create or update a secret (writes Vault + metadata) |
| DELETE | `/secrets/:id` | `org_admin` | Revoke a secret (status → REVOKED, vault entry revoked) |

Request body for POST:
```json
{ "scannerKey": "scanner_1", "key": "aws_access_key", "value": "<plaintext>" }
```

Response never includes `value`.

## Internal services (exposed)

- `SecretsService.listMetadataForOrg(orgId)` — used by `dashboard` bootstrap (flow W).
- `SecretsService.listForScanner(orgId, scannerKey)` — reserved for v2 scanner secret reuse.
- `SecretsService.readValue(orgId, secretId)` — reserved for v2 scanner secret reuse.

## Dependencies

- `PrismaService`
- `VaultService` (global)

## Depended on by

- `dashboard` (metadata listing — flow W)
- (v2) `scans` / `scanner-callbacks` for persisted scanner credentials

## DB tables owned

- `Secret`

## Security rules

1. **Never log `value`.** Not at debug level, not in error messages, not in audit details.
2. **Plaintext is ephemeral.** Received in request → immediately written to Vault → variable goes out of scope.
3. **Reads are audited** with a separate action (`secret.read`) — who read what, when, for which scan job.
4. **Authorization is transitive** — if caller has `secret.write`, they can create/update; `secret.read` means they can see metadata (not values).
5. **Vault path format is fixed** — see `infra/vault/README.md`. Don't invent new paths.

## Implementation checklist

- [ ] `SecretsService.createOrUpdate` — transactional (vault first, then DB); handle vault-ok-db-fail by re-trying DB write
- [ ] `SecretsService.listMetadataForOrg`
- [ ] `SecretsService.listForScanner`
- [ ] `SecretsService.readValue` — verify orgId, vault read, emit audit event
- [ ] `SecretsService.revoke` — set status, revoke in vault, audit
- [ ] `CreateSecretDto` with `class-validator` (`@IsString`, `@Length(1, 200)`, etc.)
- [ ] Ensure logger middleware does not dump request body on `/secrets` POST
- [ ] Unit tests with a mocked VaultService
- [ ] Integration test against vault-dev

## Out of scope

- Automated secret rotation — v2 (schema has `rotatedAt` for future use)
- Bring-your-own-Vault — v2
- Per-scan secret scoping beyond `scannerKey` — v2

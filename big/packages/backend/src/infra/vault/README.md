# infra/vault/

HashiCorp Vault client wrapper. Used by:
- `secrets` module — to write/read/delete secrets (flow Y→AG)

> Scanner v1 does **not** use Vault — credentials are entered at scan time and
> forwarded once to the scanner. Vault still backs the `secrets` module for
> non-scanner secret storage and is reserved for v2 scanner persistence.

## Path convention

```
{VAULT_KV_MOUNT}/data/{VAULT_ORG_PATH_PREFIX}/{orgId}/{scannerKey?}/{key}
```

Example:
```
secret/data/orgs/9f0.../scanner_1/aws_access_key
```

`scannerKey` is optional — org-level secrets omit it.

## Rules

- **Never log secret values.** Log only `vaultPath` and `version`.
- **App DB stores metadata only** — the `Secret` table has `vaultPath` + `vaultVersion`, not the value.
- **Vault is the write source of truth.** If a write to Vault succeeds but the DB write fails, we must either rollback the Vault write or re-try the DB write — never leave orphaned secrets. Use `prisma.$transaction` to sequence DB-then-vault, writing to vault last is safer (flow AC → AD → AE).
- **Revocation:** flipping `Secret.status` to `REVOKED` doesn't delete the vault entry; use `VaultService.revoke()`.

## Vault policy (v1)

Assume a dev root token for local; in production use AppRole auth per environment. Each environment gets a policy allowing read/write only under its `orgs/` prefix.

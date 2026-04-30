# scanners/

Scanner catalog. Populated at boot from each configured scanner's `GET /api/manifest`.

## Flow diagram coverage

- B0–B5 — manifest sync (boot + admin refresh)
- V — load scanner catalog
- X4 / SA1–SAN — scanner tiles on dashboard

## Responsibility

- Fetch manifests from every `SCANNER_N_BASE_URL` at startup and on admin demand.
- Upsert each manifest into the `Scanner` table; mark unreachable scanners as `UNAVAILABLE` (do not crash the app).
- Expose the catalog to authenticated users.

There is **no per-org scanner config in v1** — credentials are entered at scan time
and forwarded to the scanner once. Anything per-org will come back in v2.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| GET | `/scanners` | any member | Catalog with name, description, JSON-Schema for credentials, dashboardBaseUrl, availability |
| POST | `/admin/scanners/refresh` | `org_admin` | Re-fetch all scanner manifests now |

## Internal services

- `ScannerSyncService` — `OnModuleInit` + `refreshAll()`.
- `ScannersService` — `list()`, `getByKey(key)`, `getById(id)`.

## Dependencies

- `PrismaService`
- `ConfigService`
- `DynamicScannerClient` (from `scanner-clients/`)

## DB tables owned

- `Scanner` — populated entirely from manifests (key, credentialSchema, dashboardBaseUrl, iconUrl, availability, lastError, manifestFetchedAt).

## Manifest contract

Each scanner must implement `GET /api/manifest` returning:

```json
{
  "key": "aws_cspm",
  "name": "AWS CSPM",
  "description": "AWS misconfiguration scanner",
  "version": "1.2.0",
  "category": "cloud",
  "iconUrl": "https://scanner.example.com/icon.svg",
  "dashboardBaseUrl": "https://aws-cspm.example.com/dashboard",
  "credentialSchema": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["accessKeyId", "secretAccessKey"],
    "properties": {
      "accessKeyId":     { "type": "string", "title": "AWS Access Key ID" },
      "secretAccessKey": { "type": "string", "title": "AWS Secret Access Key", "format": "password" }
    }
  }
}
```

Boot resilience: if the manifest fetch fails for any scanner, that env slot's row
is marked `UNAVAILABLE` with `lastError` populated. The CP boots normally; the
tile renders disabled with the error in a tooltip.

## Adding a new scanner (v1)

1. Set `SCANNER_<N>_BASE_URL` and `SCANNER_<N>_SHARED_SECRET` in `.env` (any
   `<N>` — slots are discovered by regex, no fixed range).
2. Restart CP, or hit `POST /admin/scanners/refresh`. Done.

`scanner-env.ts` scans `process.env` for the pattern `SCANNER_(\d+)_BASE_URL`
and pairs each with the matching `_SHARED_SECRET`. No code change is required
to add scanner #5, #6, etc.

## Implementation checklist

- [x] `ScannerSyncService.refreshAll` + `OnModuleInit`
- [x] `ManifestFetcher` (folded into `DynamicScannerClient.fetchManifest`)
- [x] `POST /admin/scanners/refresh`
- [x] `GET /scanners` returns catalog DTOs
- [ ] Unit tests (sync resilience, upsert semantics)
- [ ] Stub-server integration test

## Out of scope

- Per-org scanner enablement / config — v2.
- Runtime plug-in install of new scanners — v2 (still requires a CP env-var addition for v1).
- Fancy JSON-Schema features (conditionals, oneOf trees) — limited to what `@rjsf/core` renders.

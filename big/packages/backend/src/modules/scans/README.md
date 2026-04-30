# scans/

Synchronous scan dispatch. Validates input, calls the scanner directly,
persists the `ScanJob`, returns the job id. **No queue.** Credentials supplied
in the request are forwarded to the scanner once and never persisted.

## Flow diagram coverage

- CA → CP — tile click through to dispatch ack
- (R1–R6) — `GET /scans/:id/report` returns a redirect URL to the scanner dashboard

## Responsibility

1. Validate user-submitted credentials against the scanner's `credentialSchema` (Ajv).
2. Generate a callback nonce.
3. POST `{baseUrl}/api/scan` with HMAC-signed body containing credentials and a
   callback URL pointing back at `scanner-callbacks/`.
4. Persist the `ScanJob` with the scanner-issued `externalScanId`.
5. Return `{ jobId }` to the frontend.

For "View report" (R1–R6): looks up the scan, asks the scanner for a fresh
`viewSecret` via `POST /api/scans/:scanId/view-token`, returns
`{ redirectUrl: "{dashboardBaseUrl}?scanId=...&secret=..." }`. The plaintext
secret is never persisted on CP — only its bcrypt hash from the completion callback.

## Public API

| Method | Path | Role | Description |
|---|---|---|---|
| POST | `/scans/run` | `org_admin` \| `org_member` \| `scanner_operator` | Run scan with `{ scannerKey, credentials }`, returns `{ jobId }` |
| GET | `/scans/:id` | any member | Scan job detail |
| GET | `/scans/:id/report` | any member | `{ redirectUrl }` to scanner dashboard (only for COMPLETED) |
| GET | `/scans` | any member | List scans for current org (filters: `?scannerKey=&status=`) |

## Internal services

- `ScansService.requestRun(...)` — full CA → CP path.
- `ScansService.getById(orgId, jobId)` — strict orgId filter.
- `ScansService.getReportRedirect(orgId, jobId)` — view-token fetch + URL build.
- `ScansService.listForOrg(...)` — filtered listing.

## Dependencies

- `PrismaService`
- `ConfigService` (resolve `SCANNER_N_BASE_URL` + shared secret per env slot)
- `ScannersService` (catalog lookup + credential schema)
- `DynamicScannerClient` (signed HTTP)

## DB tables owned

- `ScanJob` — full lifecycle. Status starts at `DISPATCHED`; transitions to
  `RUNNING`/`COMPLETED`/`FAILED` come from `scanner-callbacks`.

## Rejection paths

| Failure | Status | Audit action |
|---|---|---|
| Scanner unknown | 404 | (default) |
| Scanner UNAVAILABLE | 409 | (default) |
| Credentials fail JSON-Schema validation | 400 | (default) |
| Dispatch HTTP error (timeout / 5xx / 4xx) | 409 | `scan.run.requested` (with error captured on ScanJob) |

## Implementation checklist

- [x] `ScansService.requestRun` synchronous dispatch
- [x] `ScansService.getById` with org filter
- [x] `ScansService.listForOrg`
- [x] `ScansService.getReportRedirect`
- [ ] Stub-server integration test for happy path + failure modes

## Out of scope (v2 territory)

- Retry / backoff on dispatch — direct call only.
- Cancel running scans.
- Persisting credentials for re-use — by design, never stored.
- Per-org entitlement / quota / concurrency checks — wire when entitlements module is real.

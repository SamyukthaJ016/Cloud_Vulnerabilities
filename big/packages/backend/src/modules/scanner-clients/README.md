# scanner-clients/

One generic HTTP client (`DynamicScannerClient`) that talks to any scanner
implementing the manifest contract. The per-scanner subclasses from v0 are gone —
all scanners speak the same shape now (manifest + `/api/scan` + view-token), so
the differences are config-only (base URL + shared secret).

## Flow diagram coverage

- B2 — `GET /api/manifest` at boot
- CJ → CL — signed `POST /api/scan` during dispatch
- R3–R4 — signed `POST /api/scans/:scanId/view-token` on view-report click

## Responsibility

- HMAC-sign every outbound request (body + nonce, SHA-256, hex).
- Time-bounded HTTP calls (5s for manifest, 10s for scan dispatch and view-token).
- **Stateless.** No DB, no config. Caller supplies `(baseUrl, sharedSecret)` per call.

## Methods

```ts
class DynamicScannerClient {
  fetchManifest(baseUrl: string): Promise<ScannerManifest>
  run(baseUrl: string, sharedSecret: string, req: ScannerRunRequest): Promise<ScannerRunAck>
  fetchViewToken(baseUrl: string, sharedSecret: string, externalScanId: string)
    : Promise<ScannerViewTokenResponse>
}
```

## Outbound contract (signed)

Headers on every authenticated request:
```
X-Scanner-Nonce:     <random hex>
X-Scanner-Signature: hex(HMAC-SHA256(rawBody + '.' + nonce, sharedSecret))
Content-Type:        application/json
```

`POST /api/scan` body:
```json
{
  "jobId": "uuid (CP-issued)",
  "orgId": "uuid",
  "callbackUrl": "https://cp.example.com/scanner-callbacks/<scannerKey>/<jobId>",
  "nonce": "<hex>",
  "credentials": { /* whatever credentialSchema asked for */ }
}
```

Expected ack (any 2xx):
```json
{ "scanId": "scanner-side-id", "status": "accepted" }
```

`POST /api/scans/:scanId/view-token` returns `{ "viewSecret": "..." }`.

## Dependencies

- `@nestjs/axios` (`HttpModule`)

## Depended on by

- `scanners/` — manifest fetch
- `scans/` — dispatch + view-token

## Out of scope

- Result payload parsing — scanners own their own dashboards in v1; CP doesn't render findings.
- Polling / streaming — fire-and-callback only.
- mTLS — HMAC shared secret only.

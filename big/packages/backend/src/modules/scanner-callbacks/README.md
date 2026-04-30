# scanner-callbacks/

Inbound endpoint that external scanners POST results to. HMAC-verified;
stores `viewSecretHash` + `summary` + status transition. Idempotent.

Replaces the old `scan-orchestrator/` (which was queue-based and stubbed).

## Flow diagram coverage

- GT — scanner POSTs callback
- GU–GZ — verify, hash viewSecret, update status, audit

## Public API (inbound only)

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/scanner-callbacks/:scannerKey/:jobId` | HMAC (per-scanner shared secret) | Scanner posts result |

> The route is mounted **outside** the global `/api` prefix (see `main.ts`).

## Callback contract

Headers:
```
X-Scanner-Nonce:     <echoes the nonce from dispatch (must match ScanJob.callbackNonce)>
X-Scanner-Signature: hex(HMAC-SHA256(rawBody + '.' + nonce, sharedSecret))
```

Body:
```json
{
  "status": "running" | "completed" | "failed",
  "viewSecret": "opaque string (only on completed)",
  "summary": { "critical": 3, "high": 7, "medium": 12, "low": 4, "info": 1 },
  "error": "optional string"
}
```

CP stores `bcrypt(viewSecret)` on `ScanJob.viewSecretHash`. The plaintext is
**never persisted** — `scans/` re-fetches it from the scanner on demand via
`POST /api/scans/:scanId/view-token`.

## State machine

```
DISPATCHED → RUNNING → (COMPLETED | FAILED)
DISPATCHED → FAILED      (dispatch error before any callback)
```

A callback for an already-terminal job (`COMPLETED` or `FAILED`) is a no-op
(idempotency).

## Internal services

- `CallbackVerifierService` — HMAC + constant-time compare. Resolves the shared
  secret from `Scanner.baseUrlEnvKey` → config slot.
- `CallbackHandlerService` — DB transition, bcrypt hash, summary write.

## Dependencies

- `PrismaService`
- `ConfigService`
- `bcrypt`

## Out of scope

- Findings ingestion — scanner owns its own dashboard in v1.
- Retries / dead-letter — scanner is responsible for re-posting on transient
  CP failures.
- Cancel propagation.

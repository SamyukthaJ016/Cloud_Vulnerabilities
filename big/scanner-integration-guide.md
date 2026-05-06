# Scanner Integration Guide

A guide for scanner-team developers integrating their scanner with the
**CloudGuard Control Plane (CP)**.

You don't need to know anything about the CP codebase to follow this. By the
end you'll have:

- Four HTTP endpoints in your scanner that speak the CP contract.
- A working end-to-end flow: tile in CP UI → user runs scan → your scanner
  runs → CP shows "completed" → user clicks View Report → lands on your
  dashboard.

---

## 1. Mental model in 60 seconds

The CP is the user's front door. **Your scanner is a backend service the CP
talks to over HTTP.** You own:

- The scanning logic itself (whatever your scanner does).
- A small dashboard UI inside your service that renders results for one scan.

The CP owns:

- Auth, multi-tenancy, **billing, plan-based scanner access, roles &
  permissions** — by the time `POST /api/scan` reaches you, the user has
  already been authorized.
- The catalog tile and the credential modal.
- **Storing the credentials the user enters in HashiCorp Vault**, then
  forwarding them on every dispatch.
- Dispatch and the redirect to your dashboard.

From the scanner's perspective the wire format is unchanged from v1: you
still receive `credentials` inline on every `POST /api/scan` request. The
only thing that's different is *where the CP got them from* — first scan =
fresh from the modal; later scans for the same scanner+org = pulled from
Vault. You don't need to know which.

```
   ┌────────────┐    1. GET /api/manifest    ┌────────────┐
   │            │ ──────────────────────────▶ │            │
   │            │ ◀─────────────────────────  │            │
   │            │                             │            │
   │            │    2. POST /api/scan        │            │
   │     CP     │ ──────────────────────────▶ │  scanner   │
   │            │ ◀── 202 { scanId }          │            │
   │            │                             │            │
   │            │    3. POST /scanner-        │            │
   │            │       callbacks/.../jobId   │            │
   │            │ ◀──────────────────────────  │            │
   │            │                             │            │
   │            │    4. POST /api/scans/      │            │
   │            │       :scanId/view-token    │            │
   │            │ ──────────────────────────▶ │            │
   │            │ ◀── { viewSecret }          │            │
   └────────────┘                             └────────────┘
        │                                          ▲
        │   5. user redirected to scanner          │
        │      /dashboard?scanId=...&secret=...    │
        └──────────────────────────────────────────┘
```

---

## 2. What you'll build

Four endpoints in your service plus one HTML page:

| # | Method | Path | Who calls it | When |
|---|---|---|---|---|
| 1 | `GET`  | `/api/manifest` | CP | At CP boot + admin refresh button |
| 2 | `POST` | `/api/scan` | CP | When a user clicks "Run scan" in the UI |
| 3 | `POST` | `/scanner-callbacks/<scannerKey>/<jobId>` | **You call CP** | When your scan finishes |
| 4 | `POST` | `/api/scans/<scanId>/view-token` | CP | When the user clicks "View report" |
| 5 | `GET`  | `/dashboard?scanId=...&secret=...` | User's browser | After "View report" redirect |

---

## 3. The HMAC contract (read this once)

Every signed request — outbound or inbound — uses the **same scheme** so you
only have to implement it once.

You and the CP share a secret string per scanner: the value of
`SCANNER_<N>_SHARED_SECRET` on the CP side. Use a long random string. Treat
it like an API key — never log it, never commit it.

### Signing an outgoing request

1. Take the **raw JSON body bytes** you're about to send (call this `rawBody`).
2. Generate a fresh random nonce — at least 16 hex chars / 32 bytes is fine.
3. Compute:
   ```
   signature = HEX( HMAC-SHA256( sharedSecret, rawBody + b'.' + nonce ) )
   ```
   Note: there is a literal `.` byte between the body and the nonce.
4. Send these two headers along with `Content-Type: application/json`:
   ```
   X-Scanner-Nonce:     <the nonce you generated>
   X-Scanner-Signature: <the hex signature>
   ```

### Verifying an incoming request

Same algorithm in reverse. Compute the expected signature using the raw
request body bytes and the nonce header, then compare against
`X-Scanner-Signature` using a **constant-time** compare (e.g.
`hmac.compare_digest`, `crypto.timingSafeEqual`). If anything mismatches,
return **401**.

### Reference snippet (Python)

```python
import hmac, hashlib

def sign(raw_body: bytes, nonce: str, shared_secret: str) -> str:
    data = raw_body + b"." + nonce.encode("utf-8")
    return hmac.new(shared_secret.encode(), data, hashlib.sha256).hexdigest()

def verify(raw_body: bytes, nonce: str, signature: str, shared_secret: str) -> bool:
    expected = sign(raw_body, nonce, shared_secret)
    return hmac.compare_digest(expected, signature)
```

> **Important:** sign over the **exact bytes** you're sending on the wire.
> If your HTTP library re-serializes the body (changes whitespace, key
> order), the signature won't match. Serialize once into a `bytes`, sign that,
> send that. Same on the verify side: get the **raw** request body before
> any JSON parsing.

---

## 4. Endpoint specs

### 4.1 `GET /api/manifest` — self-description

The CP fetches this at boot and on admin refresh. It defines your scanner's
identity, what credentials the modal should ask for, and where your dashboard
lives.

**No auth.** Just respond with JSON.

**Response 200:**
```json
{
  "key": "aws_cspm",
  "name": "AWS CSPM",
  "description": "AWS misconfiguration scanner",
  "version": "1.2.0",
  "category": "cloud",
  "iconUrl": "https://your-scanner.example.com/icon.svg",
  "dashboardBaseUrl": "https://your-scanner.example.com/dashboard",
  "credentialSchema": {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "type": "object",
    "required": ["accessKeyId", "secretAccessKey"],
    "properties": {
      "accessKeyId": {
        "type": "string",
        "title": "AWS Access Key ID"
      },
      "secretAccessKey": {
        "type": "string",
        "title": "AWS Secret Access Key",
        "format": "password"
      },
      "region": {
        "type": "string",
        "title": "Region",
        "default": "us-east-1"
      }
    }
  }
}
```

**Field rules:**

| Field | Required | Notes |
|---|---|---|
| `key` | yes | Stable, lowercase, snake_case identifier. `^[a-z][a-z0-9_]*$`. **Never change** after release — the CP keys scans on this. |
| `name` | yes | Human-readable; appears on the tile. |
| `description` | no | One-line tile subtitle. |
| `version` | yes | Free-form, e.g. semver. Updated value overwrites the catalog row on next refresh. |
| `category` | no | E.g. `cloud`, `code`, `network`, `container`. Shown as a tag. |
| `iconUrl` | no | Public URL to a small image (svg/png). Falls back to a blank tile if missing. |
| `dashboardBaseUrl` | yes | The base URL the CP redirects to for "View report". |
| `credentialSchema` | yes | A JSON Schema draft-07 object. The CP frontend renders this as a form via `@rjsf/core`. Keep it flat for v1. |

**`credentialSchema` tips:**

- Use `"format": "password"` on secret fields to mask them in the UI.
- `"default"` values pre-fill the form.
- `"required": [...]` enforces non-empty fields client-side and server-side
  (CP validates with Ajv before forwarding to you).
- Stick to JSON Schema features `@rjsf/core` supports — primitives, enums,
  `default`, `format`. Avoid conditional schemas / `oneOf` trees in v1.

### 4.2 `POST /api/scan` — start a scan

The CP sends the user's credentials and a callback URL. **HMAC-signed** —
verify the signature, accept the request, return immediately, do the actual
work in the background.

**Auth:** HMAC headers (`X-Scanner-Nonce`, `X-Scanner-Signature`). Verify or
return 401.

**Request body:**
```json
{
  "jobId": "9f3b1d2c-...-...-...",
  "orgId": "1c0a8e44-...-...-...",
  "callbackUrl": "https://cp.example.com/scanner-callbacks/aws_cspm/9f3b1d2c-...",
  "nonce": "a7f3...",
  "credentials": {
    "accessKeyId": "AKIA...",
    "secretAccessKey": "...",
    "region": "us-east-1"
  }
}
```

| Field | Notes |
|---|---|
| `jobId` | The CP-side scan id. **Echo this back as part of the callback URL.** |
| `orgId` | Multi-tenant id. Use it to log/scope/rate-limit per customer. |
| `callbackUrl` | Where to POST your status updates. Pre-built so you don't have to know CP routing. |
| `nonce` | The nonce the CP signed *this* request with. **Reuse it on every callback for this jobId** — the CP checks that callback nonce matches. |
| `credentials` | Whatever your `credentialSchema` asked for. CP retrieves these from Vault on every dispatch (first scan = fresh entry, subsequent scans = stored). Use only for this scan; do not log; do not persist on your side. |

**Response 202:**
```json
{ "scanId": "your-scanner-side-id", "status": "accepted" }
```

| Field | Notes |
|---|---|
| `scanId` | An identifier *you* mint for this scan. The CP stores it; you'll receive it again on the view-token call (4.4) and on dashboard load (4.5). |
| `status` | Always the literal string `"accepted"` for v1. |

**Response 4xx/5xx:**

If you can't accept the scan (auth failed, malformed body, internal error),
return a non-2xx with a JSON body like `{ "error": "reason" }`. The CP marks
the scan FAILED and shows the error to the user.

**Important:** return 202 **immediately**. Don't run the scan inside this
request handler. Spawn a worker / background task / queue job. The CP
expects this call to take well under 10 seconds (it has a 10s client
timeout).

### 4.3 `POST /scanner-callbacks/<scannerKey>/<jobId>` — your status updates

This is the **CP's endpoint, not yours.** You POST to it whenever your scan's
status changes. **HMAC-signed by you** with the shared secret. Reuse the
**same nonce** the CP sent you in 4.2.

You can call it more than once. The CP only processes the first terminal
status (`completed` or `failed`); later callbacks are no-ops.

**URL:** the exact `callbackUrl` field from 4.2 — don't construct your own.

**Headers:**
```
Content-Type:        application/json
X-Scanner-Nonce:     <same nonce from the dispatch>
X-Scanner-Signature: <HMAC-SHA256(rawBody + '.' + nonce, sharedSecret) hex>
```

**Body — running (optional but nice to have):**
```json
{ "status": "running" }
```

Send this once when work actually starts. The CP flips the row to RUNNING
in the UI.

**Body — completed:**
```json
{
  "status": "completed",
  "viewSecret": "long-random-opaque-string",
  "summary": {
    "critical": 3,
    "high": 7,
    "medium": 12,
    "low": 4,
    "info": 1
  }
}
```

| Field | Notes |
|---|---|
| `viewSecret` | A capability token **you mint and own**. The CP stores `bcrypt(viewSecret)` only — it cannot read it back. Keep your own copy (or be ready to issue a fresh one in 4.4). |
| `summary` | Optional severity counts shown on the scan detail page. Any subset of keys is fine. |

**Body — failed:**
```json
{
  "status": "failed",
  "error": "human-readable reason"
}
```

**Expected response:** `200 { "ok": true }`. The CP returns 401 if your
signature is bad, 404 if it doesn't recognize the jobId or scannerKey.

### 4.4 `POST /api/scans/<scanId>/view-token` — issue view secret on demand

When the user clicks "View report" later, the CP calls this to get a fresh
`viewSecret` (because it never stored the plaintext one). Treat each call
as a request for a short-lived view capability.

**Auth:** HMAC headers. The body is small:
```json
{ "scanId": "your-scanner-side-id" }
```

**Response 200:**
```json
{ "viewSecret": "another-or-same-opaque-string" }
```

You may return the same secret every time, or rotate. The dashboard (4.5)
just needs to accept whatever you return here.

### 4.5 `GET /dashboard?scanId=...&secret=...` — your report page

A standard HTML page. The CP redirects the browser here after a successful
4.4. **You** validate the `secret` against what you issued for `scanId`;
return 401 if it doesn't match.

```
GET /dashboard?scanId=stub-scan-fixed-001&secret=stub-view-secret-abc123
```

What you render is up to you — findings, charts, downloads. CP doesn't
care.

---

## 5. End-to-end flow

```
[CP boot]
  CP → GET  /api/manifest                       (you respond 200 with manifest)
  CP stores your row in its catalog with availability=AVAILABLE.

[user clicks tile in CP UI]
  CP renders the credentialSchema as a form.

[user submits the form]
  CP → POST /api/scan         (signed, body has jobId+credentials)
  You ↩ 202 { scanId }
  Your background worker starts the scan.

[scan begins]
  You → POST callbackUrl      (signed, body { status: "running" })
  CP ↩ 200

[scan finishes]
  You → POST callbackUrl      (signed, body { status: "completed", viewSecret, summary })
  CP ↩ 200
  CP marks the row COMPLETED, stores bcrypt(viewSecret), shows "View report" button.

[user clicks View report]
  CP → POST /api/scans/<scanId>/view-token      (signed, body { scanId })
  You ↩ 200 { viewSecret }
  CP responds to user's browser with a redirect URL:
    https://your-host/dashboard?scanId=...&secret=<viewSecret>

[user lands on your dashboard]
  Your /dashboard validates the secret and renders the report.
```

---

## 6. Reference implementation

The repo includes a **stub scanner** (Flask, ~150 lines) in `stub-scanner/`
that implements all five touchpoints end-to-end. Read it as a worked example.

```bash
cd stub-scanner
pip install -r requirements.txt
SHARED_SECRET=dev-secret python server.py
```

It handles:
- The manifest with a JSON Schema for credentials.
- HMAC sign + verify.
- A background thread that posts the `running` then `completed` callback.
- A trivial `/dashboard` page with secret check.

If your language is different (Go, Node, Java, Rust), the stub is still
the easiest spec to crib from — the wire format is identical.

---

## 7. Local testing checklist

Before requesting CP-side wiring:

1. **Manifest reachable.** `curl https://your-scanner/api/manifest` returns
   valid JSON matching the field rules in §4.1.
2. **Sign + verify roundtrip.** Implement the HMAC functions and test
   against the snippet in §3 with a known secret + body + nonce. Both sides
   must produce the same hex string.
3. **Dispatch + ack.** Hit `POST /api/scan` with a fake CP-shaped body and
   a valid signature. Confirm you respond 202 with a `scanId`.
4. **Callback works.** Stand up a tiny local "fake CP" endpoint (or use
   `webhook.site`) and have your scanner POST to it. Verify the nonce echoes
   and the signature you compute matches what the recipient computes.
5. **Dashboard rejects bad secret.** `GET /dashboard?scanId=x&secret=wrong`
   returns 401.

When all five pass, hand the CP team:
- Your `https://...` host base URL (we'll set it as `SCANNER_<N>_BASE_URL`).
- A long random string for the shared secret (we'll set it as
  `SCANNER_<N>_SHARED_SECRET`).
- A short note on what your scanner does (for the description).

We restart the CP and your tile appears in the catalog automatically. No CP
code change needed.

---

## 8. Troubleshooting

| Symptom | Likely cause |
|---|---|
| CP shows your scanner as `UNAVAILABLE` with `lastError` ≈ network error | Manifest URL is wrong or your service was down at CP boot. Fix and ask the CP team to hit the admin refresh endpoint. |
| Manifest sync logs `Manifest fetch failed: timeout` | Your service took >5s to respond to `/api/manifest`. Make sure that handler is fast (no DB calls if possible). |
| Modal opens with no fields, or strange-looking fields | `credentialSchema` is missing/malformed or uses unsupported features. Run it through any JSON Schema validator first. |
| `POST /api/scan` returns 4xx but you're sure your code is fine | The CP validates user-entered creds against your `credentialSchema` *before* calling you. A 4xx **from the CP** never reaches your service — but if you see a non-2xx in **your** logs, it's your handler. |
| CP returns 401 to your callback | Signature mismatch. Most common causes:<br>• You're signing parsed-then-reserialized JSON instead of the raw bytes you send.<br>• Wrong shared secret.<br>• Wrong nonce (must be the one the CP sent in dispatch). |
| CP returns 404 to your callback | URL has the wrong `scannerKey` or `jobId`. Use the exact `callbackUrl` from the dispatch body — don't reconstruct it. |
| "View report" 500s on the CP side | Your `/api/scans/:scanId/view-token` errored or returned a non-JSON body. Check your logs. |
| Dashboard loads with a wrong-looking secret | The CP passes through whatever you returned in 4.4. Make sure the dashboard checks against the value you most recently issued for that `scanId`. |

---

## 9. Common gotchas

- **Don't change `key` after release.** The CP catalog rows and existing
  scan jobs are keyed on it. If you really need a new identifier, ship it as
  a new scanner and deprecate the old one.
- **Don't log credentials, and don't persist them.** They're sent on every
  dispatch (CP pulls from Vault and includes them inline), but the source of
  truth is Vault on the CP side. Holding your own copy duplicates secrets
  that the user expects to be rotatable centrally. Strip credentials from
  debug logs, error reports, and APM traces.
- **Don't reuse one nonce across different scans.** Each dispatch comes with
  its own nonce; reuse only within callbacks for the *same* `jobId`.
- **Background work, not request-handler work.** If your `POST /api/scan`
  handler does the scan synchronously and takes 30s, the CP will time out
  and mark the job FAILED before you even start the callback.
- **Idempotent callbacks.** If you re-deliver a `completed` callback (because
  of a retry on your side), the CP ignores it — you won't double-update.
  Don't rely on it triggering a re-render.
- **Public dashboard URL.** `dashboardBaseUrl` must be reachable from the
  user's browser, not just from the CP. If you're behind a VPN, end users
  see a broken redirect.

---

## 10. Handled by the CP (don't build on your side)

The CP owns these end-to-end — you can assume they're already enforced by
the time a request reaches your service:

- **Auth, multi-tenancy, RBAC** — only authenticated, role-permitted users
  can trigger scans.
- **Billing & plan-based access** — if a user's plan doesn't include your
  scanner, `POST /api/scan` will simply not be called.
- **Credential storage in Vault** — CP captures credentials in the modal,
  writes them to Vault, and includes them inline on every dispatch. You
  don't have a "save my key for next time" UI to build.

## 11. Out of scope (for now)

These are intentionally **not** part of the contract — don't build them yet:

- Scan cancellation propagation from CP to your service.
- Scheduled / periodic scans (CP triggers each run today).
- Findings ingestion into the CP (you keep findings in your own dashboard).
- mTLS or token-based auth (HMAC shared secret only).

Anything not listed in §4 is yours to design however you want — the CP
doesn't peek inside.

---

## 12. Questions

Ping the CP team with:
- A reproducible request/response transcript (curl or HAR).
- The CP-side log line if you have it.
- Your scanner's `key` and the `jobId` involved.

Most issues are signature mismatches; (3) and (8) catch ~90% of them.

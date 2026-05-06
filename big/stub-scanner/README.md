# stub-scanner — Reference Implementation

A small, fully-working scanner service that implements the **CloudGuard
Control Plane (CP) integration contract** end-to-end. Use it for two things:

1. **As a worked example** while integrating your real scanner. Read
   [server.py](server.py) top-to-bottom — it's organized in the same order
   as the CP ↔ scanner exchange and every section has comments explaining
   why each piece exists and what to change for a real scanner.
2. **As a smoke test** for the CP itself — point CP at this stub, watch a
   full scan round-trip happen with no real cloud target involved.

Read this alongside the integration guide:
> [docs/scanner-integration-guide.md](../docs/scanner-integration-guide.md)

---

## What it implements

| Endpoint | Direction | What it does |
|---|---|---|
| `GET /api/manifest` | CP → stub | Returns name, JSON-Schema for credentials, dashboard URL |
| `POST /api/scan` | CP → stub | Verifies HMAC, returns scanId in 202, kicks off background work |
| `POST <callbackUrl>` | stub → CP | Signs + POSTs `running` then `completed` callbacks |
| `POST /api/scans/<scanId>/view-token` | CP → stub | Verifies HMAC, returns the view secret |
| `GET /dashboard?scanId=&secret=` | browser → stub | Validates secret, renders the report HTML |

The stub does no real work — it sleeps `SCAN_DELAY` seconds and reports
fixed findings. View secret and scan id are constants so you can predict the
round-trip exactly.

---

## Run

```bash
cd stub-scanner
pip install -r requirements.txt
SHARED_SECRET=dev-secret python server.py
```

Listens on `:4001` by default.

### Environment variables

| Var | Default | Purpose |
|---|---|---|
| `SHARED_SECRET` | `dev-secret-change-me` | HMAC key — must equal `SCANNER_<N>_SHARED_SECRET` on the CP |
| `SCANNER_KEY` | `stub_scanner` | Stable identifier; goes into `Scanner.key` row in CP |
| `PORT` | `4001` | Listen port |
| `SCAN_DELAY` | `7` | Seconds the fake scan sleeps before posting `completed` |
| `PUBLIC_BASE_URL` | `http://localhost:4001` | Base for `dashboardBaseUrl` in the manifest |

---

## Wire it to the CP

In `packages/backend/.env`, pick any free slot number `<N>`:

```
SCANNER_1_BASE_URL=http://localhost:4001
SCANNER_1_SHARED_SECRET=dev-secret
SCANNER_CALLBACK_BASE_URL=http://localhost:3000
```

Restart the CP. On boot you should see:

```
[ScannerSyncService] Synced manifest for stub_scanner (SCANNER_1_BASE_URL)
```

A row appears in the `Scanner` table with `availability = AVAILABLE` and
the tile shows up in the `/scanners` UI.

---

## End-to-end test

1. Start the stub: `python server.py`.
2. Start the CP backend + frontend.
3. Log in, open `/scanners`. The "Stub Scanner" tile appears.
4. Click it → modal renders username / password / target inputs from the manifest.
5. Submit. The stub prints `received scan request job=…`, then ~7s later
   `callback completed → HTTP 200`.
6. Open `/scans` → the row shows status `completed` with a "View report" button.
7. Click "View report" → redirected to
   `http://localhost:4001/dashboard?scanId=stub-scan-fixed-001&secret=…`
   showing the placeholder report page.

If something breaks, the stub logs each callback attempt with the HTTP
response — `401` means CP rejected the signature (check `SHARED_SECRET`
matches on both sides).

---

## How to use this as a template for your own scanner

The file is organized into 8 sections marked with `# ====` banners. Roughly:

| Section | What it is | What you change |
|---|---|---|
| 1. Configuration | Env-var-driven settings | Set your `SHARED_SECRET`, `SCANNER_KEY`, `PUBLIC_BASE_URL` |
| 2. HMAC sign/verify | The wire contract | **Copy verbatim** (or port to your language) |
| 3. `GET /api/manifest` | Self-description | Edit the manifest dict — your name, schema, dashboard URL |
| 4. `POST /api/scan` | Accept-and-ack handler | Leave structure alone; your real work goes in section 5 |
| 5. `_run_scan_async` | Background worker | **Replace with your real scan logic** |
| 6. `POST .../view-token` | Issue view secret on demand | Wire to your own scan-id → secret mapping |
| 7. `GET /dashboard` | HTML report page | Replace with your real findings UI |
| 8. Boot | Server startup | Run behind a real WSGI server in prod |

The contract (sections 2, 4, 6) is fixed — those wire formats and
signatures are how the CP recognizes you. Everything else (manifest
content, what your scan does, how your dashboard looks) is yours.

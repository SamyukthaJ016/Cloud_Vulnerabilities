"""
================================================================================
  CloudGuard Scanner — Reference Implementation (Python / Flask)
================================================================================

This file is BOTH:
  (a) a working stub scanner used to test the CloudGuard Control Plane (CP)
      end-to-end without needing a real scanner service, AND
  (b) a worked example for scanner-team developers integrating their own
      scanner with the CP.

Read this file top-to-bottom — it is laid out in the order the CP and your
scanner exchange messages. Every section starts with a `=========` banner
explaining what it does and what you'd change for a real scanner.

Read the integration guide alongside this file:
  → docs/scanner-integration-guide.md

The contract in one diagram:

    1. CP boot           CP  → GET /api/manifest                → you
    2. user clicks tile  CP  → POST /api/scan {creds}           → you
                         you ← 202 {scanId}                     ← CP
    3. work happens      you → POST callbackUrl {running}       → CP
                         you → POST callbackUrl {completed,...} → CP
    4. user clicks View  CP  → POST /api/scans/<id>/view-token  → you
                         you ← 200 {viewSecret}                 ← CP
    5. browser redirect  user → GET /dashboard?scanId&secret    → you (HTML)

What you customize for a real scanner:
  - The MANIFEST block in section 3 — your name, schema, dashboard URL.
  - The `_run_scan_async` function in section 5 — your actual scan logic.
  - The `dashboard` handler in section 7 — your actual report HTML.
  - Everything else (HMAC sign/verify, request/response shapes) is the
    contract — copy it verbatim or port it to your language.

Run:
    pip install -r requirements.txt
    SHARED_SECRET=dev-secret python server.py
"""

import hashlib
import hmac
import json
import os
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from flask import Flask, jsonify, request


# ==============================================================================
# 1. CONFIGURATION
# ==============================================================================
# Everything in this block comes from environment variables so you don't bake
# secrets or URLs into the image. For a real scanner, set these in your
# deployment env (k8s ConfigMap/Secret, Docker env file, etc.).
#
# Pair-up with the CP side:
#   SHARED_SECRET (here)  ↔  SCANNER_<N>_SHARED_SECRET (CP .env)
#   PUBLIC_BASE_URL must be reachable from BOTH the CP and end users' browsers.
# ==============================================================================

# HMAC key. Use a long random string (32+ bytes). Treat it like an API key —
# never log it, never commit it. The CP's SCANNER_<N>_SHARED_SECRET must match.
SHARED_SECRET = os.getenv("SHARED_SECRET", "dev-secret-change-me")

# Stable identifier for this scanner. Lowercase, snake_case. NEVER change after
# release — the CP keys catalog rows and existing scan jobs on this string.
SCANNER_KEY = os.getenv("SCANNER_KEY", "stub_scanner")

# Where this Flask app listens.
PORT = int(os.getenv("PORT", "4001"))

# The URL the CP and end-user browsers reach this service at. Used in:
#   - the manifest's dashboardBaseUrl field (where users get redirected for reports)
# In production this is your scanner's public hostname behind TLS.
PUBLIC_BASE_URL = os.getenv("PUBLIC_BASE_URL", f"http://localhost:{PORT}")

# Stub-only knobs — replace in your real implementation:
SCAN_DELAY = int(os.getenv("SCAN_DELAY", "7"))   # how long the fake "scan" sleeps
FIXED_SCAN_ID = "stub-scan-fixed-001"            # your scan id is whatever you want
FIXED_VIEW_SECRET = "stub-view-secret-abc123"    # your view secret is whatever you want


app = Flask(__name__)


# ==============================================================================
# 2. HMAC SIGN / VERIFY  (the contract — copy as-is to your language)
# ==============================================================================
# Every signed exchange uses the same scheme:
#
#   signature = hex( HMAC-SHA256( shared_secret, raw_body + b"." + nonce ) )
#
# The literal `.` byte is required — the CP signs and verifies the same way.
#
# CRITICAL — sign over the EXACT BYTES you send on the wire. If your HTTP
# library re-serializes the body (changes whitespace, key order), the signature
# won't match. Serialize ONCE into a `bytes`, sign that, send that. Same on the
# verify side: get the RAW request body before any JSON parsing.
#
# Headers used in every signed request:
#   X-Scanner-Nonce:     <fresh random string OR the dispatch nonce, see below>
#   X-Scanner-Signature: <hex signature>
#   Content-Type:        application/json
# ==============================================================================

def sign(raw_body: bytes, nonce: str) -> str:
    """Compute the HMAC-SHA256 hex signature over (raw_body + '.' + nonce)."""
    data = raw_body + b"." + nonce.encode("utf-8")
    return hmac.new(SHARED_SECRET.encode(), data, hashlib.sha256).hexdigest()


def verify_request(raw_body: bytes) -> bool:
    """
    Verify the X-Scanner-* headers on an incoming Flask request.
    Use this on every endpoint the CP calls (`/api/scan` and `/api/scans/<id>/view-token`).

    Returns True if the signature matches, False otherwise. Use a constant-time
    compare via `hmac.compare_digest`.
    """
    nonce = request.headers.get("X-Scanner-Nonce", "")
    signature = request.headers.get("X-Scanner-Signature", "")
    if not nonce or not signature:
        return False
    expected = sign(raw_body, nonce)
    return hmac.compare_digest(expected, signature)


# ==============================================================================
# 3. ENDPOINT — GET /api/manifest        (CP → you, called at CP boot + refresh)
# ==============================================================================
# Self-description. The CP fetches this once at boot per SCANNER_<N>_BASE_URL,
# upserts a row in its `Scanner` table, and renders a tile in the UI.
#
# No auth — but keep it FAST (CP timeout = 5s). No DB calls if you can avoid them.
#
# Field rules (see docs/scanner-integration-guide.md §4.1 for the full table):
#   key                — stable, lowercase, snake_case. NEVER change after release.
#   name               — human-readable; appears on the tile.
#   description        — one-line tile subtitle (optional).
#   version            — free-form, e.g. semver.
#   category           — 'cloud' | 'code' | 'network' | 'container' (optional).
#   iconUrl            — public URL to a small icon (optional).
#   dashboardBaseUrl   — REQUIRED. Where the CP redirects for "View report".
#   credentialSchema   — REQUIRED. JSON Schema draft-07; CP renders it as a form.
#                        Use "format": "password" on secret fields. Keep it FLAT
#                        for v1 — `@rjsf/core` doesn't render conditional schemas.
# ==============================================================================

@app.get("/api/manifest")
def manifest():
    return jsonify(
        {
            "key": SCANNER_KEY,
            "name": "Stub Scanner",
            "description": "Test scanner that sleeps and reports a fake completion.",
            "version": "1.0.0",
            "category": "test",
            "iconUrl": None,
            "dashboardBaseUrl": f"{PUBLIC_BASE_URL}/dashboard",
            "credentialSchema": {
                "$schema": "http://json-schema.org/draft-07/schema#",
                "type": "object",
                "required": ["username"],
                "properties": {
                    "username": {"type": "string", "title": "Username"},
                    "password": {
                        "type": "string",
                        "title": "Password",
                        "format": "password",  # ← masks the input in the modal
                    },
                    "target": {
                        "type": "string",
                        "title": "Target URL",
                        "default": "https://example.com",  # ← pre-fills the field
                    },
                },
            },
        }
    )


# ==============================================================================
# 4. ENDPOINT — POST /api/scan           (CP → you, called when user clicks Run)
# ==============================================================================
# The CP sends the user's credentials and a callbackUrl that points back at the
# CP. You MUST:
#   1. Verify the HMAC signature (or return 401).
#   2. Validate the request shape (or return 400).
#   3. Kick off your scan in the BACKGROUND.
#   4. Return 202 with a scanId IMMEDIATELY — under 10s (CP client timeout).
#
# You do NOT do the scan inside this handler. If you do, the CP will time out
# and mark the job FAILED before your callback can arrive.
#
# Body shape:
#   {
#     "jobId":       "<CP-side scan id; you echo this back via callbackUrl>",
#     "orgId":       "<multi-tenant id; use for logging/scoping/rate-limiting>",
#     "callbackUrl": "<full URL to POST status updates to — use as-is>",
#     "nonce":       "<the nonce CP signed THIS request with — REUSE on every callback>",
#     "credentials": { /* whatever your credentialSchema asked for */ }
#   }
# ==============================================================================

@app.post("/api/scan")
def scan():
    raw_body = request.get_data()  # raw bytes — needed for signature verify

    # 1. Verify signature
    if not verify_request(raw_body):
        return jsonify({"error": "invalid signature"}), 401

    # 2. Validate shape
    body = json.loads(raw_body) if raw_body else {}
    job_id = body.get("jobId")
    callback_url = body.get("callbackUrl")
    nonce = body.get("nonce")
    credentials = body.get("credentials", {})

    if not (job_id and callback_url and nonce):
        return jsonify({"error": "missing jobId/callbackUrl/nonce"}), 400

    print(f"[stub] received scan request job={job_id} → will callback in {SCAN_DELAY}s")

    # 3. Kick off background work — DO NOT block this handler.
    threading.Thread(
        target=_run_scan_async,
        args=(job_id, callback_url, nonce, credentials),
        daemon=True,
    ).start()

    # 4. Return 202 immediately with YOUR scanId (you mint it).
    return jsonify({"scanId": FIXED_SCAN_ID, "status": "accepted"}), 202


# ==============================================================================
# 5. CALLBACK — POST callbackUrl          (you → CP, called from background work)
# ==============================================================================
# This is the CP's endpoint, NOT yours. You POST to the URL the CP gave you in
# the dispatch body. You MUST:
#   - Sign with HMAC using the SAME nonce the CP sent you in the dispatch.
#     (The CP rejects callbacks whose nonce doesn't match.)
#   - Send Content-Type: application/json.
#
# You can call it more than once per jobId. Order matters logically:
#   1. {"status": "running"}                              — when work starts
#   2. {"status": "completed", "viewSecret": ..., ...}    — when work finishes ok
#      OR
#      {"status": "failed",    "error": "..."}            — when work fails
#
# After the CP receives a terminal status (completed | failed) it ignores
# further callbacks for the same jobId — this is intentional idempotency.
# ==============================================================================

def _post_callback(callback_url: str, nonce: str, body_dict: dict) -> None:
    """Sign the body with the SAME nonce the CP sent in dispatch, then POST."""
    raw = json.dumps(body_dict, separators=(",", ":")).encode("utf-8")
    signature = sign(raw, nonce)  # ← reuse dispatch nonce, NOT a fresh one
    req = Request(
        callback_url,
        data=raw,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-Scanner-Nonce": nonce,
            "X-Scanner-Signature": signature,
        },
    )
    try:
        with urlopen(req, timeout=10) as resp:
            print(f"[stub] callback {body_dict.get('status')} → HTTP {resp.status}")
    except HTTPError as e:
        # 401 = signature mismatch (check shared secret + raw-body signing)
        # 404 = wrong scannerKey or jobId in callbackUrl
        print(f"[stub] callback {body_dict.get('status')} failed: HTTP {e.code} — {e.read()!r}")
    except URLError as e:
        # Network-level failure (CP unreachable, DNS, connection refused).
        # In production you'd want a retry queue here.
        print(f"[stub] callback {body_dict.get('status')} failed: {e.reason}")


def _run_scan_async(
    job_id: str,
    callback_url: str,
    nonce: str,
    credentials: dict,
) -> None:
    """
    ============================================================================
    REPLACE THIS FUNCTION with your real scan logic.
    ============================================================================

    Contract:
      1. (optional) Send {"status": "running"} when actual work begins.
      2. Do the work. Use `credentials` to authenticate to whatever target.
         Do NOT log credentials. Do NOT persist them on your side — the CP
         stores them in Vault and forwards on every dispatch.
      3. On success, send {"status": "completed", "viewSecret": ..., "summary": ...}.
         - viewSecret: a capability token YOU mint and own. The CP stores
           bcrypt(viewSecret) only — you'll be asked for a fresh one on every
           "View report" click via /api/scans/<scanId>/view-token.
         - summary: optional severity counts shown on the scan detail page.
      4. On failure, send {"status": "failed", "error": "human-readable reason"}.

    The stub below sleeps `SCAN_DELAY` seconds then reports fake findings.
    """

    # 1. Tell the CP we've started.
    _post_callback(callback_url, nonce, {"status": "running"})

    # 2. ===== YOUR SCAN LOGIC GOES HERE =====
    #    Use `credentials["username"]`, `credentials["password"]`, etc. to
    #    authenticate to the target system, run your checks, collect findings.
    #    Store the findings somewhere YOU control (your own DB) keyed by
    #    `FIXED_SCAN_ID` (or whatever scanId you returned in 202).
    time.sleep(SCAN_DELAY)
    # ========================================

    # 3. Tell the CP we're done.
    _post_callback(
        callback_url,
        nonce,
        {
            "status": "completed",
            "viewSecret": FIXED_VIEW_SECRET,
            "summary": {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5},
        },
    )


# ==============================================================================
# 6. ENDPOINT — POST /api/scans/<scanId>/view-token   (CP → you, on view-report)
# ==============================================================================
# When the user clicks "View report" later (could be days after the scan), the
# CP calls this to get a `viewSecret` it can pass to your dashboard. The CP
# never stored the plaintext from your completion callback — only its bcrypt
# hash — so it has to ask you each time.
#
# You can return the same viewSecret every time, or rotate (in which case your
# dashboard must accept whichever you most recently issued for that scanId).
#
# HMAC-signed by the CP — verify or return 401.
# ==============================================================================

@app.post("/api/scans/<scan_id>/view-token")
def view_token(scan_id):
    raw_body = request.get_data()
    if not verify_request(raw_body):
        return jsonify({"error": "invalid signature"}), 401

    print(f"[stub] view-token requested for scan={scan_id}")
    return jsonify({"viewSecret": FIXED_VIEW_SECRET})


# ==============================================================================
# 7. ENDPOINT — GET /dashboard?scanId=&secret=        (browser → you, HTML page)
# ==============================================================================
# The user lands here after the CP redirects them from "View report". This is
# the only endpoint that serves HTML; everything else is JSON.
#
# Auth: validate `secret` matches what you issued for `scanId` in section 6.
# Return 401 on mismatch.
#
# Render whatever you want — findings table, charts, downloads, etc. The CP
# does not introspect this page.
# ==============================================================================

@app.get("/dashboard")
def dashboard():
    scan_id = request.args.get("scanId", "unknown")
    secret = request.args.get("secret", "")

    if secret != FIXED_VIEW_SECRET:
        return ("<h1>401 Unauthorized</h1><p>bad or missing secret</p>", 401)

    # ===== YOUR REAL DASHBOARD HTML GOES HERE =====
    return f"""<!doctype html>
<html><head><title>Stub scanner report</title></head>
<body style="font-family: system-ui, sans-serif; max-width: 640px; margin: 60px auto; padding: 0 16px;">
  <h1>Report page for scan id: <code>{scan_id}</code></h1>
  <p>This is the stub scanner's dashboard. The CP redirect worked — you arrived here with
     a valid view secret.</p>
  <p style="color: #666;">In a real scanner this page would render findings, evidence, etc.</p>
</body></html>"""


# ==============================================================================
# 8. BOOT
# ==============================================================================
# `threaded=True` lets Flask's dev server handle the background callback POST
# while the request handler is still returning. In production you'd run this
# behind a real WSGI server (gunicorn, uvicorn) — same code, no changes.
# ==============================================================================

if __name__ == "__main__":
    print(f"[stub] starting on :{PORT} (key={SCANNER_KEY}, delay={SCAN_DELAY}s)")
    app.run(host="0.0.0.0", port=PORT, threaded=True)

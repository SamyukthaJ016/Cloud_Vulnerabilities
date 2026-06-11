#!/usr/bin/env python3
"""
Poll the CloudGuard scan queue through the worker API.

Run locally:
  CLOUDGUARD_BASE_URL=http://localhost:8000 python backend/scripts/scan_job_worker.py

Run one job and exit:
  python backend/scripts/scan_job_worker.py --once
"""

import json
import os
import sys
import time
import urllib.error
import urllib.request


BASE_URL = os.getenv("CLOUDGUARD_BASE_URL", "http://localhost:8000").rstrip("/")
WORKER_TOKEN = os.getenv("WORKER_TOKEN")
POLL_INTERVAL_SECONDS = int(os.getenv("SCAN_WORKER_POLL_INTERVAL", "10"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("SCAN_WORKER_REQUEST_TIMEOUT", "900"))


def run_once() -> dict:
    url = f"{BASE_URL}/api/jobs/worker/run-once"
    headers = {"Content-Type": "application/json"}
    if WORKER_TOKEN:
        headers["x-worker-token"] = WORKER_TOKEN

    request = urllib.request.Request(url, data=b"{}", headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    once = "--once" in sys.argv
    print(f"CloudGuard scan worker connected to {BASE_URL}")

    while True:
        try:
            result = run_once()
            print(json.dumps(result, default=str))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            print(f"Worker request failed: HTTP {exc.code} {body}", file=sys.stderr)
            if once:
                return 1
        except Exception as exc:
            print(f"Worker error: {exc}", file=sys.stderr)
            if once:
                return 1

        if once:
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())

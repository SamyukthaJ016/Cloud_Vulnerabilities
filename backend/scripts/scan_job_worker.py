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
import threading
import time
import urllib.error
import urllib.request


BASE_URL = os.getenv("CLOUDGUARD_BASE_URL", "http://localhost:8000").rstrip("/")
WORKER_TOKEN = os.getenv("WORKER_TOKEN")
WORKER_ID = os.getenv("SCAN_WORKER_ID", "api-scan-worker")
POLL_INTERVAL_SECONDS = int(os.getenv("SCAN_WORKER_POLL_INTERVAL", "10"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "15"))
REQUEST_TIMEOUT_SECONDS = int(os.getenv("SCAN_WORKER_REQUEST_TIMEOUT", "900"))


def worker_headers() -> dict:
    headers = {"Content-Type": "application/json"}
    if WORKER_TOKEN:
        headers["x-worker-token"] = WORKER_TOKEN
    headers["x-worker-id"] = WORKER_ID
    headers["x-worker-type"] = "scan"
    return headers


def post_heartbeat(status: str = "online") -> None:
    payload = {
        "worker_id": WORKER_ID,
        "worker_type": "scan",
        "status": status,
        "metadata": {
            "mode": "api",
            "base_url": BASE_URL,
            "poll_interval_seconds": POLL_INTERVAL_SECONDS,
        },
    }
    try:
        request = urllib.request.Request(
            f"{BASE_URL}/api/workers/heartbeat",
            data=json.dumps(payload).encode("utf-8"),
            headers=worker_headers(),
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    except Exception as exc:
        print(f"Worker heartbeat failed: {exc}", file=sys.stderr)


def start_heartbeat_thread() -> threading.Event:
    stop_event = threading.Event()

    def loop() -> None:
        while not stop_event.is_set():
            post_heartbeat("online")
            stop_event.wait(HEARTBEAT_INTERVAL_SECONDS)

    thread = threading.Thread(target=loop, name="scan-worker-heartbeat", daemon=True)
    thread.start()
    return stop_event


def run_once() -> dict:
    url = f"{BASE_URL}/api/jobs/worker/run-once"

    request = urllib.request.Request(url, data=b"{}", headers=worker_headers(), method="POST")
    with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> int:
    once = "--once" in sys.argv
    print(f"CloudGuard scan worker {WORKER_ID} connected to {BASE_URL}")
    heartbeat_stop = start_heartbeat_thread()

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
            heartbeat_stop.set()
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())

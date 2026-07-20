#!/usr/bin/env python3
"""
Run CloudGuard scan jobs inside this container.

Unlike scan_job_worker.py, this worker does not call the portal API to execute
the scan. It imports the scanner runtime and processes queued jobs locally
against the shared DATABASE_URL, so CPU-heavy scanner workloads can run on a
separate E2E VM.
"""

import asyncio
import json
import os
import sys
import threading
import time

from backend.main import process_scan_job, record_scanner_worker_heartbeat, requeue_stale_scan_jobs


POLL_INTERVAL_SECONDS = int(os.getenv("SCAN_WORKER_POLL_INTERVAL", "10"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "15"))
WORKER_ID = os.getenv("SCAN_WORKER_ID", "local-scan-worker")


async def run_once() -> dict:
    requeue_stale_scan_jobs()
    return await process_scan_job()


def heartbeat(status: str = "online") -> None:
    try:
        record_scanner_worker_heartbeat(
            WORKER_ID,
            "scan",
            status,
            {
                "mode": "local-db",
                "poll_interval_seconds": POLL_INTERVAL_SECONDS,
            },
        )
    except Exception as exc:
        print(f"Local worker heartbeat failed: {exc}", file=sys.stderr)


def start_heartbeat_thread() -> threading.Event:
    stop_event = threading.Event()

    def loop() -> None:
        while not stop_event.is_set():
            heartbeat("online")
            stop_event.wait(HEARTBEAT_INTERVAL_SECONDS)

    thread = threading.Thread(target=loop, name="local-scan-worker-heartbeat", daemon=True)
    thread.start()
    return stop_event


def main() -> int:
    once = "--once" in sys.argv
    print(f"CloudGuard local scan worker started: {WORKER_ID}")
    heartbeat_stop = start_heartbeat_thread()

    while True:
        try:
            result = asyncio.run(run_once())
            print(json.dumps(result, default=str))
        except Exception as exc:
            print(f"Local worker error: {exc}", file=sys.stderr)
            if once:
                heartbeat_stop.set()
                return 1

        if once:
            heartbeat_stop.set()
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())

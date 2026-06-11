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
import time

from backend.main import process_scan_job, requeue_stale_scan_jobs


POLL_INTERVAL_SECONDS = int(os.getenv("SCAN_WORKER_POLL_INTERVAL", "10"))


async def run_once() -> dict:
    requeue_stale_scan_jobs()
    return await process_scan_job()


def main() -> int:
    once = "--once" in sys.argv
    worker_id = os.getenv("SCAN_WORKER_ID", "local-scan-worker")
    print(f"CloudGuard local scan worker started: {worker_id}")

    while True:
        try:
            result = asyncio.run(run_once())
            print(json.dumps(result, default=str))
        except Exception as exc:
            print(f"Local worker error: {exc}", file=sys.stderr)
            if once:
                return 1

        if once:
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())

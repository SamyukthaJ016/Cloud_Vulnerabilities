#!/usr/bin/env python3
"""
Run CloudGuard sandbox lab orchestration inside this container.

The worker provisions queued temporary labs, records evidence/validation proof,
queues scanner jobs where needed, and destroys lab resources after scan
completion or TTL expiry.
"""

import asyncio
import json
import os
import sys
import threading
import time

from backend.main import process_sandbox_labs_once, record_scanner_worker_heartbeat


POLL_INTERVAL_SECONDS = int(os.getenv("SANDBOX_LAB_WORKER_POLL_INTERVAL", "10"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "15"))
WORKER_ID = os.getenv("SANDBOX_LAB_WORKER_ID", "sandbox-lab-worker")


async def run_once() -> dict:
    return await process_sandbox_labs_once()


def heartbeat(status: str = "online") -> None:
    try:
        record_scanner_worker_heartbeat(
            WORKER_ID,
            "sandbox",
            status,
            {
                "mode": "sandbox-lab",
                "poll_interval_seconds": POLL_INTERVAL_SECONDS,
            },
        )
    except Exception as exc:
        print(f"Sandbox lab worker heartbeat failed: {exc}", file=sys.stderr)


def start_heartbeat_thread() -> threading.Event:
    stop_event = threading.Event()

    def loop() -> None:
        while not stop_event.is_set():
            heartbeat("online")
            stop_event.wait(HEARTBEAT_INTERVAL_SECONDS)

    thread = threading.Thread(target=loop, name="sandbox-lab-worker-heartbeat", daemon=True)
    thread.start()
    return stop_event


def main() -> int:
    once = "--once" in sys.argv
    print(f"CloudGuard sandbox lab worker started: {WORKER_ID}")
    heartbeat_stop = start_heartbeat_thread()

    while True:
        try:
            result = asyncio.run(run_once())
            print(json.dumps(result, default=str))
        except Exception as exc:
            print(f"Sandbox lab worker error: {exc}", file=sys.stderr)
            if once:
                heartbeat_stop.set()
                return 1

        if once:
            heartbeat_stop.set()
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())

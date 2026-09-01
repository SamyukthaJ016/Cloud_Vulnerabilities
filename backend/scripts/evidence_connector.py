#!/usr/bin/env python3
"""
Generic file-based evidence connector.

Drop JSON files into EVIDENCE_CONNECTOR_INBOX. The connector normalizes each
file into the Evidence Ingestion API contract and posts it to /api/evidence.
"""

import json
import os
import shutil
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict


BASE_URL = os.getenv("CLOUDGUARD_BASE_URL", "http://localhost:8000").rstrip("/")
CONNECTOR_TOKEN = os.getenv("EVIDENCE_CONNECTOR_TOKEN")
INBOX_DIR = Path(os.getenv("EVIDENCE_CONNECTOR_INBOX", "/app/connectors/inbox"))
PROCESSED_DIR = Path(os.getenv("EVIDENCE_CONNECTOR_PROCESSED", "/app/connectors/processed"))
FAILED_DIR = Path(os.getenv("EVIDENCE_CONNECTOR_FAILED", "/app/connectors/failed"))
POLL_INTERVAL_SECONDS = int(os.getenv("EVIDENCE_CONNECTOR_POLL_INTERVAL", "10"))
HEARTBEAT_INTERVAL_SECONDS = int(os.getenv("WORKER_HEARTBEAT_INTERVAL", "15"))
DEFAULT_SOURCE_SYSTEM = os.getenv("EVIDENCE_SOURCE_SYSTEM", "file-connector")
DEFAULT_SCANNER_TYPE = os.getenv("EVIDENCE_SCANNER_TYPE", "external")
DEFAULT_ARTIFACT_TYPE = os.getenv("EVIDENCE_ARTIFACT_TYPE", "json")
CONNECTOR_ID = os.getenv("EVIDENCE_CONNECTOR_ID", DEFAULT_SOURCE_SYSTEM)


def ensure_dirs() -> None:
    for directory in (INBOX_DIR, PROCESSED_DIR, FAILED_DIR):
        directory.mkdir(parents=True, exist_ok=True)


def normalize_payload(path: Path, raw: Any) -> Dict[str, Any]:
    if isinstance(raw, dict) and "source_system" in raw and "payload" in raw:
        envelope = dict(raw)
        envelope.setdefault("filename", path.name)
        envelope.setdefault("content_type", "application/json")
        envelope.setdefault("artifact_type", DEFAULT_ARTIFACT_TYPE)
        envelope.setdefault("metadata", {})
        envelope["metadata"].setdefault("connector", "file")
        envelope["metadata"].setdefault("original_filename", path.name)
        return envelope

    return {
        "source_system": DEFAULT_SOURCE_SYSTEM,
        "scanner_type": DEFAULT_SCANNER_TYPE,
        "artifact_type": DEFAULT_ARTIFACT_TYPE,
        "filename": path.name,
        "content_type": "application/json",
        "payload": raw if isinstance(raw, dict) else {"value": raw},
        "metadata": {
            "connector": "file",
            "original_filename": path.name,
        },
    }


def post_evidence(envelope: Dict[str, Any]) -> Dict[str, Any]:
    if not CONNECTOR_TOKEN:
        raise RuntimeError("EVIDENCE_CONNECTOR_TOKEN is required")
    body = json.dumps(envelope, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "X-Connector-ID": CONNECTOR_ID,
        "Authorization": f"Bearer {CONNECTOR_TOKEN}",
    }

    request = urllib.request.Request(
        f"{BASE_URL}/api/evidence",
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


def post_heartbeat(status: str = "online") -> None:
    if not CONNECTOR_TOKEN:
        print("Evidence connector heartbeat skipped: EVIDENCE_CONNECTOR_TOKEN is required", file=sys.stderr)
        return
    payload = {
        "worker_id": CONNECTOR_ID,
        "worker_type": "evidence",
        "status": status,
        "metadata": {
            "mode": "file-connector",
            "inbox": str(INBOX_DIR),
            "poll_interval_seconds": POLL_INTERVAL_SECONDS,
            "source_system": DEFAULT_SOURCE_SYSTEM,
            "scanner_type": DEFAULT_SCANNER_TYPE,
        },
    }
    headers = {
        "Content-Type": "application/json",
        "X-Connector-ID": CONNECTOR_ID,
        "Authorization": f"Bearer {CONNECTOR_TOKEN}",
    }

    try:
        request = urllib.request.Request(
            f"{BASE_URL}/api/workers/heartbeat",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=10) as response:
            response.read()
    except Exception as exc:
        print(f"Evidence connector heartbeat failed: {exc}", file=sys.stderr)


def start_heartbeat_thread() -> threading.Event:
    stop_event = threading.Event()

    def loop() -> None:
        while not stop_event.is_set():
            post_heartbeat("online")
            stop_event.wait(HEARTBEAT_INTERVAL_SECONDS)

    thread = threading.Thread(target=loop, name="evidence-connector-heartbeat", daemon=True)
    thread.start()
    return stop_event


def process_file(path: Path) -> None:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        result = post_evidence(normalize_payload(path, raw))
        shutil.move(str(path), PROCESSED_DIR / path.name)
        print(json.dumps({"file": path.name, "status": "accepted", "result": result}, default=str))
    except Exception as exc:
        try:
            shutil.move(str(path), FAILED_DIR / path.name)
        except FileNotFoundError:
            pass
        if isinstance(exc, urllib.error.HTTPError):
            body = exc.read().decode("utf-8", errors="replace")
            print(f"Evidence connector failed for {path.name}: HTTP {exc.code} {body}", file=sys.stderr)
        else:
            print(f"Evidence connector failed for {path.name}: {exc}", file=sys.stderr)


def run_once() -> None:
    ensure_dirs()
    for path in sorted(INBOX_DIR.glob("*.json")):
        if path.is_file():
            process_file(path)


def main() -> int:
    once = "--once" in sys.argv
    print(f"Evidence connector {CONNECTOR_ID} posting to {BASE_URL}/api/evidence")
    heartbeat_stop = start_heartbeat_thread()
    while True:
        run_once()
        if once:
            heartbeat_stop.set()
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())

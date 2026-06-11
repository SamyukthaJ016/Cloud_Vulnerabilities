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
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Dict


BASE_URL = os.getenv("CLOUDGUARD_BASE_URL", "http://localhost:8000").rstrip("/")
CONNECTOR_TOKEN = os.getenv("CONNECTOR_TOKEN") or os.getenv("EVIDENCE_CONNECTOR_TOKEN")
CONNECTOR_USER_ID = os.getenv("CONNECTOR_USER_ID", "anonymous")
INBOX_DIR = Path(os.getenv("EVIDENCE_CONNECTOR_INBOX", "/app/connectors/inbox"))
PROCESSED_DIR = Path(os.getenv("EVIDENCE_CONNECTOR_PROCESSED", "/app/connectors/processed"))
FAILED_DIR = Path(os.getenv("EVIDENCE_CONNECTOR_FAILED", "/app/connectors/failed"))
POLL_INTERVAL_SECONDS = int(os.getenv("EVIDENCE_CONNECTOR_POLL_INTERVAL", "10"))
DEFAULT_SOURCE_SYSTEM = os.getenv("EVIDENCE_SOURCE_SYSTEM", "file-connector")
DEFAULT_SCANNER_TYPE = os.getenv("EVIDENCE_SCANNER_TYPE", "external")
DEFAULT_ARTIFACT_TYPE = os.getenv("EVIDENCE_ARTIFACT_TYPE", "json")


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
    body = json.dumps(envelope, default=str).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "x-cloudguard-user": CONNECTOR_USER_ID,
    }
    if CONNECTOR_TOKEN:
        headers["x-connector-token"] = CONNECTOR_TOKEN

    request = urllib.request.Request(
        f"{BASE_URL}/api/evidence",
        data=body,
        headers=headers,
        method="POST",
    )
    with urllib.request.urlopen(request, timeout=60) as response:
        return json.loads(response.read().decode("utf-8"))


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
    print(f"Evidence connector posting to {BASE_URL}/api/evidence")
    while True:
        run_once()
        if once:
            return 0
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())

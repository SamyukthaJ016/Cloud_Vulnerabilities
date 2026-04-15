import os
import shutil
import tempfile
import time
import uuid
from pathlib import Path, PurePosixPath
from typing import Any

from fastapi import HTTPException, UploadFile


UPLOAD_ROOT = Path(tempfile.gettempdir()) / "cloudguard_uploads"
UPLOAD_RETENTION_SECONDS = 60 * 60 * 24


def _sanitize_segment(value: str, fallback: str) -> str:
    cleaned = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "-" for ch in (value or ""))
    cleaned = cleaned.strip("-_")
    return cleaned or fallback


def _sanitize_relative_path(raw_path: str, fallback_name: str) -> Path:
    normalized = (raw_path or fallback_name or "uploaded-file").replace("\\", "/").strip()
    normalized = normalized.lstrip("/")
    pure = PurePosixPath(normalized)
    safe_parts = [part for part in pure.parts if part not in {"", "."}]

    if any(part == ".." for part in safe_parts):
        raise HTTPException(status_code=400, detail="Folder upload contains an invalid path")

    if not safe_parts:
        safe_parts = [fallback_name or "uploaded-file"]

    return Path(*safe_parts)


def cleanup_stale_uploads(scan_type: str) -> None:
    base_dir = UPLOAD_ROOT / _sanitize_segment(scan_type, "uploads")
    if not base_dir.exists():
        return

    cutoff = time.time() - UPLOAD_RETENTION_SECONDS
    for child in base_dir.iterdir():
        try:
            if child.stat().st_mtime < cutoff:
                if child.is_dir():
                    shutil.rmtree(child, ignore_errors=True)
                else:
                    child.unlink(missing_ok=True)
        except OSError:
            continue


def _store_uploaded_entries(
    *,
    file_entries: list[tuple[str, str, bytes]],
    user_id: str,
    scan_type: str,
) -> dict[str, Any]:
    cleanup_stale_uploads(scan_type)

    scan_dir = UPLOAD_ROOT / _sanitize_segment(scan_type, "uploads")
    user_dir = scan_dir / _sanitize_segment(user_id, "anonymous")
    upload_dir = user_dir / f"{int(time.time())}-{uuid.uuid4().hex[:8]}"
    upload_dir.mkdir(parents=True, exist_ok=True)

    stored_paths: list[Path] = []

    for filename, relative_path, contents in file_entries:
        destination_rel = _sanitize_relative_path(relative_path, filename or "uploaded-file")
        destination = upload_dir / destination_rel
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(contents)
        stored_paths.append(destination_rel)

    root_candidates = [path.parts[0] for path in stored_paths if path.parts]
    root_name = root_candidates[0] if root_candidates else upload_dir.name
    root_path = upload_dir / root_name if root_candidates and all(part == root_name for part in root_candidates) else upload_dir

    return {
        "stored_path": str(root_path),
        "upload_root": str(upload_dir),
        "root_name": root_name,
        "file_count": len(file_entries),
    }


async def store_uploaded_directory(
    *,
    files: list[UploadFile],
    relative_paths: list[str],
    user_id: str,
    scan_type: str,
) -> dict[str, Any]:
    if not files:
        raise HTTPException(status_code=400, detail="No files were uploaded")

    if relative_paths and len(relative_paths) != len(files):
        raise HTTPException(status_code=400, detail="Uploaded file metadata is inconsistent")

    source_paths = relative_paths or [upload.filename or f"file-{index}" for index, upload in enumerate(files)]
    file_entries: list[tuple[str, str, bytes]] = []

    try:
        for upload, relative_path in zip(files, source_paths):
            contents = await upload.read()
            file_entries.append((upload.filename or "uploaded-file", relative_path, contents))
    finally:
        for upload in files:
            await upload.close()

    return _store_uploaded_entries(
        file_entries=file_entries,
        user_id=user_id,
        scan_type=scan_type,
    )


def store_uploaded_file_payloads(
    *,
    files: list[tuple[str, str, bytes]],
    user_id: str,
    scan_type: str,
) -> dict[str, Any]:
    if not files:
        raise HTTPException(status_code=400, detail="No files were uploaded")

    return _store_uploaded_entries(
        file_entries=files,
        user_id=user_id,
        scan_type=scan_type,
    )

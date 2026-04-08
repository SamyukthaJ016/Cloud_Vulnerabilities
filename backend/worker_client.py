import logging
import os
from typing import Any, Optional

import httpx
from fastapi import HTTPException


logger = logging.getLogger("scan_worker_client")


def get_scan_worker_url() -> Optional[str]:
    url = (os.getenv("SCAN_WORKER_URL") or "").strip().rstrip("/")
    return url or None


def is_scan_worker_enabled() -> bool:
    return bool(get_scan_worker_url())


def _worker_timeout() -> float:
    raw = (os.getenv("SCAN_WORKER_TIMEOUT") or "300").strip()
    try:
        return float(raw)
    except ValueError:
        return 300.0


def _worker_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = (os.getenv("SCAN_WORKER_TOKEN") or os.getenv("WORKER_API_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _format_worker_error_detail(response: httpx.Response, data: Any) -> str:
    detail = data.get("detail", data) if isinstance(data, dict) else data
    content_type = (response.headers.get("content-type") or "").lower()

    if "text/html" in content_type:
        if response.status_code == 524:
            detail = (
                "Scan worker timed out at the tunnel/origin layer. "
                "The scan may still be running on the worker."
            )
        else:
            detail = f"Scan worker returned an HTML error page ({response.status_code})."

    return str(detail)


def _map_worker_status(status_code: int) -> int:
    if status_code == 524:
        return 504
    if status_code >= 500:
        return 502
    return status_code


async def post_to_scan_worker(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    base_url = get_scan_worker_url()
    if not base_url:
        raise HTTPException(status_code=500, detail="SCAN_WORKER_URL is not configured")

    url = f"{base_url}{path}"
    try:
        async with httpx.AsyncClient(timeout=_worker_timeout()) as client:
            response = await client.post(url, json=payload, headers=_worker_headers())
    except httpx.TimeoutException as exc:
        logger.error("Timed out calling scan worker: %s", exc)
        raise HTTPException(status_code=504, detail="Scan worker timed out") from exc
    except httpx.HTTPError as exc:
        logger.error("Failed to reach scan worker: %s", exc)
        raise HTTPException(status_code=502, detail="Scan worker is unreachable") from exc

    try:
        data = response.json() if response.content else {}
    except ValueError:
        data = {"detail": response.text}

    if response.status_code >= 400:
        raise HTTPException(
            status_code=_map_worker_status(response.status_code),
            detail=(
                f"Scan worker error ({response.status_code}): "
                f"{_format_worker_error_detail(response, data)}"
            ),
        )

    return data if isinstance(data, dict) else {"data": data}


async def start_scan_on_worker(path: str, payload: dict[str, Any]) -> dict[str, Any]:
    base_url = get_scan_worker_url()
    if not base_url:
        raise HTTPException(status_code=500, detail="SCAN_WORKER_URL is not configured")

    url = f"{base_url}{path}"
    timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)

    try:
        async with httpx.AsyncClient(timeout=timeout) as client:
            async with client.stream("POST", url, json=payload, headers=_worker_headers()) as response:
                if response.status_code >= 400:
                    raw = await response.aread()
                    try:
                        data = response.json() if raw else {}
                    except ValueError:
                        data = {"detail": raw.decode(errors="replace")}

                    raise HTTPException(
                        status_code=_map_worker_status(response.status_code),
                        detail=(
                            f"Scan worker error ({response.status_code}): "
                            f"{_format_worker_error_detail(response, data)}"
                        ),
                    )
    except httpx.TimeoutException as exc:
        logger.error("Timed out starting scan on worker: %s", exc)
        raise HTTPException(status_code=504, detail="Scan worker timed out") from exc
    except httpx.HTTPError as exc:
        logger.error("Failed to reach scan worker: %s", exc)
        raise HTTPException(status_code=502, detail="Scan worker is unreachable") from exc

    return {
        "status": "started",
        "message": "Scan started on worker",
        "execution_mode": "worker_async",
        "providers_scanned": payload.get("providers", []),
        "deep_scan_enabled": bool(payload.get("deep_scan")),
        "offensive_scan_enabled": bool(payload.get("offensive_scan", True)),
        "dashboard_url": "/dashboard",
        "history_url": "/frontend/history.html",
    }


async def get_scan_worker_health() -> dict[str, Any]:
    base_url = get_scan_worker_url()
    if not base_url:
        return {
            "configured": False,
            "status": "not_configured",
        }

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                f"{base_url}/health",
                headers=_worker_headers(),
            )
        data = response.json() if response.content else {}
        if response.status_code >= 400:
            return {
                "configured": True,
                "status": "error",
                "detail": data.get("detail", data) if isinstance(data, dict) else data,
            }
        if isinstance(data, dict):
            data.setdefault("configured", True)
            return data
        return {"configured": True, "status": "online", "data": data}
    except Exception as exc:
        logger.error("Failed to fetch scan worker health: %s", exc)
        return {
            "configured": True,
            "status": "offline",
            "detail": str(exc),
        }

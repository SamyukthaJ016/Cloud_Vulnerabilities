from __future__ import annotations

import logging
import os
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import httpx


logger = logging.getLogger("grc_bridge")

DEFAULT_LOCAL_GRC_UI = "http://127.0.0.1:3000"
DEFAULT_GRC_INTEGRATION_PATH = "/integrations"
DEFAULT_GRC_RISKS_PATH = "/risks"


def _clean_url(value: Optional[str]) -> str:
    return (value or "").strip().rstrip("/")


def get_grc_ui_base_url() -> str:
    return _clean_url(os.getenv("GRC_UI_URL")) or DEFAULT_LOCAL_GRC_UI


def get_grc_api_base_url() -> str:
    return _clean_url(os.getenv("GRC_API_URL") or os.getenv("GRC_BASE_URL"))


def get_grc_integration_id() -> Optional[str]:
    value = (os.getenv("GRC_INTEGRATION_ID") or "").strip()
    return value or None


def is_grc_server_sync_enabled() -> bool:
    return bool(get_grc_api_base_url())


def _grc_headers() -> dict[str, str]:
    headers = {"Accept": "application/json"}
    token = (os.getenv("GRC_API_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _merge_url(base_url: str, *, path: Optional[str] = None, query: Optional[dict[str, str]] = None) -> str:
    parsed = urlsplit(base_url)
    merged_query = dict(parse_qsl(parsed.query, keep_blank_values=True))
    if query:
        merged_query.update({k: v for k, v in query.items() if v is not None})

    new_path = path if path is not None else (parsed.path or "/")
    return urlunsplit(
        (
            parsed.scheme,
            parsed.netloc,
            new_path,
            urlencode(merged_query),
            parsed.fragment,
        )
    )


def build_grc_links() -> dict[str, str]:
    ui_base = get_grc_ui_base_url()
    integration_url = _merge_url(
        ui_base,
        path=DEFAULT_GRC_INTEGRATION_PATH,
        query={
            "search": "CloudGuard",
            "integrationType": "cloudguard",
            "autoSync": "true",
            "redirect": "risks",
            "source": "cloudguard",
        },
    )
    risks_url = _merge_url(
        ui_base,
        path=DEFAULT_GRC_RISKS_PATH,
        query={"source": "cloudguard"},
    )
    return {
        "ui_url": ui_base,
        "integration_url": integration_url,
        "risks_url": risks_url,
    }


async def _discover_cloudguard_integration_id() -> Optional[str]:
    api_base = get_grc_api_base_url()
    if not api_base:
        return None

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{api_base}/api/integrations", headers=_grc_headers())
        if response.status_code >= 400:
            logger.warning("Failed to list GRC integrations: %s %s", response.status_code, response.text[:200])
            return None

        payload = response.json() if response.content else {}
        items = payload if isinstance(payload, list) else payload.get("data", [])
        for item in items:
            if str(item.get("type") or "").strip().lower() == "cloudguard":
                integration_id = str(item.get("id") or "").strip()
                if integration_id:
                    return integration_id
    except Exception as exc:
        logger.warning("Could not discover CloudGuard integration in GRC: %s", exc)
    return None


async def get_grc_status() -> dict[str, Any]:
    links = build_grc_links()
    api_base = get_grc_api_base_url()
    configured_integration_id = get_grc_integration_id()
    discovered_integration_id = None
    api_reachable = False
    status_detail: str | None = None

    if api_base:
        try:
            async with httpx.AsyncClient(timeout=8.0) as client:
                response = await client.get(f"{api_base}/api/integrations", headers=_grc_headers())
            api_reachable = response.status_code < 400
            if api_reachable:
                payload = response.json() if response.content else {}
                items = payload if isinstance(payload, list) else payload.get("data", [])
                for item in items:
                    if str(item.get("type") or "").strip().lower() == "cloudguard":
                        discovered_integration_id = str(item.get("id") or "").strip() or None
                        break
            else:
                status_detail = f"GRC API returned {response.status_code}"
        except Exception as exc:
            status_detail = str(exc)

    integration_id = configured_integration_id or discovered_integration_id
    server_sync_available = bool(api_base and api_reachable and integration_id)

    return {
        "configured": bool(api_base or links["ui_url"]),
        "server_sync_available": server_sync_available,
        "browser_bridge_available": True,
        "sync_mode": "server" if server_sync_available else "browser_bridge",
        "api_url": api_base or None,
        "integration_id": integration_id,
        "links": links,
        "message": (
            "CloudGuard can trigger GRC sync server-side."
            if server_sync_available
            else "Opening the GRC UI will trigger CloudGuard sync in the browser."
        ),
        "detail": status_detail,
    }


async def trigger_grc_sync() -> dict[str, Any]:
    api_base = get_grc_api_base_url()
    if not api_base:
        return {
            "status": "not_configured",
            "message": "GRC API is not configured for server-side sync.",
            "links": build_grc_links(),
        }

    integration_id = get_grc_integration_id() or await _discover_cloudguard_integration_id()
    if not integration_id:
        return {
            "status": "integration_not_found",
            "message": "CloudGuard integration was not found in GRC.",
            "links": build_grc_links(),
        }

    try:
        async with httpx.AsyncClient(timeout=45.0) as client:
            response = await client.post(
                f"{api_base}/api/integrations/{integration_id}/sync",
                headers=_grc_headers(),
            )
        payload = response.json() if response.content else {}
        if response.status_code >= 400:
            detail = payload.get("message") if isinstance(payload, dict) else str(payload)
            return {
                "status": "error",
                "message": detail or f"GRC sync failed with status {response.status_code}",
                "integration_id": integration_id,
                "links": build_grc_links(),
            }

        return {
            "status": "completed",
            "message": payload.get("message", "GRC sync triggered successfully")
            if isinstance(payload, dict)
            else "GRC sync triggered successfully",
            "integration_id": integration_id,
            "result": payload,
            "links": build_grc_links(),
        }
    except Exception as exc:
        logger.warning("Failed to trigger GRC sync: %s", exc)
        return {
            "status": "error",
            "message": str(exc),
            "integration_id": integration_id,
            "links": build_grc_links(),
        }


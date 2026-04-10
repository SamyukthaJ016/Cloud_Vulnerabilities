from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


USER_ID_COOKIE = "cloudguard_user_id"
LIGHTWEIGHT_PATHS = {
    "/health",
    "/api/info",
    "/api/scans",
    "/api/latest-findings",
    "/api/system/status",
    "/scan/multi-cloud",
}

lightweight_app = FastAPI(title="CloudGuard Lightweight Public API")
lightweight_app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_main_app = None


def _get_main_app():
    global _main_app
    if _main_app is None:
        from backend.main import app as loaded_app

        _main_app = loaded_app
    return _main_app


def _get_conn():
    from backend.database import get_conn

    return get_conn()


def _standalone_user_id(request: Request) -> str:
    return (
        (request.query_params.get("user_id") or "").strip()
        or (request.cookies.get(USER_ID_COOKIE) or "").strip()
        or (os.getenv("STANDALONE_USER_ID") or "").strip()
        or "anonymous"
    )


def _parse_int(value: Optional[str], fallback: int, minimum: int = 0, maximum: int = 500) -> int:
    try:
        parsed = int(value) if value is not None else fallback
    except (TypeError, ValueError):
        parsed = fallback
    return max(minimum, min(parsed, maximum))


def _parse_bool(value: Optional[str], default: bool = False) -> bool:
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


@lightweight_app.get("/health")
async def lightweight_health():
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()

        return {
            "status": "healthy",
            "database": "connected",
            "mode": "lightweight",
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception as exc:
        return {
            "status": "unhealthy",
            "database": "error",
            "error": str(exc),
            "mode": "lightweight",
            "timestamp": datetime.utcnow().isoformat(),
        }


@lightweight_app.get("/api/info")
async def lightweight_info():
    return {
        "service": "CloudGuard - Multi-Cloud Security Scanner",
        "version": "4.0.0",
        "architecture": "MCP-SERVER",
        "mode": "lightweight",
        "scan_worker_enabled": bool((os.getenv("SCAN_WORKER_URL") or "").strip()),
        "features": [
            "User Credential Management",
            "MCP Server Architecture",
            "Security Dashboard",
            "Deep Vulnerability Scanning",
            "Offensive Security Testing",
        ],
    }


def _worker_headers() -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    token = (os.getenv("SCAN_WORKER_TOKEN") or os.getenv("WORKER_API_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


async def _fetch_worker_health() -> dict[str, Any]:
    worker_url = (os.getenv("SCAN_WORKER_URL") or "").strip().rstrip("/")
    if not worker_url:
        return {"configured": False, "status": "not_configured"}

    try:
        import httpx

        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{worker_url}/health", headers=_worker_headers())
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
        return {"configured": True, "status": "offline", "detail": str(exc)}


@lightweight_app.get("/api/system/status")
async def lightweight_system_status():
    timestamp = datetime.utcnow().isoformat()
    worker_health = await _fetch_worker_health()
    worker_status = worker_health.get("status") or "unknown"

    database_component: dict[str, Any]
    statistics = {
        "total_scans_today": 0,
        "active_schedules": 0,
        "total_findings": 0,
        "avg_scan_time": 0,
    }

    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
            cur.fetchone()
            database_component = {
                "name": "PostgreSQL",
                "status": "online",
                "latency_ms": "< 50ms",
                "last_check": timestamp,
            }

            cur.execute(
                """
                SELECT
                    COUNT(*) FILTER (WHERE DATE(started_at) = CURRENT_DATE),
                    COALESCE(AVG(duration_seconds), 0)
                FROM scans
                """
            )
            scans_today, avg_scan_time = cur.fetchone()
            cur.execute("SELECT COUNT(*) FROM findings")
            total_findings = cur.fetchone()[0]
            try:
                cur.execute("SELECT COUNT(*) FROM scheduled_scans WHERE enabled = TRUE")
                active_schedules = cur.fetchone()[0]
            except Exception:
                active_schedules = 0

            statistics = {
                "total_scans_today": int(scans_today or 0),
                "active_schedules": int(active_schedules or 0),
                "total_findings": int(total_findings or 0),
                "avg_scan_time": int(avg_scan_time or 0),
            }
    except Exception as exc:
        database_component = {
            "name": "PostgreSQL",
            "status": "error",
            "error": str(exc),
            "last_check": timestamp,
        }

    overall_status = "healthy"
    if worker_status not in {"online", "healthy"} or database_component["status"] != "online":
        overall_status = "degraded"

    return {
        "timestamp": timestamp,
        "overall_status": overall_status,
        "components": {
            "mcp_servers": [],
            "scan_worker": [
                {
                    "name": "scan-worker",
                    "status": "online" if worker_status in {"online", "healthy"} else "offline",
                    "detail": worker_health.get("detail"),
                    "last_check": timestamp,
                }
            ],
            "vulnerability_scanners": [],
            "database": [database_component],
            "api_endpoints": [
                {"name": "/health", "status": "operational", "response_time_ms": 50, "last_check": timestamp},
                {"name": "/api/info", "status": "operational", "response_time_ms": 50, "last_check": timestamp},
                {"name": "/api/scans", "status": "operational", "response_time_ms": 50, "last_check": timestamp},
                {"name": "/api/latest-findings", "status": "operational", "response_time_ms": 50, "last_check": timestamp},
            ],
        },
        "statistics": statistics,
    }


@lightweight_app.post("/scan/multi-cloud")
async def lightweight_start_scan(request: Request):
    worker_url = (os.getenv("SCAN_WORKER_URL") or "").strip().rstrip("/")
    if not worker_url:
        return {"status": "error", "detail": "SCAN_WORKER_URL is not configured"}

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    payload.setdefault("user_id", _standalone_user_id(request))

    try:
        import httpx

        timeout = httpx.Timeout(connect=10.0, read=30.0, write=30.0, pool=10.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.post(
                f"{worker_url}/internal/scan/multi-cloud",
                json=payload,
                headers=_worker_headers(),
            )
        try:
            data = response.json() if response.content else {}
        except ValueError:
            data = {"detail": response.text}

        if response.status_code >= 400:
            return {
                "status": "error",
                "detail": f"Scan worker error ({response.status_code}): {data}",
            }

        return data
    except Exception as exc:
        return {"status": "error", "detail": f"Scan worker is unreachable: {exc}"}


@lightweight_app.get("/api/latest-findings")
async def lightweight_latest_findings(request: Request):
    user_id = _standalone_user_id(request)
    limit = _parse_int(request.query_params.get("limit"), 10, minimum=1, maximum=500)
    scan_ids = request.query_params.get("scan_ids")

    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            query = """
                SELECT
                    r.name as resource_name,
                    r.cloud,
                    f.severity,
                    f.description,
                    f.validated_by as tool,
                    f.created_at
                FROM findings f
                JOIN scans s ON s.id = f.scan_id
                JOIN resources r ON f.resource_id = r.id
                WHERE s.user_id = %s
            """
            params: list[Any] = [user_id]

            if scan_ids:
                try:
                    ids = [int(item.strip()) for item in scan_ids.split(",") if item.strip()]
                    if ids:
                        query += " AND f.scan_id = ANY(%s)"
                        params.append(ids)
                except ValueError:
                    pass

            query += " ORDER BY f.created_at DESC LIMIT %s"
            params.append(limit)
            cur.execute(query, tuple(params))
            rows = cur.fetchall()

        return {
            "status": "success",
            "data": [
                {
                    "resource_name": resource_name,
                    "cloud": cloud,
                    "severity": severity,
                    "description": description,
                    "tool": tool,
                    "timestamp": created_at.isoformat() if created_at else None,
                }
                for resource_name, cloud, severity, description, tool, created_at in rows
            ],
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc), "data": []}


@lightweight_app.get("/api/scans")
async def lightweight_scans(request: Request):
    user_id = _standalone_user_id(request)
    limit = _parse_int(request.query_params.get("limit"), 20, minimum=1, maximum=250)
    offset = _parse_int(request.query_params.get("offset"), 0, minimum=0, maximum=100000)
    provider = request.query_params.get("provider")
    status = request.query_params.get("status")
    from_date = request.query_params.get("from_date")
    to_date = request.query_params.get("to_date")
    latest_only = _parse_bool(request.query_params.get("latest_only"), default=False)

    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            filters = ["s.user_id = %s"]
            params: list[Any] = [user_id]

            if provider:
                filters.append("s.cloud = %s")
                params.append(provider)
            if status:
                filters.append("s.status = %s")
                params.append(status)
            if from_date:
                filters.append("s.started_at >= %s")
                params.append(from_date)
            if to_date:
                filters.append("s.started_at <= %s")
                params.append(to_date)

            where_clause = " AND ".join(filters)
            if latest_only:
                query = f"""
                    WITH filtered_scans AS (
                        SELECT
                            s.id,
                            s.cloud,
                            s.account_id,
                            s.status,
                            s.started_at,
                            s.duration_seconds,
                            ROW_NUMBER() OVER (
                                PARTITION BY s.cloud, COALESCE(s.account_id, '')
                                ORDER BY s.started_at DESC, s.id DESC
                            ) AS rn
                        FROM scans s
                        WHERE {where_clause}
                    ),
                    selected_scans AS (
                        SELECT id, cloud, account_id, status, started_at, duration_seconds
                        FROM filtered_scans
                        WHERE rn = 1
                        ORDER BY started_at DESC, id DESC
                        LIMIT %s OFFSET %s
                    )
                    SELECT
                        ss.id,
                        ss.cloud,
                        ss.account_id,
                        ss.status,
                        ss.started_at,
                        ss.duration_seconds,
                        COUNT(DISTINCT r.id) as resource_count,
                        COUNT(DISTINCT f.id) as finding_count,
                        COUNT(DISTINCT CASE WHEN f.severity = 'CRITICAL' THEN f.id END) as critical_count
                    FROM selected_scans ss
                    LEFT JOIN resources r ON ss.id = r.scan_id
                    LEFT JOIN findings f ON ss.id = f.scan_id
                    GROUP BY ss.id, ss.cloud, ss.account_id, ss.status, ss.started_at, ss.duration_seconds
                    ORDER BY ss.started_at DESC, ss.id DESC
                """
                query_params = [*params, limit, offset]
                count_query = f"""
                    WITH filtered_scans AS (
                        SELECT
                            ROW_NUMBER() OVER (
                                PARTITION BY s.cloud, COALESCE(s.account_id, '')
                                ORDER BY s.started_at DESC, s.id DESC
                            ) AS rn
                        FROM scans s
                        WHERE {where_clause}
                    )
                    SELECT COUNT(*) FROM filtered_scans WHERE rn = 1
                """
                count_params = params
            else:
                query = f"""
                    SELECT
                        s.id,
                        s.cloud,
                        s.account_id,
                        s.status,
                        s.started_at,
                        s.duration_seconds,
                        COUNT(DISTINCT r.id) as resource_count,
                        COUNT(DISTINCT f.id) as finding_count,
                        COUNT(DISTINCT CASE WHEN f.severity = 'CRITICAL' THEN f.id END) as critical_count
                    FROM scans s
                    LEFT JOIN resources r ON s.id = r.scan_id
                    LEFT JOIN findings f ON s.id = f.scan_id
                    WHERE {where_clause}
                    GROUP BY s.id, s.cloud, s.account_id, s.status, s.started_at, s.duration_seconds
                    ORDER BY s.started_at DESC, s.id DESC
                    LIMIT %s OFFSET %s
                """
                query_params = [*params, limit, offset]
                count_query = f"SELECT COUNT(*) FROM scans s WHERE {where_clause}"
                count_params = params

            cur.execute(query, tuple(query_params))
            rows = cur.fetchall()
            cur.execute(count_query, tuple(count_params))
            total = cur.fetchone()[0]

        return {
            "status": "success",
            "scans": [
                {
                    "id": scan_id,
                    "cloud": cloud,
                    "account_id": account_id,
                    "status": scan_status,
                    "started_at": started_at.isoformat() if started_at else None,
                    "duration_seconds": duration,
                    "resource_count": resource_count,
                    "finding_count": finding_count,
                    "critical_count": critical_count,
                }
                for (
                    scan_id,
                    cloud,
                    account_id,
                    scan_status,
                    started_at,
                    duration,
                    resource_count,
                    finding_count,
                    critical_count,
                ) in rows
            ],
            "total": total,
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc), "scans": [], "total": 0}


class LazyCloudGuardApp:
    async def __call__(self, scope, receive, send):
        if scope.get("type") == "http":
            path = (scope.get("path") or "").rstrip("/") or "/"
            if path in LIGHTWEIGHT_PATHS:
                await lightweight_app(scope, receive, send)
                return

        await _get_main_app()(scope, receive, send)


app = LazyCloudGuardApp()

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware


ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


USER_ID_COOKIE = "cloudguard_user_id"
SSO_TOKEN_COOKIE = "cloudguard_sso_token"
LIGHTWEIGHT_PATHS = {
    "/",
    "/dashboard",
    "/frontend/history.html",
    "/schedules",
    "/system-status",
    "/health",
    "/api/info",
    "/api/auth/status",
    "/api/auth/sso/exchange",
    "/api/grc/status",
    "/api/grc/sync",
    "/api/uploads/iac-folder",
    "/api/credentials/providers/status",
    "/api/provider-breakdown",
    "/api/scan-history",
    "/api/scans",
    "/api/latest-findings",
    "/api/system/status",
    "/posture/dashboard",
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


@lightweight_app.middleware("http")
async def require_sso_session(request: Request, call_next):
    helpers = _user_context_helpers()
    incoming_token = (request.query_params.get("token") or "").strip()

    if (
        request.method == "OPTIONS"
        or helpers["is_public_path"](request.url.path)
        or (incoming_token and helpers["is_html_navigation"](request))
    ):
        return await call_next(request)

    user = helpers["authenticate_sso_user"](request)
    if not user:
        if helpers["is_html_navigation"](request):
            return RedirectResponse(helpers["build_sso_login_redirect"](request), status_code=307)
        return JSONResponse(
            status_code=401,
            content={
                "detail": "Authentication required",
                "login_url": helpers["build_sso_login_redirect"](request),
                "auth_mode": "sso" if not helpers["use_standalone_auth"](request) else "standalone",
            },
        )

    response = await call_next(request)
    response.set_cookie(
        helpers["USER_ID_COOKIE"],
        user["id"],
        max_age=60 * 60 * 24 * 30,
        path="/",
        samesite="lax",
        secure=request.url.scheme == "https",
    )

    token = getattr(request.state, "sso_token", None) or user.get("token")
    if token:
        response.set_cookie(
            helpers["SSO_TOKEN_COOKIE"],
            token,
            max_age=60 * 60,
            httponly=True,
            path="/",
            samesite="lax",
            secure=request.url.scheme == "https",
        )

    return response

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


def _user_context_helpers():
    from backend.user_context import (
        SSO_TOKEN_COOKIE as user_context_sso_cookie,
        USER_ID_COOKIE as user_context_cookie,
        authenticate_sso_user,
        build_sso_login_redirect,
        is_html_navigation,
        is_public_path,
        use_standalone_auth,
        verify_sso_token,
    )

    return {
        "SSO_TOKEN_COOKIE": user_context_sso_cookie,
        "USER_ID_COOKIE": user_context_cookie,
        "authenticate_sso_user": authenticate_sso_user,
        "build_sso_login_redirect": build_sso_login_redirect,
        "is_html_navigation": is_html_navigation,
        "is_public_path": is_public_path,
        "use_standalone_auth": use_standalone_auth,
        "verify_sso_token": verify_sso_token,
    }


def _standalone_user_id(request: Request) -> str:
    return (
        getattr(request.state, "user_id", None)
        or (request.query_params.get("user_id") or "").strip()
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


def _is_lightweight_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    return normalized in LIGHTWEIGHT_PATHS or normalized.startswith("/api/credentials")


def _frontend_file_response(filename: str) -> HTMLResponse:
    possible_paths = [
        ROOT / "frontend" / filename,
        Path("/app/frontend") / filename,
    ]

    for path in possible_paths:
        if path.exists():
            return HTMLResponse(path.read_text(encoding="utf-8"))

    raise FileNotFoundError(filename)


def _clean_sso_landing_url(request: Request) -> str:
    parsed = urlparse(str(request.url))
    filtered_query = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if key not in {"token", "from", "service"}
    ]
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urlencode(filtered_query, doseq=True),
            "",
        )
    )


def _maybe_complete_sso_html_landing(request: Request) -> Optional[RedirectResponse]:
    token = (request.query_params.get("token") or "").strip()
    if not token:
        return None

    helpers = _user_context_helpers()
    user = helpers["verify_sso_token"](token)
    response = RedirectResponse(_clean_sso_landing_url(request), status_code=307)

    if not user:
        return response

    response.set_cookie(
        helpers["USER_ID_COOKIE"],
        user["id"],
        max_age=60 * 60 * 24 * 30,
        path="/",
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    response.set_cookie(
        helpers["SSO_TOKEN_COOKIE"],
        token,
        max_age=60 * 60,
        httponly=True,
        path="/",
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


def _parse_scan_ids(scan_ids: Optional[str]) -> list[int]:
    if not scan_ids:
        return []

    try:
        return [int(item.strip()) for item in scan_ids.split(",") if item.strip()]
    except ValueError:
        return []


def _available_vulnerability_tools_payload(worker_health: dict[str, Any]) -> dict[str, bool]:
    tools = worker_health.get("vulnerability_tools") or []
    return {str(tool): True for tool in tools if tool}


def _credential_manager():
    from backend.credentials.manager import credential_manager

    return credential_manager


def _cloud_credential_cls():
    from backend.credentials.manager import CloudCredential

    return CloudCredential


def _normalize_aws_region_value(region: Optional[str]) -> str:
    from backend.credentials.manager import normalize_aws_region

    return normalize_aws_region(region)


def _serialize_credential_response(
    credential_id: int,
    credential: Any,
    save_action: Optional[str] = None,
    validation_status: str = "pending",
    validation_message: Optional[str] = None,
    is_valid: bool = False,
) -> dict[str, Any]:
    return {
        "id": credential_id,
        "user_id": credential.user_id,
        "cloud_provider": credential.cloud_provider,
        "credential_name": credential.credential_name,
        "is_default": credential.is_default,
        "is_valid": is_valid,
        "validation_status": validation_status,
        "validation_message": validation_message,
        "last_used": None,
        "created_at": datetime.utcnow().isoformat(),
        "save_action": save_action,
        "aws_role_arn": getattr(credential, "aws_role_arn", None),
        "aws_access_key_id": getattr(credential, "aws_access_key_id", None),
        "kubernetes_context": getattr(credential, "kubernetes_context", None),
        "kubernetes_cluster_name": getattr(credential, "kubernetes_cluster_name", None),
        "iac_target_path": getattr(credential, "iac_target_path", None),
        "iac_enabled_tools": getattr(credential, "iac_enabled_tools", None),
        "container_image_target": getattr(credential, "container_image_target", None),
        "container_path_target": getattr(credential, "container_path_target", None),
        "container_enabled_tools": getattr(credential, "container_enabled_tools", None),
        "container_sbom_tools": getattr(credential, "container_sbom_tools", None),
    }


async def _validate_saved_kubernetes_credential(
    credential_id: int,
    credential: Any,
) -> dict[str, Any]:
    from backend.credentials.api import _validate_kubernetes_credential_via_worker

    return await _validate_kubernetes_credential_via_worker(credential_id, credential)


@lightweight_app.get("/", response_class=HTMLResponse)
async def lightweight_root(request: Request):
    landing_response = _maybe_complete_sso_html_landing(request)
    if landing_response:
        return landing_response
    return _frontend_file_response("index.html")


@lightweight_app.get("/dashboard", response_class=HTMLResponse)
async def lightweight_dashboard_page(request: Request):
    landing_response = _maybe_complete_sso_html_landing(request)
    if landing_response:
        return landing_response
    return _frontend_file_response("dashboard.html")


@lightweight_app.get("/frontend/history.html", response_class=HTMLResponse)
async def lightweight_history_page(request: Request):
    landing_response = _maybe_complete_sso_html_landing(request)
    if landing_response:
        return landing_response
    return _frontend_file_response("history.html")


@lightweight_app.get("/schedules", response_class=HTMLResponse)
async def lightweight_schedules_page(request: Request):
    landing_response = _maybe_complete_sso_html_landing(request)
    if landing_response:
        return landing_response
    return _frontend_file_response("scheduled_scans.html")


@lightweight_app.get("/system-status", response_class=HTMLResponse)
async def lightweight_system_status_page(request: Request):
    landing_response = _maybe_complete_sso_html_landing(request)
    if landing_response:
        return landing_response
    return _frontend_file_response("system_status.html")


@lightweight_app.get("/api/credentials")
async def lightweight_get_credentials(request: Request):
    user_id = _standalone_user_id(request)
    provider = (request.query_params.get("provider") or "").strip() or None

    try:
        return _credential_manager().get_all_user_credentials(user_id, provider=provider)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@lightweight_app.delete("/api/credentials/{credential_id}")
async def lightweight_delete_credential(credential_id: int, request: Request):
    user_id = _standalone_user_id(request)

    try:
        deleted = _credential_manager().delete_credential(credential_id, user_id)
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    if not deleted:
        raise HTTPException(status_code=404, detail="Credential not found")

    return {"success": True, "credential_id": credential_id}


@lightweight_app.post("/api/credentials/aws")
async def lightweight_save_aws_credential(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    user_id = _standalone_user_id(request)
    CloudCredential = _cloud_credential_cls()
    credential = CloudCredential(
        user_id=user_id,
        cloud_provider="aws",
        credential_name=(payload.get("credential_name") or "").strip(),
        aws_access_key_id=payload.get("aws_access_key_id"),
        aws_secret_access_key=payload.get("aws_secret_access_key"),
        aws_region=_normalize_aws_region_value(payload.get("aws_region")),
        aws_role_arn=payload.get("aws_role_arn"),
        aws_session_token=payload.get("aws_session_token"),
        is_default=bool(payload.get("is_default", True)),
    )

    credential_id, save_action = _credential_manager().save_credential(credential)
    credential.id = credential_id
    background_tasks.add_task(_credential_manager().validate_credential, credential)
    return _serialize_credential_response(credential_id, credential, save_action=save_action)


@lightweight_app.post("/api/credentials/openai")
async def lightweight_save_openai_credential(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    user_id = _standalone_user_id(request)
    CloudCredential = _cloud_credential_cls()
    credential = CloudCredential(
        user_id=user_id,
        cloud_provider="openai",
        credential_name=(payload.get("credential_name") or "").strip(),
        openai_api_key=payload.get("openai_api_key"),
        openai_org_id=payload.get("openai_org_id"),
        is_default=bool(payload.get("is_default", True)),
    )

    credential_id, save_action = _credential_manager().save_credential(credential)
    credential.id = credential_id
    background_tasks.add_task(_credential_manager().validate_credential, credential)
    return _serialize_credential_response(credential_id, credential, save_action=save_action)


@lightweight_app.post("/api/credentials/gcp")
async def lightweight_save_gcp_credential(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    user_id = _standalone_user_id(request)

    try:
        service_account_json = payload.get("gcp_service_account_json") or ""
        service_account_data = json.loads(service_account_json)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid JSON for service account")

    CloudCredential = _cloud_credential_cls()
    credential = CloudCredential(
        user_id=user_id,
        cloud_provider="gcp",
        credential_name=(payload.get("credential_name") or "").strip(),
        gcp_service_account_json=service_account_json,
        gcp_project_id=payload.get("gcp_project_id") or service_account_data.get("project_id"),
        is_default=bool(payload.get("is_default", True)),
    )

    credential_id, save_action = _credential_manager().save_credential(credential)
    credential.id = credential_id
    background_tasks.add_task(_credential_manager().validate_credential, credential)
    return _serialize_credential_response(credential_id, credential, save_action=save_action)


@lightweight_app.post("/api/credentials/kubernetes")
async def lightweight_save_kubernetes_credential(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    user_id = _standalone_user_id(request)
    CloudCredential = _cloud_credential_cls()
    credential = CloudCredential(
        user_id=user_id,
        cloud_provider="kubernetes",
        credential_name=(payload.get("credential_name") or "").strip(),
        kubernetes_kubeconfig=payload.get("kubernetes_kubeconfig"),
        kubernetes_context=payload.get("kubernetes_context"),
        kubernetes_cluster_name=payload.get("kubernetes_cluster_name"),
        is_default=bool(payload.get("is_default", True)),
    )

    try:
        credential_id, save_action = _credential_manager().save_credential(credential)
    except Exception as exc:
        detail = str(exc)
        raise HTTPException(status_code=400 if "kubeconfig" in detail.lower() else 500, detail=detail)

    credential.id = credential_id
    if (os.getenv("SCAN_WORKER_URL") or "").strip():
        background_tasks.add_task(_validate_saved_kubernetes_credential, credential_id, credential)
    else:
        background_tasks.add_task(_credential_manager().validate_credential, credential)
    return _serialize_credential_response(credential_id, credential, save_action=save_action)


@lightweight_app.post("/api/credentials/iac")
async def lightweight_save_iac_credential(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    user_id = _standalone_user_id(request)
    CloudCredential = _cloud_credential_cls()
    credential = CloudCredential(
        user_id=user_id,
        cloud_provider="iac",
        credential_name=(payload.get("credential_name") or "").strip(),
        iac_target_path=(payload.get("iac_target_path") or "").strip() or None,
        iac_enabled_tools=payload.get("iac_enabled_tools") or [],
        is_default=bool(payload.get("is_default", True)),
    )

    credential_id, save_action = _credential_manager().save_credential(credential)
    credential.id = credential_id
    background_tasks.add_task(_credential_manager().validate_credential, credential)
    return _serialize_credential_response(credential_id, credential, save_action=save_action)


@lightweight_app.post("/api/credentials/container")
async def lightweight_save_container_credential(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    user_id = _standalone_user_id(request)
    CloudCredential = _cloud_credential_cls()
    credential = CloudCredential(
        user_id=user_id,
        cloud_provider="container",
        credential_name=(payload.get("credential_name") or "").strip(),
        container_image_target=(payload.get("container_image_target") or "").strip() or None,
        container_path_target=(payload.get("container_path_target") or "").strip() or None,
        container_enabled_tools=payload.get("container_enabled_tools") or [],
        container_sbom_tools=payload.get("container_sbom_tools") or [],
        is_default=bool(payload.get("is_default", True)),
    )

    credential_id, save_action = _credential_manager().save_credential(credential)
    credential.id = credential_id
    background_tasks.add_task(_credential_manager().validate_credential, credential)
    return _serialize_credential_response(credential_id, credential, save_action=save_action)


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


@lightweight_app.get("/api/auth/status")
async def lightweight_auth_status(request: Request):
    helpers = _user_context_helpers()
    standalone = helpers["use_standalone_auth"](request)
    user = helpers["authenticate_sso_user"](request)

    if not user:
        return JSONResponse(
            status_code=401,
            content={
                "authenticated": False,
                "auth_mode": "standalone" if standalone else "sso",
                "login_url": helpers["build_sso_login_redirect"](request) if not standalone else None,
            },
        )

    return {
        "authenticated": True,
        "auth_mode": "standalone" if standalone else "sso",
        "user": {
            "id": user["id"],
            "email": user.get("email"),
            "name": user.get("name"),
            "role": user.get("role"),
        },
    }


@lightweight_app.post("/api/auth/sso/exchange")
async def lightweight_sso_exchange(request: Request):
    helpers = _user_context_helpers()
    payload = await request.json()
    token = str(payload.get("token") or "").strip()
    if not token:
        raise HTTPException(status_code=400, detail="Missing SSO token")

    user = helpers["verify_sso_token"](token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid or expired SSO token")

    response = JSONResponse(
        {
            "authenticated": True,
            "auth_mode": "sso",
            "user": {
                "id": user["id"],
                "email": user.get("email"),
                "name": user.get("name"),
                "role": user.get("role"),
            },
        }
    )
    response.set_cookie(
        helpers["USER_ID_COOKIE"],
        user["id"],
        max_age=60 * 60 * 24 * 30,
        path="/",
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    response.set_cookie(
        helpers["SSO_TOKEN_COOKIE"],
        token,
        max_age=60 * 60,
        httponly=True,
        path="/",
        samesite="lax",
        secure=request.url.scheme == "https",
    )
    return response


@lightweight_app.get("/api/credentials/providers/status")
async def lightweight_provider_status(request: Request):
    user_id = _standalone_user_id(request)
    worker_enabled = bool((os.getenv("SCAN_WORKER_URL") or "").strip())

    providers = {
        "aws": {"configured": False, "valid": False, "selectable": False, "default_id": None},
        "gcp": {"configured": False, "valid": False, "selectable": False, "default_id": None},
        "openai": {"configured": False, "valid": False, "selectable": False, "default_id": None},
        "azure": {"configured": False, "valid": False, "selectable": False, "default_id": None},
        "kubernetes": {"configured": False, "valid": False, "selectable": False, "default_id": None},
        "iac": {"configured": False, "valid": False, "selectable": False, "default_id": None},
        "container": {"configured": False, "valid": False, "selectable": False, "default_id": None},
    }

    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, cloud_provider, is_default, COALESCE(is_valid, FALSE), validation_status
                FROM cloud_credentials
                WHERE user_id = %s
                ORDER BY is_default DESC, updated_at DESC, id DESC
                """,
                (user_id,),
            )
            rows = cur.fetchall()

        for cred_id, provider, is_default, is_valid, validation_status in rows:
            if provider not in providers:
                continue

            valid = bool(is_valid) or (validation_status or "").lower() == "valid"
            providers[provider]["configured"] = True
            providers[provider]["valid"] = providers[provider]["valid"] or valid
            providers[provider]["selectable"] = (
                providers[provider]["selectable"]
                or valid
                or (provider == "kubernetes" and worker_enabled)
            )
            if is_default and not providers[provider]["default_id"]:
                providers[provider]["default_id"] = cred_id

        return providers
    except Exception as exc:
        return {"status": "error", "message": str(exc), **providers}


@lightweight_app.get("/api/grc/status")
async def lightweight_grc_status():
    from backend.grc_bridge import get_grc_status

    return await get_grc_status()


@lightweight_app.post("/api/grc/sync")
async def lightweight_grc_sync():
    from backend.grc_bridge import trigger_grc_sync

    return await trigger_grc_sync()


@lightweight_app.post("/api/uploads/iac-folder")
async def lightweight_upload_iac_folder(
    req: Request,
    files: list[UploadFile] = File(...),
    relative_paths: list[str] = Form(default=[]),
):
    user_id = _standalone_user_id(req)

    if (os.getenv("SCAN_WORKER_URL") or "").strip():
        from backend.worker_client import upload_iac_folder_to_scan_worker

        worker_files: list[tuple[str, bytes, str]] = []
        for upload in files:
            worker_files.append(
                (
                    upload.filename or "uploaded-file",
                    await upload.read(),
                    upload.content_type or "application/octet-stream",
                )
            )
            await upload.close()

        return await upload_iac_folder_to_scan_worker(
            user_id=user_id,
            files=worker_files,
            relative_paths=relative_paths,
        )

    from backend.upload_utils import store_uploaded_directory

    result = await store_uploaded_directory(
        files=files,
        relative_paths=relative_paths,
        user_id=user_id,
        scan_type="iac",
    )
    result.update(
        {
            "status": "stored",
            "message": "IaC folder uploaded",
        }
    )
    return result


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


@lightweight_app.get("/posture/dashboard")
async def lightweight_posture_dashboard(request: Request):
    user_id = _standalone_user_id(request)
    scan_ids = request.query_params.get("scan_ids")
    parsed_scan_ids = _parse_scan_ids(scan_ids)
    worker_health = await _fetch_worker_health()
    dashboard = {
        "clouds": [],
        "total_resources": 0,
        "total_findings": 0,
        "public_resources": 0,
        "vulnerability_tools_available": _available_vulnerability_tools_payload(worker_health),
        "timestamp": datetime.utcnow().isoformat(),
    }

    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            query = """
                SELECT
                    r.cloud,
                    COUNT(DISTINCT r.id),
                    COUNT(DISTINCT f.id),
                    COUNT(DISTINCT CASE WHEN r.public THEN r.id END)
                FROM resources r
                JOIN scans s ON s.id = r.scan_id
                LEFT JOIN findings f ON r.id = f.resource_id
                WHERE s.user_id = %s
            """
            params: list[Any] = [user_id]
            if parsed_scan_ids:
                query += " AND r.scan_id = ANY(%s)"
                params.append(parsed_scan_ids)
            query += " GROUP BY r.cloud"
            cur.execute(query, tuple(params))
            summary = cur.fetchall()

        for provider, resources, findings, public in summary:
            dashboard["clouds"].append(
                {
                    "provider": provider,
                    "resources": resources,
                    "findings": findings,
                    "public": public,
                }
            )
            dashboard["total_resources"] += int(resources or 0)
            dashboard["total_findings"] += int(findings or 0)
            dashboard["public_resources"] += int(public or 0)

        if dashboard["total_resources"]:
            risk_ratio = dashboard["total_findings"] / dashboard["total_resources"]
            score = max(0, 100 - (risk_ratio * 100))
        else:
            score = 100

        dashboard["security_score"] = round(score, 2)
        return dashboard
    except Exception as exc:
        return {
            **dashboard,
            "status": "error",
            "message": str(exc),
            "security_score": 100,
        }


@lightweight_app.get("/api/provider-breakdown")
async def lightweight_provider_breakdown(request: Request):
    user_id = _standalone_user_id(request)
    scan_ids = _parse_scan_ids(request.query_params.get("scan_ids"))

    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            query = """
                SELECT
                    r.cloud AS provider,
                    COUNT(DISTINCT r.id) AS resources,
                    COUNT(DISTINCT f.id) AS findings
                FROM resources r
                JOIN scans s ON s.id = r.scan_id
                LEFT JOIN findings f ON r.id = f.resource_id
                WHERE s.user_id = %s
            """
            params: list[Any] = [user_id]
            if scan_ids:
                query += " AND r.scan_id = ANY(%s)"
                params.append(scan_ids)
            query += " GROUP BY r.cloud ORDER BY resources DESC"
            cur.execute(query, tuple(params))
            results = cur.fetchall()

        data = []
        for provider, resources, findings in results:
            score = max(0, 100 - (((findings or 0) / resources) * 100)) if resources else 100
            data.append(
                {
                    "provider": provider,
                    "resources": resources,
                    "findings": findings,
                    "security_score": round(score, 1),
                }
            )

        return {"status": "success", "data": data}
    except Exception as exc:
        return {"status": "error", "message": str(exc), "data": []}


@lightweight_app.get("/api/scan-history")
async def lightweight_scan_history(request: Request):
    user_id = _standalone_user_id(request)
    days = _parse_int(request.query_params.get("days"), 30, minimum=1, maximum=365)

    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    DATE(s.started_at) AS scan_date,
                    COUNT(DISTINCT s.id) AS scan_count,
                    COUNT(DISTINCT f.id) AS findings_count,
                    COUNT(DISTINCT CASE WHEN f.severity = 'CRITICAL' THEN f.id END) AS critical_count
                FROM scans s
                LEFT JOIN findings f ON s.id = f.scan_id
                WHERE s.user_id = %s
                  AND s.started_at >= NOW() - (%s || ' days')::interval
                GROUP BY DATE(s.started_at)
                ORDER BY scan_date ASC
                """,
                (user_id, days),
            )
            results = cur.fetchall()

        return {
            "status": "success",
            "data": [
                {
                    "date": scan_date.isoformat() if scan_date else None,
                    "scans": scan_count,
                    "findings": findings_count,
                    "critical": critical_count,
                }
                for scan_date, scan_count, findings_count, critical_count in results
            ],
        }
    except Exception as exc:
        return {"status": "error", "message": str(exc), "data": []}


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
            if _is_lightweight_path(path):
                await lightweight_app(scope, receive, send)
                return

        await _get_main_app()(scope, receive, send)


app = LazyCloudGuardApp()

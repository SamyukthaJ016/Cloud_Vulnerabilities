import asyncio
import json
import logging
import os
import secrets
from typing import Any, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException
from pydantic import BaseModel, Field

from backend.cloudfox.cloudfox_scanner import cloudfox_scanner
from backend.credentials.manager import CloudCredential, credential_manager
from backend.database import get_conn
from backend.main import (
    format_scan_completion_response,
    initialize_mcp_servers_for_user,
    run_multi_cloud_scan_internal,
)
from backend.scan_api_helpers import build_permission_required_payload
from backend.vulnerability.vulnerability_scanner import VulnerabilityScanner


logger = logging.getLogger("cloudguard_worker")

app = FastAPI(
    title="CloudGuard Worker API",
    description="Dedicated scan worker for long-running multi-cloud scans",
    version="1.0.0",
)

worker_vuln_scanner = VulnerabilityScanner()


class WorkerMultiCloudScanRequest(BaseModel):
    providers: list[str]
    account_ids: dict[str, str] = Field(default_factory=dict)
    deep_scan: bool = False
    offensive_scan: bool = True
    user_id: str
    credential_id: Optional[int] = None
    scan_targets: dict[str, dict[str, Any]] = Field(default_factory=dict)


class WorkerScheduleRunRequest(BaseModel):
    auth_user_id: str


class WorkerKubernetesValidationRequest(BaseModel):
    user_id: str
    kubeconfig: str
    context: Optional[str] = None
    cluster_name: Optional[str] = None


def _async_scan_mode_enabled() -> bool:
    raw = (os.getenv("WORKER_ASYNC_SCANS") or "true").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def _verify_worker_token(
    authorization: Optional[str] = Header(default=None),
    x_worker_token: Optional[str] = Header(default=None),
) -> None:
    expected = (os.getenv("WORKER_API_TOKEN") or os.getenv("SCAN_WORKER_TOKEN") or "").strip()
    if not expected:
        return

    provided = x_worker_token
    if not provided and authorization:
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() == "bearer":
            provided = token.strip()

    if not provided or not secrets.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Invalid worker token")


def _scan_result_summary(scan_results: list[Any]) -> list[dict[str, Any]]:
    return [
        {
            "provider": result.provider,
            "resources": len(result.resources),
            "findings": len(result.findings),
            "duration": result.scan_duration,
        }
        for result in scan_results
    ]


def _resolve_requested_credential(
    request: WorkerMultiCloudScanRequest,
    provider: str,
):
    if request.credential_id and len(request.providers) == 1:
        credential = credential_manager.get_credential_by_id(
            request.user_id,
            request.credential_id,
        )
        if credential and credential.cloud_provider == provider:
            return credential

    return credential_manager.get_default_credential(request.user_id, provider)


async def _preflight_multi_cloud_scan(request: WorkerMultiCloudScanRequest) -> None:
    missing = [
        provider for provider in request.providers
        if provider in {"aws", "gcp", "kubernetes"}
        if not _resolve_requested_credential(request, provider)
    ]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing credentials for: {', '.join(missing)}. Please add credentials in Settings.",
        )


async def _run_multi_cloud_scan_background(request: WorkerMultiCloudScanRequest) -> None:
    try:
        result_ctx = await run_multi_cloud_scan_internal(
            providers=request.providers,
            account_ids=request.account_ids,
            deep_scan=request.deep_scan,
            user_id=request.user_id,
            credential_id=request.credential_id,
            scan_targets=request.scan_targets,
        )
        logger.info(
            "Background worker scan completed for user=%s scan_ids=%s",
            request.user_id,
            result_ctx.get("scan_ids"),
        )
    except Exception:
        logger.exception(
            "Background worker scan failed for user=%s providers=%s",
            request.user_id,
            request.providers,
        )


@app.get("/health")
async def health():
    return {
        "status": "online",
        "service": "scan-worker",
        "cloudfox_available": cloudfox_scanner.available,
        "vulnerability_tools": list(worker_vuln_scanner.tools_available.keys()),
    }


@app.post("/internal/credentials/validate-kubernetes")
async def validate_kubernetes_credential(
    request: WorkerKubernetesValidationRequest,
    _: None = Depends(_verify_worker_token),
):
    aws_exec_cred = credential_manager.get_default_credential(request.user_id, "aws")
    credential = CloudCredential(
        user_id=request.user_id,
        cloud_provider="kubernetes",
        credential_name="worker-validation",
        kubernetes_kubeconfig=request.kubeconfig,
        kubernetes_context=request.context,
        kubernetes_cluster_name=request.cluster_name,
        aws_access_key_id=aws_exec_cred.aws_access_key_id if aws_exec_cred else None,
        aws_secret_access_key=aws_exec_cred.aws_secret_access_key if aws_exec_cred else None,
        aws_session_token=aws_exec_cred.aws_session_token if aws_exec_cred else None,
        aws_region=aws_exec_cred.aws_region if aws_exec_cred else None,
    )
    return credential_manager._validate_kubernetes_credential(credential)


@app.post("/internal/scan/multi-cloud")
async def run_multi_cloud_scan(
    request: WorkerMultiCloudScanRequest,
    _: None = Depends(_verify_worker_token),
):
    logger.info(
        "Worker executing multi-cloud scan for user=%s providers=%s",
        request.user_id,
        request.providers,
    )

    try:
        await _preflight_multi_cloud_scan(request)
    except Exception as exc:
        if hasattr(exc, "iam_user_arn") and hasattr(exc, "recommended_policy_arn"):
            return build_permission_required_payload(
                request.user_id,
                request.credential_id,
                exc,
            )
        raise

    if _async_scan_mode_enabled():
        asyncio.create_task(_run_multi_cloud_scan_background(request))
        return {
            "status": "started",
            "message": "Scan started on worker",
            "execution_mode": "worker_async",
            "providers_scanned": request.providers,
            "deep_scan_enabled": request.deep_scan,
            "offensive_scan_enabled": request.offensive_scan,
            "dashboard_url": "/dashboard",
            "history_url": "/frontend/history.html",
        }

    try:
        result_ctx = await run_multi_cloud_scan_internal(
            providers=request.providers,
            account_ids=request.account_ids,
            deep_scan=request.deep_scan,
            user_id=request.user_id,
            credential_id=request.credential_id,
            scan_targets=request.scan_targets,
        )
    except Exception as exc:
        if hasattr(exc, "iam_user_arn") and hasattr(exc, "recommended_policy_arn"):
            return build_permission_required_payload(
                request.user_id,
                request.credential_id,
                exc,
            )
        raise

    response = format_scan_completion_response(
        result_ctx["scan_ids"],
        result_ctx["scan_results"],
        result_ctx["ai_analysis"],
    )
    response.update(
        {
            "deep_scan_enabled": request.deep_scan,
            "offensive_scan_enabled": request.offensive_scan,
            "providers_scanned": request.providers,
            "scan_results": _scan_result_summary(result_ctx["scan_results"]),
            "execution_mode": "worker",
        }
    )
    return response


@app.post("/internal/schedules/{schedule_id}/run")
async def run_schedule_now(
    schedule_id: int,
    request: WorkerScheduleRunRequest,
    background_tasks: BackgroundTasks,
    _: None = Depends(_verify_worker_token),
):
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT user_id, providers, account_ids, deep_scan, credential_id, schedule
            FROM scan_schedules
            WHERE id = %s AND user_id = %s
            """,
            (schedule_id, request.auth_user_id),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Schedule not found")

    user_id, providers_json, account_ids_json, deep_scan, credential_id, schedule_payload = row
    providers = json.loads(providers_json) if providers_json else []
    account_ids = json.loads(account_ids_json) if account_ids_json else {}
    scan_targets = (schedule_payload or {}).get("scan_targets", {}) if isinstance(schedule_payload, dict) else {}

    if "aws" in providers:
        try:
            await initialize_mcp_servers_for_user(user_id, ["aws"], credential_id)
        except Exception as exc:
            if hasattr(exc, "iam_user_arn") and hasattr(exc, "recommended_policy_arn"):
                return build_permission_required_payload(user_id, credential_id, exc)
            raise

    background_tasks.add_task(
        run_multi_cloud_scan_internal,
        providers=providers,
        account_ids=account_ids,
        deep_scan=deep_scan,
        user_id=user_id,
        credential_id=credential_id,
        scan_targets=scan_targets,
    )
    return {"status": "started", "message": "Scan started on worker"}


@app.post("/internal/schedules/run-due")
async def run_due_schedules(_: None = Depends(_verify_worker_token)):
    from backend.scheduler_worker import run_due_schedules as _run_due_schedules

    await _run_due_schedules()
    return {"status": "completed"}


import os
import json
import logging
import textwrap
import uuid
import hashlib
import shutil
from io import BytesIO
from pathlib import Path
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import secrets

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from dotenv import load_dotenv
from openai import OpenAI
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from psycopg2.extras import Json

# MCP & Cloud Architecture
from backend.mcp.mcp_base import mcp_registry, MCPPlugin, ScanResult, CloudResource, SecurityFinding, Severity
from backend.mcp.mcp_aws_plugin import AWSPlugin
from backend.mcp.mcp_gcp_plugin import GCPPlugin

# MCP Server Architecture
from backend.mcp_servers.base_server import mcp_server_manager, MCPMessage, MCPResponse
from backend.mcp_servers.aws_server import create_aws_server
from backend.mcp_servers.gcp_server import create_gcp_server
from backend.mcp_servers.iac_server import create_iac_server
from backend.mcp_servers.kubernetes_server import create_kubernetes_server
from backend.cloudfox.cloudfox_server import create_cloudfox_server
from backend.mcp_scanner import mcp_scanner

# Vulnerability Scanning
from backend.vulnerability.vulnerability_scanner import VulnerabilityScanner, ScanTarget
from backend.vulnerability.vulnerability_integration import CloudVulnerabilityIntegration

# AI & Database
from backend.ai_recommender import AIRecommendationEngine
from backend.database import (
    create_scan_record,
    store_resource,
    store_finding,
    store_vulnerability,
    get_scan_report,
    get_multi_cloud_summary,
    get_conn,
)
from backend.ai.multi_agent_analyzer import get_multi_agent_analyzer
from backend.ai.persistent_memory import memory_system
from backend.ai.agentic_orchestrator import get_agentic_orchestrator
from backend.ai.agentic_core import ToolRegistry

# Credential Management
from backend.credentials.api import router as credentials_router
from backend.credentials.manager import credential_manager, CloudCredential

# CloudFox (Offensive Security)
from backend.cloudfox.cloudfox_scanner import (
    cloudfox_scanner,
    full_offensive_scan,
    format_cloudfox_report
)

# Database Migrations
from backend.migration_manager import run_migrations


load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_scanner")


def create_optional_openai_client() -> Optional[OpenAI]:
    api_key = os.getenv("OPENAI_API_KEY") or os.getenv("AI_API_KEY")
    base_url = os.getenv("OPENAI_BASE_URL") or os.getenv("AI_BASE_URL")
    if base_url and not api_key:
        api_key = "local-model"
    if not api_key:
        logger.warning("OPENAI_API_KEY is not configured; AI-only features will use fallbacks.")
        return None
    client_kwargs = {"api_key": api_key}
    if base_url:
        client_kwargs["base_url"] = base_url
    return OpenAI(**client_kwargs)


def read_frontend_asset(filename: str) -> str:
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "..", "frontend", filename),
        os.path.join("/app/frontend", filename),
        os.path.join("frontend", filename),
    ]

    for path in possible_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            with open(abs_path, "r", encoding="utf-8") as f:
                return f.read()

    raise FileNotFoundError(filename)

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="CloudGuard - Multi-Cloud Security Scanner",
    description="AI-powered CSPM with vulnerability detection and user credential management",
    version="3.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(credentials_router)

@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    logger.info("🚀 Starting CloudGuard Backend...")
    try:
        run_migrations()
        logger.info("✅ Database migrations complete")
    except Exception as e:
        logger.error(f"❌ Failed to run database migrations: {e}")

    # Initialize enhanced AI systems
    global multi_agent_analyzer
    logger.info("🤖 Initializing Multi-Agent Analysis System...")
    multi_agent_analyzer = get_multi_agent_analyzer(os.getenv("OPENAI_API_KEY"))

    logger.info("🧠 Initializing Persistent Memory System...")
    memory_system._ensure_tables_exist()

    logger.info("✅ Enhanced AI systems ready")
    logger.info("🚀 CloudGuard with MCP Server Architecture")
    logger.info("📊 Version: 4.0.0 (MCP-BASED)")
    logger.info(f"🔧 Vulnerability tools: {list(vuln_scanner.tools_available.keys())}")

    if cloudfox_scanner.available:
        logger.info(f"✅ CloudFox available: {cloudfox_scanner.cloudfox_path}")
    else:
        logger.warning("⚠️ CloudFox not found - offensive scans unavailable")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 Shutting down MCP servers")
    await mcp_scanner.cleanup()
    vuln_integration.cleanup()

# Consolidating router inclusions...
# app.include_router(credentials_router)

OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL") or os.getenv("AI_MODEL", "gpt-4o-mini")

openai_client = create_optional_openai_client()
orchestrator_client = openai_client
ai_engine = AIRecommendationEngine(api_key=os.getenv("OPENAI_API_KEY"))

vuln_scanner = VulnerabilityScanner()
vuln_integration = CloudVulnerabilityIntegration()

# ============================================================
# REQUEST MODELS
# ============================================================

class ScanRequest(BaseModel):
    message: str
    deep_scan: bool = False
    session_id: Optional[str] = None

class MultiCloudScanRequest(BaseModel):
    providers: list[str]
    account_ids: dict[str, str] = {}
    deep_scan: bool = False
    offensive_scan: bool = True  # NEW: Enable CloudFox by default
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    credential_id: Optional[int] = None  # NEW: Allow selecting specific credential


class EvidenceIngestionRequest(BaseModel):
    evidence_id: Optional[str] = None
    job_id: Optional[str] = None
    control_id: Optional[str] = None
    control_name: Optional[str] = None
    source_system: str = "manual"
    scanner_type: Optional[str] = None
    artifact_type: str = "json"
    filename: Optional[str] = None
    content_type: Optional[str] = "application/json"
    payload: Dict[str, Any] = {}
    metadata: Dict[str, Any] = {}


class AssetRiskContextRequest(BaseModel):
    tenant_id: Optional[str] = None
    asset_ref: str
    provider: Optional[str] = None
    asset_type: Optional[str] = None
    asset_name: Optional[str] = None
    business_criticality: str = "medium"
    internet_exposed: bool = False
    data_classification: str = "internal"
    environment: str = "unknown"
    owner: Optional[str] = None
    tags: Dict[str, Any] = Field(default_factory=dict)
    network_context: Dict[str, Any] = Field(default_factory=dict)
    identity_context: Dict[str, Any] = Field(default_factory=dict)
    custom_context: Dict[str, Any] = Field(default_factory=dict)


class FindingPrioritizationRequest(BaseModel):
    tenant_id: Optional[str] = None
    findings: List[Dict[str, Any]]
    asset_contexts: List[AssetRiskContextRequest] = Field(default_factory=list)


class ValidationJobRequest(BaseModel):
    tenant_id: Optional[str] = None
    finding_ref: str
    job_id: Optional[str] = None
    evidence_id: Optional[str] = None
    asset_ref: Optional[str] = None
    validation_type: str = "sandbox"
    safety_guardrails: Dict[str, Any] = Field(default_factory=dict)
    request_payload: Dict[str, Any] = Field(default_factory=dict)
    ttl_minutes: Optional[int] = 5
    requested_by: Optional[str] = None


class ValidationJobUpdateRequest(BaseModel):
    tenant_id: Optional[str] = None
    status: str
    proof_payload: Dict[str, Any] = Field(default_factory=dict)
    proof_uri: Optional[str] = None
    result_summary: Optional[str] = None
    evidence_id: Optional[str] = None


class RemediationActionRequest(BaseModel):
    tenant_id: Optional[str] = None
    finding_ref: str
    validation_id: Optional[str] = None
    mode: str = "learn"
    title: str
    priority: str = "medium"
    risk_score: int = 0
    action_type: str = "manual"
    recommended_steps: List[Dict[str, Any]] = Field(default_factory=list)
    automation_payload: Dict[str, Any] = Field(default_factory=dict)
    rollback_plan: Dict[str, Any] = Field(default_factory=dict)
    evidence_id: Optional[str] = None
    requested_by: Optional[str] = None


class RemediationDecisionRequest(BaseModel):
    tenant_id: Optional[str] = None
    decision: str
    note: Optional[str] = None
    approved_by: Optional[str] = None
    evidence_id: Optional[str] = None
    result_payload: Dict[str, Any] = Field(default_factory=dict)


class ThreatModelRequest(BaseModel):
    tenant_id: Optional[str] = None
    scope: str
    source_type: str = "manual"
    input_artifacts: List[Dict[str, Any]] = Field(default_factory=list)


class SandboxLabRequest(BaseModel):
    tenant_id: Optional[str] = None
    provider: str
    lab_type: str = "default"
    ttl_minutes: int = 5
    credential_id: Optional[int] = None
    region: Optional[str] = None
    namespace: Optional[str] = None
    scan_after_deploy: bool = True
    auto_destroy: bool = True
    requested_by: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class SandboxLabDestroyRequest(BaseModel):
    tenant_id: Optional[str] = None
    reason: Optional[str] = "manual_destroy"


class IaCUploadedFile(BaseModel):
    filename: str
    content: str


class IaCFileScanRequest(BaseModel):
    files: List[IaCUploadedFile]
    user_id: Optional[str] = None
    deep_scan: bool = False


class ScheduledScanRequest(BaseModel):
    providers: list[str]
    account_ids: dict[str, str] = {}
    deep_scan: bool = False
    schedule: dict
    user_id: Optional[str] = None
    credential_id: Optional[int] = None  # NEW: Allow selecting specific credential for scheduled scans
    notify_email: bool = False           # NEW: Notification preference
    email_address: Optional[str] = None  # NEW: Target email address
    test_permissions: bool = True        # NEW: Validate permissions before scheduling


class VulnScanRequest(BaseModel):
    target_type: str
    path: str
    metadata: dict = {}
    session_id: Optional[str] = None

class AgentChatRequest(BaseModel):
    message: str

class AgentChatResponse(BaseModel):
    reply: str

class AgentExplainScanRequest(BaseModel):
    scan_id: int
    question: Optional[str] = None

class SessionRequest(BaseModel):
    user_id: str = "anonymous"
    credentials: Dict[str, int] = {}

class SessionResponse(BaseModel):
    session_id: str
    expires_at: datetime
    providers_available: List[str]

class WorkerHeartbeatRequest(BaseModel):
    worker_id: str = Field(..., min_length=1, max_length=128)
    worker_type: str = Field("scan", pattern="^(scan|scheduler|sandbox|evidence|inline|unknown)$")
    status: str = Field("online", pattern="^(online|idle|busy|degraded|offline)$")
    metadata: Dict[str, Any] = Field(default_factory=dict)

# ============================================================
# 🔥 FIXED CREDENTIAL INITIALIZATION
# ============================================================

from backend.credentials.manager import credential_manager

def initialize_plugins_with_user_credentials(user_id: str) -> dict:
    logger.info(f"🔍 Loading credentials for user: {user_id}")

    providers_initialized: dict[str, MCPPlugin] = {}

    # ==========================
    # AWS INITIALIZATION (Robust)
    # ==========================
    aws_credential_id: int | None = None

    # Try to get ANY valid credential (preferred default, then latest)
    all_aws = credential_manager.get_all_user_credentials(user_id, "aws")

    if all_aws:
        best_candidate = all_aws[0]
        aws_cred = credential_manager.get_credentials(best_candidate["id"], user_id)

        if aws_cred:
            aws_credential_id = aws_cred.id
            is_def_str = "(Default)" if aws_cred.is_default else "(Fallback)"
            logger.info(f"🔑 Using AWS credential {is_def_str} for user {user_id} (id={aws_credential_id})")

            try:
                # 1. Initialize Plugin (Old Architecture)
                plugin = AWSPlugin({
                    "access_key_id": aws_cred.aws_access_key_id,
                    "secret_access_key": aws_cred.aws_secret_access_key,
                    "session_token": aws_cred.aws_session_token,
                    "region": aws_cred.aws_region or "us-east-1",
                })
                mcp_registry.register("aws", plugin)
                providers_initialized["aws"] = plugin
                logger.info("✅ AWS Plugin registered")

                # 2. Initialize MCP Server (New Architecture - Required for Scan)
                aws_server = create_aws_server({
                    "access_key_id": aws_cred.aws_access_key_id,
                    "secret_access_key": aws_cred.aws_secret_access_key,
                    "session_token": aws_cred.aws_session_token,
                    "region": aws_cred.aws_region or "us-east-1"
                })
                mcp_server_manager.register_server(aws_server)
                logger.info("✅ AWS MCP Server registered")

            except Exception as e:
                logger.error(f"❌ Failed to initialize AWS plugin/server: {e}")
                aws_credential_id = None
    else:
        logger.warning(f"⚠️ No AWS credentials found for user {user_id}")

    # ==========================
    # GCP INITIALIZATION (Robust)
    # ==========================
    # Try to get ANY valid credential (preferred default, then latest)
    all_gcp = credential_manager.get_all_user_credentials(user_id, "gcp")

    if all_gcp:
        best_candidate = all_gcp[0]
        gcp_cred = credential_manager.get_credentials(best_candidate["id"], user_id)

        if gcp_cred:
            is_def_str = "(Default)" if gcp_cred.is_default else "(Fallback)"
            logger.info(f"🔑 Using GCP credential {is_def_str} for user {user_id} (id={gcp_cred.id})")

            try:
                # 1. Initialize Plugin (Old Architecture)
                plugin = GCPPlugin({
                    "service_account_json": gcp_cred.gcp_service_account_json,
                    "project_id": gcp_cred.gcp_project_id
                })
                mcp_registry.register("gcp", plugin)
                providers_initialized["gcp"] = plugin
                logger.info("✅ GCP Plugin registered")

                # 2. Initialize MCP Server (New Architecture - Required for Scan)
                gcp_server = create_gcp_server({
                    "service_account_json": gcp_cred.gcp_service_account_json,
                    "project_id": gcp_cred.gcp_project_id
                })
                mcp_server_manager.register_server(gcp_server)
                logger.info("✅ GCP MCP Server registered")

            except Exception as e:
                logger.error(f"❌ Failed to initialize GCP plugin/server: {e}")
    else:
        logger.warning(f"⚠️ No GCP credentials found for user {user_id}")

    return providers_initialized



def get_user_id(request: Request) -> str:
    """Extract the browser-scoped CloudGuard user ID."""
    session_id = request.cookies.get("session_id") or request.cookies.get("cloudguard_session")
    if session_id:
        return f"user_{session_id}"
    return "anonymous"


def _request_token(req: Request, header_name: str, query_name: str) -> Optional[str]:
    auth_header = req.headers.get("authorization", "")
    return (
        req.headers.get(header_name)
        or req.query_params.get(query_name)
        or (auth_header.removeprefix("Bearer ").strip() if auth_header.startswith("Bearer ") else None)
    )


def _is_connector_request_authorized(req: Request) -> bool:
    expected_token = os.getenv("CONNECTOR_TOKEN") or os.getenv("EVIDENCE_CONNECTOR_TOKEN")
    provided_token = _request_token(req, "x-connector-token", "connector_token")
    if expected_token:
        return provided_token == expected_token
    return os.getenv("CONNECTOR_AUTH_REQUIRED", "false").lower() != "true"


def _connector_user_id(req: Request) -> str:
    return req.headers.get("x-cloudguard-user") or get_user_id(req)


def _wrap_text(text: str, width: int = 95):
    text = text.replace("\r", " ").replace("\n", " ")
    return textwrap.wrap(text, width=width)

def build_scan_report(scan_id: int) -> dict:
    rows = get_scan_report(scan_id)
    if not rows:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

    findings = [
        {
            "resource_id": r[0],
            "resource_name": r[1],
            "cloud": (r[2] or "").lower(),
            "type": r[3],
            "public": r[4],
            "severity": r[5],
            "description": r[6],
        }
        for r in rows
        if r[5]
    ]


# ============================================================
# SCHEDULE MANAGEMENT
# ============================================================

@app.post("/api/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: int, background_tasks: BackgroundTasks):
    """Manually trigger a scheduled scan now"""
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            "SELECT user_id, providers, account_ids, deep_scan, credential_id FROM scan_schedules WHERE id = %s",
            (schedule_id,)
        )
        row = cur.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Schedule not found")

        user_id, providers_text, account_ids_text, deep_scan, credential_id = row
        providers = json.loads(providers_text)
        account_ids = json.loads(account_ids_text)

    # 🛡️ Permission Check
    if "aws" in providers:
        logger.info(f"🛡️ Testing AWS permissions for schedule {schedule_id} before run...")
        try:
            await initialize_mcp_servers_for_user(user_id, ["aws"], credential_id)
        except Exception as e:
            if hasattr(e, 'iam_user_arn') and hasattr(e, 'recommended_policy_arn'):
                logger.warning(f"🛡️ Permission check failed for schedule {schedule_id}")
                iam_user_name = e.iam_user_arn.split('/')[-1] if '/' in e.iam_user_arn else e.iam_user_arn
                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "permission_required",
                        "permission_error": {
                            "type": "missing_assume_role_permission",
                            "iam_user_name": iam_user_name,
                            "iam_user_arn": e.iam_user_arn,
                            "role_arn": getattr(e, 'role_arn', None),
                            "policy_arn": e.recommended_policy_arn,
                            "credential_id": credential_id,
                            "can_auto_grant": True
                        }
                    }
                )

    scan_request = MultiCloudScanRequest(
        providers=providers,
        account_ids=account_ids,
        deep_scan=deep_scan,
        offensive_scan=True,
        user_id=user_id,
        credential_id=credential_id,
    )
    job = create_scan_job(user_id, scan_request)
    if os.getenv("SCAN_JOB_INLINE_WORKER", "true").lower() == "true":
        background_tasks.add_task(process_scan_job, job["job_id"])

    return {
        "status": "queued",
        "job_id": job["job_id"],
        "message": "Scheduled scan job queued",
    }


load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_scanner")



OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL") or os.getenv("AI_MODEL", "gpt-4o-mini")

openai_client = create_optional_openai_client()
orchestrator_client = openai_client
ai_engine = AIRecommendationEngine(api_key=os.getenv("OPENAI_API_KEY"))

vuln_scanner = VulnerabilityScanner()
vuln_integration = CloudVulnerabilityIntegration()

# Initialize multi-agent analyzer
multi_agent_analyzer = None

# ============================================================
# REQUEST MODELS
# ============================================================

# Duplicate models removed. Using definitions from the top of the file.

# ============================================================
# CREDENTIAL INITIALIZATION FOR MCP SERVERS
# ============================================================

async def initialize_mcp_servers_for_user(user_id: str, providers: list[str], credential_id: Optional[int] = None):
    """Ensure MCP servers are initialized for the user's selected providers."""
    logger.info(f"🔄 (Re)initializing MCP servers for user {user_id} and requested providers: {providers}")

    for provider in providers:
        if provider == "aws":
            # Use specific credential if provided, otherwise use default
            if credential_id:
                aws_cred = credential_manager.get_credential_by_id(user_id, credential_id)
            else:
                aws_cred = credential_manager.get_default_credential(user_id, "aws")

            if (not aws_cred):
                logger.warning(f"⚠️ No AWS credentials found in DB for user {user_id}")
                # ONLY fallback if user is anonymous and we have no other choice
                if user_id == "anonymous" and mcp_server_manager.get_server("aws"):
                    logger.info("ℹ️ Using existing AWS MCP server for anonymous user (env fallback)")
                    continue
                mcp_registry.unregister("aws")
                await mcp_server_manager.unregister_server("aws")
                logger.error(f"❌ Cannot initialize AWS for user {user_id}: No credentials.")
                # We don't continue here - we want the scan to fail for this provider specifically
                # Note: No need to unregister - register() will overwrite if needed
                continue

            # If we HAVE a user credential, always (re)initialize to ensure it's used
            logger.info(f"[ServerInit] (Re)initializing AWS server with credentials for user: {user_id}")
            aws_config = {
                "access_key_id": aws_cred.aws_access_key_id,
                "secret_access_key": aws_cred.aws_secret_access_key,
                "region": aws_cred.aws_region or "us-east-1",
                "credential_id": aws_cred.id,
                "user_id": user_id,
            }

            # ✅ Add session_token if it exists
            token = aws_cred.aws_session_token
            if token and token.strip() and token.lower() not in ("none", "null"):
                aws_config["session_token"] = token

            # ✅ Add role_arn if it exists
            role_arn = aws_cred.aws_role_arn
            if role_arn and role_arn.strip() and role_arn.lower() not in ("none", "null"):
                aws_config["role_arn"] = role_arn


            server = create_aws_server(aws_config)

            mcp_server_manager.register_server(server)
            await server.start()

            # 🔥 THIS IS CRITICAL
            mcp_registry.register("aws", server)
            if not mcp_server_manager.get_server("cloudfox"):
                from backend.cloudfox.cloudfox_server import create_cloudfox_server

                cloudfox_server = create_cloudfox_server({
                    "profile": "default",
                    "region": aws_cred.aws_region or "us-east-1",
                })
                mcp_server_manager.register_server(cloudfox_server)
                await cloudfox_server.start()
                mcp_registry.register("cloudfox", cloudfox_server)

                logger.info("✅ CloudFox MCP server initialized")
            logger.info("✅ AWS MCP server initialized and registered")

        elif provider == "gcp":
            logger.info(f"[ServerInit] Attempting to retrieve default GCP credential for user: {user_id}")
            gcp_cred = credential_manager.get_default_credential(user_id, "gcp")

            if not gcp_cred:
                logger.warning(f"⚠️ No GCP credentials found in DB for user {user_id}")
                if user_id == "anonymous" and mcp_server_manager.get_server("gcp"):
                    logger.info("ℹ️ Using existing GCP MCP server for anonymous user (env fallback)")
                    continue
                mcp_registry.unregister("gcp")
                await mcp_server_manager.unregister_server("gcp")
                logger.error(f"❌ Cannot initialize GCP for user {user_id}: No credentials.")
                # Note: No need to unregister - register() will overwrite if needed
                continue

            # If we HAVE a user credential, always (re)initialize to ensure it's used
            logger.info(f"[ServerInit] (Re)initializing GCP server with credentials (cred_id={gcp_cred.id}) for user: {user_id}")
            gcp_config = {
                "service_account_json": gcp_cred.gcp_service_account_json,
                "project_id": gcp_cred.gcp_project_id
            }

            server = create_gcp_server(gcp_config)
            mcp_server_manager.register_server(server)
            await server.start()

            mcp_registry.register("gcp", server)
            logger.info(f"✅ GCP MCP Server initialized and registered for project: {gcp_cred.gcp_project_id}")

        elif provider == "cloudfox":
            if mcp_server_manager.get_server("cloudfox"):
                continue

            server = create_cloudfox_server()
            mcp_server_manager.register_server(server)
            await server.start()

            mcp_registry.register("cloudfox", server)

            logger.info("✅ CloudFox MCP server initialized")

        elif provider == "kubernetes":
            kube_cred = credential_manager.get_default_credential(user_id, "kubernetes")

            if not kube_cred:
                logger.warning(f"⚠️ No Kubernetes kubeconfig found in DB for user {user_id}")
                mcp_registry.unregister("kubernetes")
                await mcp_server_manager.unregister_server("kubernetes")
                continue

            kubernetes_config = {
                "root_path": os.getcwd(),
                "kubeconfig": kube_cred.kubernetes_kubeconfig,
                "context": kube_cred.kubernetes_context,
                "cluster_name": kube_cred.kubernetes_cluster_name,
                "credential_id": kube_cred.id,
                "user_id": user_id,
            }

            try:
                aws_cred = credential_manager.get_default_credential(user_id, "aws")
                if aws_cred:
                    kubernetes_config["aws"] = {
                        "access_key_id": aws_cred.aws_access_key_id,
                        "secret_access_key": aws_cred.aws_secret_access_key,
                        "session_token": aws_cred.aws_session_token,
                        "region": aws_cred.aws_region or "us-east-1",
                        "role_arn": aws_cred.aws_role_arn,
                    }
            except Exception as exc:
                logger.warning(f"Could not attach AWS credentials for Kubernetes enrichment: {exc}")

            try:
                gcp_cred = credential_manager.get_default_credential(user_id, "gcp")
                if gcp_cred:
                    kubernetes_config["gcp"] = {
                        "service_account_json": gcp_cred.gcp_service_account_json,
                        "project_id": gcp_cred.gcp_project_id,
                    }
            except Exception as exc:
                logger.warning(f"Could not attach GCP credentials for Kubernetes enrichment: {exc}")

            try:
                azure_cred = credential_manager.get_default_credential(user_id, "azure")
                if azure_cred:
                    kubernetes_config["azure"] = {
                        "client_id": azure_cred.azure_client_id,
                        "client_secret": azure_cred.azure_client_secret,
                        "tenant_id": azure_cred.azure_tenant_id,
                        "subscription_id": azure_cred.azure_subscription_id,
                    }
            except Exception as exc:
                logger.warning(f"Could not attach Azure credentials for Kubernetes enrichment: {exc}")

            server = create_kubernetes_server(kubernetes_config)
            mcp_server_manager.register_server(server)
            await server.start()
            mcp_registry.register("kubernetes", server)
            logger.info("✅ Kubernetes live cluster scanner initialized")

        elif provider == "iac":
            server = create_iac_server({"root_path": os.getcwd()})
            mcp_server_manager.register_server(server)
            await server.start()
            mcp_registry.register("iac", server)
            logger.info("✅ IaC scanner initialized")

def _mcp_to_scan_result(provider: str, data: dict | ScanResult) -> ScanResult:
    """Convert raw MCP response dict to ScanResult object"""
    if isinstance(data, ScanResult):
        return data

    raw_resources = data.get("resources", [])
    # 🛡️ DEFENSIVE: Handle cases where resources might be a dict instead of a list
    if isinstance(raw_resources, dict):
        logger.warning(f"⚠️ Provider {provider} returned resources as dict, converting to list")
        resources_list = []
        for r_type, count in raw_resources.items():
            if isinstance(count, int):
                # If it's just a count, we can't do much, but let's at least not crash
                resources_list.append({
                    "provider": provider,
                    "resource_type": r_type,
                    "name": f"{r_type}_count_{count}",
                    "config": {"count": count}
                })
            else:
                resources_list.append(count)
        raw_resources = resources_list

    resources = []
    for r in raw_resources:
        try:
            if isinstance(r, dict):
                # Ensure provider is set
                if "provider" not in r: r["provider"] = provider
                resources.append(CloudResource(**r))
            else:
                resources.append(r)
        except Exception as e:
            logger.error(f"❌ Failed to parse resource: {e}")

    findings_data = data.get("findings", [])
    findings = []
    for f in findings_data:
        try:
            if isinstance(f, dict):
                # 🛡️ DEFENSIVE: Fix missing mandatory fields for SecurityFinding
                if "provider" not in f: f["provider"] = provider

                # Handle nested resource
                if isinstance(f.get("resource"), dict):
                    res_dict = f["resource"]
                    if "provider" not in res_dict: res_dict["provider"] = provider
                    f["resource"] = CloudResource(**res_dict)
                elif not f.get("resource"):
                    # Create a dummy resource if missing
                    f["resource"] = CloudResource(provider=provider, resource_type="unknown", name="unknown")

                # Ensure recommendation exists
                if "recommendation" not in f:
                    f["recommendation"] = "No recommendation provided by scanner."

                # Handle severity enum
                if isinstance(f.get("severity"), str):
                    try:
                        f["severity"] = Severity(f["severity"].upper())
                    except:
                        f["severity"] = Severity.MEDIUM

                findings.append(SecurityFinding(**f))
            else:
                findings.append(f)
        except Exception as e:
            logger.error(f"❌ Failed to parse finding: {e}")

    return ScanResult(
        provider=provider,
        account_id=data.get("account_id", "unknown"),
        resources=resources,
        findings=findings,
        scan_duration=data.get("scan_duration", 0.0),
        errors=data.get("errors", [])
    )

async def run_gpt_agent(prompt: str) -> str:
    if not openai_client:
        return "AI agent unavailable because OPENAI_API_KEY is not configured."

    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_AGENT_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cloud security expert and CSPM analyst with deep knowledge of vulnerability management."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error("GPT Agent error: %s", e)
        return f"Agent error: {e}"

async def run_multi_cloud_scan_internal(
    providers: list[str],
    account_ids: dict[str, str],
    deep_scan: bool,
    user_id: str,
    credential_id: Optional[int] = None,  # NEW: Support specific credential
    offensive_scan: bool = True,
):
    """Core multi-cloud scan logic reused by API and scheduler."""
    logger.info(f"🚀 Multi-cloud scan for providers: {providers}")
    logger.info(f"👤 User ID: {user_id}")

    # ✅ STEP 1: Initialize plugins with user credentials
    await initialize_mcp_servers_for_user(user_id, providers, credential_id)

    # Get initialized providers from registry
    initialized_list = mcp_registry.list_providers()
    providers_initialized = {p: True for p in initialized_list}

    # Get AWS credential ID if available
    aws_cred_id = None
    if "aws" in providers_initialized:
        aws_plugin = mcp_registry.get_plugin("aws")
        if aws_plugin and hasattr(aws_plugin, "config"):
            aws_cred_id = aws_plugin.config.get("credential_id")

    logger.info(f"DEBUG aws_cred_id in internal: {aws_cred_id}")
    logger.info(f"✅ Initialized providers: {list(providers_initialized.keys())}")

    # ✅ STEP 2: Verify ALL requested providers are initialized
    missing_providers = []
    for provider in providers:
        if provider not in providers_initialized:
            missing_providers.append(provider)
            logger.error(f"❌ Provider {provider} not initialized - no credentials available")

    if missing_providers:
        error_msg = f"Missing credentials for: {', '.join(missing_providers)}. Please add credentials in Settings."
        logger.error(error_msg)
        raise HTTPException(status_code=400, detail=error_msg)

    # ✅ STEP 3: Run scans for each provider
    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    for provider in providers:
        try:
            account_id = account_ids.get(provider, "default") or "default"
            logger.info(f"📡 Scanning {provider} with account_id: {account_id}")

            # Scan using the registry (which now has the user's credentials)
            raw_result = await mcp_registry.scan(
                provider=provider,
                account_id=account_id,
                options={
                    "deep_scan": deep_scan,
                    "offensive_scan": offensive_scan,
                },
            )

            # Convert dict to ScanResult
            result = _mcp_to_scan_result(provider, raw_result)

            # Deep scan if requested
            if deep_scan:
                logger.info(f"🔬 Running deep vulnerability scan for {provider}...")
                plugin = mcp_registry.get_plugin(provider)
                cloud_client = None
                if plugin:
                    cloud_client = getattr(plugin, "s3", None) or getattr(
                        plugin, "storage_client", None
                    )

                for resource in result.resources:
                    try:
                        vuln_findings = await vuln_integration.scan_cloud_resource(
                            resource, cloud_client
                        )
                        result.findings.extend(vuln_findings)
                    except Exception as e:
                        logger.error(f"Failed to scan resource {resource.name}: {e}")

                logger.info(f"✅ Deep scan completed for {provider}")

            scan_results.append(result)

            # Store results with credential linkage
            scan_id = await store_scan_result(
                result,
                aws_credential_id=aws_cred_id if provider == "aws" else None,
            )
            stored_ids.append(scan_id)
            logger.info(f"✅ {provider.upper()} scan finished, stored as scan_id: {scan_id}")

        except Exception as e:
            logger.error(f"❌ Scan failed for {provider}: {e}")
            import traceback
            logger.error(traceback.format_exc())

            # Create a "Failed Scan" result so it's visible on the dashboard
            error_resource = CloudResource(
                provider=provider,
                resource_type="scanner",
                name=f"{provider}_scan_error",
                config={"error": str(e)}
            )
            failed_result = ScanResult(
                provider=provider,
                account_id=account_id,
                resources=[error_resource],
                findings=[
                    SecurityFinding(
                        resource=error_resource,
                        severity=Severity.HIGH,
                        issue=f"[SCAN-ERROR] {provider.upper()} scan failed",
                        description=f"The scan for {provider} failed with the following error: {str(e)}.",
                        recommendation="Check that the selected credentials are valid, active, and have the required read-only permissions.",
                        detection_tool="SCAN-ERROR",
                        tool_category="scan_orchestration"
                    )
                ],
                errors=[str(e)]
            )
            scan_results.append(failed_result)

            # Store the error as a scan record so it's not lost
            try:
                # Get appropriate credential ID if possible
                aws_id = aws_cred_id if provider == "aws" else None
                scan_id = await store_scan_result(failed_result, aws_credential_id=aws_id)
                stored_ids.append(scan_id)
                logger.info(f"⚠️ Stored FAILED scan as scan_id: {scan_id}")
            except Exception as store_err:
                logger.error(f"Failed to store error record: {store_err}")

    # ✅ STEP 4: AI Analysis
    try:
        ai_analysis = await ai_engine.analyze_scan_results(scan_results)
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        ai_analysis = {"error": "AI unavailable"}

    return {
        "scan_ids": stored_ids,
        "scan_results": scan_results,
        "ai_analysis": ai_analysis,
        "deep_scan_enabled": deep_scan,
        "user_credentials_used": len(providers_initialized) > 0,
    }
@app.post("/scan/schedule")
async def schedule_scan(request: ScheduledScanRequest, req: Request):
    user_id = request.user_id or "anonymous"
    logger.info(f"📅 Received schedule scan request from user={user_id}: {request}")

    schedule = request.schedule or {}
    stype = schedule.get("type")
    if stype not in ("once", "recurring"):
        logger.warning(f"❌ Invalid schedule type: {stype}")
        raise HTTPException(status_code=400, detail="schedule.type must be 'once' or 'recurring'")

    # ⏰ Timezone handling
    tz_name = schedule.get("timezone") or "UTC"
    try:
        tz = ZoneInfo(tz_name)
    except Exception:
        raise HTTPException(status_code=400, detail=f"Invalid timezone: {tz_name}")

    # next_run_at calculate (store in UTC)
    if stype == "once":
        dt_str = schedule.get("datetime")  # e.g. "2025-12-23T15:36"
        if not dt_str:
            raise HTTPException(status_code=400, detail="datetime is required for one-time schedule")
        try:
            local_naive = datetime.fromisoformat(dt_str)        # naive local
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid datetime format")
        local = local_naive.replace(tzinfo=tz)                  # attach timezone
        next_run_at = local.astimezone(timezone.utc)            # convert to UTC

    else:  # recurring
        time_str = schedule.get("time")  # "HH:MM"
        frequency = schedule.get("frequency", "daily") # "10m", "30m", "60m", "6h", "daily", "weekly", "monthly", "2w"

        # Today in that timezone
        now_local = datetime.now(tz)

        if frequency == "10m":
            next_run_local = now_local + timedelta(minutes=10)
        elif frequency == "30m":
            next_run_local = now_local + timedelta(minutes=30)
        elif frequency == "60m" or frequency == "hourly":
            next_run_local = now_local + timedelta(hours=1)
        elif frequency == "6h":
            next_run_local = now_local + timedelta(hours=6)
        elif frequency == "2w":
            next_run_local = now_local + timedelta(weeks=2)
        else: # daily/weekly/monthly/etc uses specific time
            if not time_str:
                 raise HTTPException(status_code=400, detail="time is required for recurring schedule (except for short intervals)")

            today_local_date = now_local.date()
            try:
                # build local datetime "YYYY-MM-DDTHH:MM"
                local_naive = datetime.fromisoformat(f"{today_local_date}T{time_str}")
                next_run_local = local_naive.replace(tzinfo=tz)
                # If time already passed today, move to tomorrow
                if next_run_local <= now_local:
                    next_run_local += timedelta(days=1)
            except Exception:
                raise HTTPException(status_code=400, detail="Invalid time format")

        next_run_at = next_run_local.astimezone(timezone.utc)

    # 🛡️ Optional Permission Check
    if request.test_permissions and "aws" in request.providers:
        logger.info(f"🛡️ Testing AWS permissions for user={user_id} before scheduling...")
        try:
            await initialize_mcp_servers_for_user(user_id, ["aws"], request.credential_id)
        except Exception as e:
            if hasattr(e, 'iam_user_arn') and hasattr(e, 'recommended_policy_arn'):
                logger.warning(f"🛡️ Permission check failed for user: {e.iam_user_arn}")

                # Fetch credential for ID
                if request.credential_id:
                    aws_cred = credential_manager.get_credential_by_id(user_id, request.credential_id)
                else:
                    aws_cred = credential_manager.get_default_credential(user_id, "aws")
                cred_id = aws_cred.id if aws_cred else None

                iam_user_name = e.iam_user_arn.split('/')[-1] if '/' in e.iam_user_arn else e.iam_user_arn

                return JSONResponse(
                    status_code=200,
                    content={
                        "status": "permission_required",
                        "permission_error": {
                            "type": "missing_assume_role_permission",
                            "iam_user_name": iam_user_name,
                            "iam_user_arn": e.iam_user_arn,
                            "role_arn": getattr(e, 'role_arn', None),
                            "policy_arn": e.recommended_policy_arn,
                            "credential_id": cred_id,
                            "can_auto_grant": True
                        }
                    }
                )
            logger.error(f"❌ Permission test failed: {e}")
            # We don't block other errors, just the specific 'AccessDenied' one we can fix

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_schedules
            (user_id, providers, account_ids, deep_scan, schedule, status, next_run_at, credential_id, notify_email, email_address, created_at)
            VALUES (%s, %s, %s, %s, %s, 'scheduled', %s, %s, %s, %s, NOW())
            RETURNING id
            """,
            (
                user_id,
                json.dumps(request.providers),
                json.dumps(request.account_ids),
                request.deep_scan,
                Json(schedule),
                next_run_at,
                request.credential_id,
                request.notify_email,
                request.email_address,
            ),
        )
        schedule_id = cur.fetchone()[0]
        conn.commit()

    logger.info(f"✅ Schedule created in DB: id={schedule_id}, next_run_at={next_run_at}")
    return {
        "status": "scheduled",
        "schedule_id": schedule_id,
        "next_run_at": next_run_at.isoformat(),
    }

# Add this function near the top of main.py
def generate_dashboard_url(scan_ids: List[int]) -> str:
    """Generate dashboard URL with scan results"""
    if not scan_ids:
        return "/dashboard"

    if len(scan_ids) == 1:
        return f"/dashboard?scan_id={scan_ids[0]}"
    else:
        return f"/dashboard?scans={','.join(map(str, scan_ids))}"

# Add this helper function for scan completion
def format_scan_completion_response(scan_ids: List[int], scan_results: List[ScanResult], ai_analysis: dict):
    """Format standard scan completion response"""
    return {
        "status": "completed",
        "scan_ids": scan_ids,
        "dashboard_url": generate_dashboard_url(scan_ids),
        "timestamp": datetime.utcnow().isoformat(),
        "summary": {
            "total_resources": sum(len(r.resources) for r in scan_results),
            "total_findings": sum(len(r.findings) for r in scan_results),
            "providers_scanned": [r.provider for r in scan_results],
            "critical_findings": sum(
                len([f for f in r.findings if f.severity.value == "CRITICAL"])
                for r in scan_results
            ),
            "high_findings": sum(
                len([f for f in r.findings if f.severity.value == "HIGH"])
                for r in scan_results
            ),
        },
        "ai_analysis": ai_analysis,
        "next_steps": [
            "View detailed results in dashboard",
            "Download PDF report",
            "Get AI recommendations",
            "Schedule regular scans"
        ]
    }


SCAN_JOB_COLUMNS = """
    job_id, user_id, providers, account_ids, deep_scan, offensive_scan,
    credential_id, status, attempts, max_attempts, priority, scan_ids,
    result, error, queued_at, started_at, completed_at, updated_at,
    last_error, locked_at, worker_id
"""


def _iso_timestamp(value):
    if value is None:
        return None
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _scan_job_from_row(row) -> Optional[Dict[str, Any]]:
    if not row:
        return None

    return {
        "job_id": row[0],
        "user_id": row[1],
        "providers": row[2] or [],
        "account_ids": row[3] or {},
        "deep_scan": row[4],
        "offensive_scan": row[5],
        "credential_id": row[6],
        "status": row[7],
        "attempts": row[8],
        "max_attempts": row[9],
        "priority": row[10],
        "scan_ids": row[11] or [],
        "result": row[12],
        "error": row[13],
        "queued_at": _iso_timestamp(row[14]),
        "started_at": _iso_timestamp(row[15]),
        "completed_at": _iso_timestamp(row[16]),
        "updated_at": _iso_timestamp(row[17]),
        "last_error": row[18],
        "locked_at": _iso_timestamp(row[19]),
        "worker_id": row[20],
    }


def _request_tenant_id(req: Request, requested_tenant_id: Optional[str] = None, user_id: Optional[str] = None) -> str:
    tenant = requested_tenant_id or req.headers.get("x-cloudguard-tenant") or user_id or get_user_id(req)
    return str(tenant or "default").strip() or "default"


def _normalize_allowed(value: str, allowed: set[str], default: str) -> str:
    normalized = str(value or default).lower().strip()
    return normalized if normalized in allowed else default


def _bounded_int(value: Any, default: int = 0, minimum: int = 0, maximum: int = 100) -> int:
    try:
        number = int(float(value))
    except (TypeError, ValueError):
        number = default
    return max(minimum, min(maximum, number))


ASSET_CONTEXT_COLUMNS = """
    context_id, tenant_id, user_id, asset_ref, provider, asset_type,
    asset_name, business_criticality, internet_exposed, data_classification,
    environment, owner, tags, network_context, identity_context,
    custom_context, created_at, updated_at
"""


def _asset_context_from_row(row) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "context_id": row[0],
        "tenant_id": row[1],
        "user_id": row[2],
        "asset_ref": row[3],
        "provider": row[4],
        "asset_type": row[5],
        "asset_name": row[6],
        "business_criticality": row[7],
        "internet_exposed": row[8],
        "data_classification": row[9],
        "environment": row[10],
        "owner": row[11],
        "tags": row[12] or {},
        "network_context": row[13] or {},
        "identity_context": row[14] or {},
        "custom_context": row[15] or {},
        "created_at": _iso_timestamp(row[16]),
        "updated_at": _iso_timestamp(row[17]),
    }


def upsert_asset_risk_context(user_id: str, tenant_id: str, request: AssetRiskContextRequest) -> Dict[str, Any]:
    asset_ref = (request.asset_ref or "").strip()
    if not asset_ref:
        raise HTTPException(status_code=400, detail="asset_ref is required")

    business_criticality = _normalize_allowed(
        request.business_criticality,
        {"low", "medium", "high", "critical"},
        "medium",
    )
    data_classification = _normalize_allowed(
        request.data_classification,
        {"public", "internal", "confidential", "restricted", "regulated"},
        "internal",
    )
    context_id = f"ctx-{uuid.uuid4().hex}"
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO asset_risk_contexts (
                context_id, tenant_id, user_id, asset_ref, provider, asset_type,
                asset_name, business_criticality, internet_exposed,
                data_classification, environment, owner, tags, network_context,
                identity_context, custom_context
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (tenant_id, asset_ref) DO UPDATE SET
                user_id = EXCLUDED.user_id,
                provider = EXCLUDED.provider,
                asset_type = EXCLUDED.asset_type,
                asset_name = EXCLUDED.asset_name,
                business_criticality = EXCLUDED.business_criticality,
                internet_exposed = EXCLUDED.internet_exposed,
                data_classification = EXCLUDED.data_classification,
                environment = EXCLUDED.environment,
                owner = EXCLUDED.owner,
                tags = EXCLUDED.tags,
                network_context = EXCLUDED.network_context,
                identity_context = EXCLUDED.identity_context,
                custom_context = EXCLUDED.custom_context,
                updated_at = NOW()
            RETURNING {ASSET_CONTEXT_COLUMNS}
            """,
            (
                context_id,
                tenant_id,
                user_id,
                asset_ref,
                request.provider,
                request.asset_type,
                request.asset_name,
                business_criticality,
                request.internet_exposed,
                data_classification,
                request.environment or "unknown",
                request.owner,
                Json(request.tags or {}),
                Json(request.network_context or {}),
                Json(request.identity_context or {}),
                Json(request.custom_context or {}),
            ),
        )
        row = cur.fetchone()
        conn.commit()
    return _asset_context_from_row(row)


def list_asset_risk_contexts(user_id: str, tenant_id: str, asset_ref: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    limit = max(1, min(limit, 500))
    with conn.cursor() as cur:
        if asset_ref:
            cur.execute(
                f"""
                SELECT {ASSET_CONTEXT_COLUMNS}
                FROM asset_risk_contexts
                WHERE user_id = %s AND tenant_id = %s AND asset_ref = %s
                ORDER BY updated_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, asset_ref, limit),
            )
        else:
            cur.execute(
                f"""
                SELECT {ASSET_CONTEXT_COLUMNS}
                FROM asset_risk_contexts
                WHERE user_id = %s AND tenant_id = %s
                ORDER BY updated_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, limit),
            )
        rows = cur.fetchall()
    return [_asset_context_from_row(row) for row in rows]


def _finding_asset_ref(finding: Dict[str, Any]) -> str:
    for key in ("asset_ref", "resource_id", "resource", "resource_name", "resource_arn", "arn", "name", "target"):
        value = finding.get(key)
        if value:
            return str(value)
    return str(finding.get("id") or finding.get("finding_id") or finding.get("title") or "unknown")


def _score_finding_with_context(finding: Dict[str, Any], context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    severity = _normalize_severity(finding.get("severity") or finding.get("risk") or finding.get("level"))
    severity_score = {
        "critical": 70,
        "high": 55,
        "medium": 35,
        "low": 15,
        "info": 5,
    }.get(severity, 5)

    score = severity_score
    reasons = [f"severity={severity}"]

    cvss = finding.get("cvss_score") or finding.get("cvss")
    if cvss is not None:
        try:
            cvss_points = _bounded_int(float(cvss) * 4, default=0, maximum=40)
            score = max(score, cvss_points)
            reasons.append(f"cvss={cvss}")
        except (TypeError, ValueError):
            pass

    if finding.get("attack_path") or finding.get("attack_paths"):
        score += 12
        reasons.append("attack path present")
    if finding.get("validated") or finding.get("validation_status") == "validated":
        score += 15
        reasons.append("validated/reproducible")
    if finding.get("exploit_available") or finding.get("known_exploit"):
        score += 10
        reasons.append("known exploit available")

    if context:
        criticality = context.get("business_criticality", "medium")
        score += {"low": 0, "medium": 5, "high": 15, "critical": 25}.get(criticality, 5)
        reasons.append(f"business criticality={criticality}")

        if context.get("internet_exposed"):
            score += 15
            reasons.append("internet exposed")

        classification = context.get("data_classification", "internal")
        score += {"public": 0, "internal": 3, "confidential": 10, "restricted": 14, "regulated": 18}.get(classification, 3)
        reasons.append(f"data={classification}")

        identity_context = context.get("identity_context") or {}
        if identity_context.get("privileged_access") or identity_context.get("admin_role_count"):
            score += 10
            reasons.append("privileged identity access")

        network_context = context.get("network_context") or {}
        public_ports = {str(port) for port in network_context.get("public_ports", [])}
        if public_ports.intersection({"22", "3389", "5432", "3306", "6379", "27017"}):
            score += 8
            reasons.append("sensitive public port")

    score = _bounded_int(score, maximum=100)
    if score >= 85:
        priority = "critical"
    elif score >= 70:
        priority = "high"
    elif score >= 45:
        priority = "medium"
    else:
        priority = "low"

    return {
        "finding": finding,
        "asset_ref": _finding_asset_ref(finding),
        "severity": severity,
        "risk_score": score,
        "priority": priority,
        "context_applied": bool(context),
        "context": context,
        "reasoning": reasons,
    }


def prioritize_findings(user_id: str, tenant_id: str, request: FindingPrioritizationRequest) -> Dict[str, Any]:
    if not request.findings:
        raise HTTPException(status_code=400, detail="findings must contain at least one item")

    inline_contexts: Dict[str, Dict[str, Any]] = {}
    for item in request.asset_contexts:
        item_tenant = item.tenant_id or tenant_id
        context = upsert_asset_risk_context(user_id, item_tenant, item)
        inline_contexts[context["asset_ref"]] = context

    stored_contexts = {
        context["asset_ref"]: context
        for context in list_asset_risk_contexts(user_id, tenant_id, limit=500)
    }
    stored_contexts.update(inline_contexts)

    prioritized = [
        _score_finding_with_context(finding, stored_contexts.get(_finding_asset_ref(finding)))
        for finding in request.findings
    ]
    prioritized.sort(key=lambda item: item["risk_score"], reverse=True)

    return {
        "status": "ok",
        "tenant_id": tenant_id,
        "count": len(prioritized),
        "generated_at": datetime.utcnow().isoformat(),
        "top_actions": [
            {
                "finding_ref": item["finding"].get("id") or item["finding"].get("finding_id") or item["asset_ref"],
                "priority": item["priority"],
                "risk_score": item["risk_score"],
                "recommendation": item["finding"].get("recommendation") or item["finding"].get("remediation"),
            }
            for item in prioritized[:5]
        ],
        "prioritized_findings": prioritized,
    }


VALIDATION_JOB_COLUMNS = """
    validation_id, tenant_id, user_id, finding_ref, job_id, evidence_id,
    asset_ref, validation_type, status, safety_guardrails, request_payload,
    proof_payload, proof_uri, result_summary, requested_by, created_at,
    started_at, completed_at, expires_at, updated_at
"""


def _validation_job_from_row(row) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "validation_id": row[0],
        "tenant_id": row[1],
        "user_id": row[2],
        "finding_ref": row[3],
        "job_id": row[4],
        "evidence_id": row[5],
        "asset_ref": row[6],
        "validation_type": row[7],
        "status": row[8],
        "safety_guardrails": row[9] or {},
        "request_payload": row[10] or {},
        "proof_payload": row[11] or {},
        "proof_uri": row[12],
        "result_summary": row[13],
        "requested_by": row[14],
        "created_at": _iso_timestamp(row[15]),
        "started_at": _iso_timestamp(row[16]),
        "completed_at": _iso_timestamp(row[17]),
        "expires_at": _iso_timestamp(row[18]),
        "updated_at": _iso_timestamp(row[19]),
    }


def create_validation_job(user_id: str, tenant_id: str, request: ValidationJobRequest) -> Dict[str, Any]:
    validation_type = _normalize_allowed(
        request.validation_type,
        {"sandbox", "configuration_recheck", "safe_probe", "iac_plan", "manual"},
        "sandbox",
    )
    ttl_minutes = max(1, min(request.ttl_minutes or 5, 240))
    guardrails = {
        "isolated_environment_required": True,
        "production_mutation_allowed": False,
        "ttl_minutes": ttl_minutes,
        "requires_cleanup": True,
        **(request.safety_guardrails or {}),
    }
    validation_id = f"val-{uuid.uuid4().hex}"
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO security_validation_jobs (
                validation_id, tenant_id, user_id, finding_ref, job_id, evidence_id,
                asset_ref, validation_type, status, safety_guardrails, request_payload,
                requested_by, expires_at
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'requested', %s, %s, %s, %s)
            RETURNING {VALIDATION_JOB_COLUMNS}
            """,
            (
                validation_id,
                tenant_id,
                user_id,
                request.finding_ref,
                request.job_id,
                request.evidence_id,
                request.asset_ref,
                validation_type,
                Json(guardrails),
                Json(request.request_payload or {}),
                request.requested_by,
                expires_at,
            ),
        )
        row = cur.fetchone()
        conn.commit()
    return _validation_job_from_row(row)


def list_validation_jobs(user_id: str, tenant_id: str, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    limit = max(1, min(limit, 500))
    with conn.cursor() as cur:
        if status:
            cur.execute(
                f"""
                SELECT {VALIDATION_JOB_COLUMNS}
                FROM security_validation_jobs
                WHERE user_id = %s AND tenant_id = %s AND status = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, status, limit),
            )
        else:
            cur.execute(
                f"""
                SELECT {VALIDATION_JOB_COLUMNS}
                FROM security_validation_jobs
                WHERE user_id = %s AND tenant_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, limit),
            )
        rows = cur.fetchall()
    return [_validation_job_from_row(row) for row in rows]


def update_validation_job(user_id: str, tenant_id: str, validation_id: str, request: ValidationJobUpdateRequest) -> Dict[str, Any]:
    status = _normalize_allowed(
        request.status,
        {"requested", "queued", "running", "validated", "not_reproducible", "unsafe", "failed", "expired", "cancelled"},
        "failed",
    )
    fields = [
        "status = %s",
        "proof_payload = %s",
        "proof_uri = %s",
        "result_summary = %s",
        "evidence_id = COALESCE(%s, evidence_id)",
        "updated_at = NOW()",
    ]
    params: List[Any] = [status, Json(request.proof_payload or {}), request.proof_uri, request.result_summary, request.evidence_id]
    if status == "running":
        fields.append("started_at = COALESCE(started_at, NOW())")
    if status in {"validated", "not_reproducible", "unsafe", "failed", "expired", "cancelled"}:
        fields.append("completed_at = NOW()")

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE security_validation_jobs
            SET {', '.join(fields)}
            WHERE validation_id = %s AND user_id = %s AND tenant_id = %s
            RETURNING {VALIDATION_JOB_COLUMNS}
            """,
            tuple(params + [validation_id, user_id, tenant_id]),
        )
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(status_code=404, detail="Validation job not found")
    return _validation_job_from_row(row)


REMEDIATION_ACTION_COLUMNS = """
    action_id, tenant_id, user_id, finding_ref, validation_id, mode, status,
    title, priority, risk_score, action_type, recommended_steps,
    automation_payload, rollback_plan, evidence_id, requested_by,
    approved_by, approval_note, created_at, approved_at, executed_at,
    completed_at, updated_at
"""


def _remediation_action_from_row(row) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "action_id": row[0],
        "tenant_id": row[1],
        "user_id": row[2],
        "finding_ref": row[3],
        "validation_id": row[4],
        "mode": row[5],
        "status": row[6],
        "title": row[7],
        "priority": row[8],
        "risk_score": row[9],
        "action_type": row[10],
        "recommended_steps": row[11] or [],
        "automation_payload": row[12] or {},
        "rollback_plan": row[13] or {},
        "evidence_id": row[14],
        "requested_by": row[15],
        "approved_by": row[16],
        "approval_note": row[17],
        "created_at": _iso_timestamp(row[18]),
        "approved_at": _iso_timestamp(row[19]),
        "executed_at": _iso_timestamp(row[20]),
        "completed_at": _iso_timestamp(row[21]),
        "updated_at": _iso_timestamp(row[22]),
    }


def create_remediation_action(user_id: str, tenant_id: str, request: RemediationActionRequest) -> Dict[str, Any]:
    mode = _normalize_allowed(request.mode, {"learn", "approve", "enforce"}, "learn")
    priority = _normalize_allowed(request.priority, {"low", "medium", "high", "critical"}, "medium")
    status = "proposed" if mode == "learn" else "pending_approval"
    action_id = f"rem-{uuid.uuid4().hex}"
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO remediation_actions (
                action_id, tenant_id, user_id, finding_ref, validation_id, mode,
                status, title, priority, risk_score, action_type,
                recommended_steps, automation_payload, rollback_plan,
                evidence_id, requested_by
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {REMEDIATION_ACTION_COLUMNS}
            """,
            (
                action_id,
                tenant_id,
                user_id,
                request.finding_ref,
                request.validation_id,
                mode,
                status,
                request.title,
                priority,
                _bounded_int(request.risk_score),
                request.action_type or "manual",
                Json(request.recommended_steps or []),
                Json(request.automation_payload or {}),
                Json(request.rollback_plan or {}),
                request.evidence_id,
                request.requested_by,
            ),
        )
        row = cur.fetchone()
        conn.commit()
    return _remediation_action_from_row(row)


def list_remediation_actions(user_id: str, tenant_id: str, status: Optional[str] = None, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    limit = max(1, min(limit, 500))
    with conn.cursor() as cur:
        if status:
            cur.execute(
                f"""
                SELECT {REMEDIATION_ACTION_COLUMNS}
                FROM remediation_actions
                WHERE user_id = %s AND tenant_id = %s AND status = %s
                ORDER BY risk_score DESC, created_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, status, limit),
            )
        else:
            cur.execute(
                f"""
                SELECT {REMEDIATION_ACTION_COLUMNS}
                FROM remediation_actions
                WHERE user_id = %s AND tenant_id = %s
                ORDER BY risk_score DESC, created_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, limit),
            )
        rows = cur.fetchall()
    return [_remediation_action_from_row(row) for row in rows]


def decide_remediation_action(user_id: str, tenant_id: str, action_id: str, request: RemediationDecisionRequest) -> Dict[str, Any]:
    decision = _normalize_allowed(
        request.decision,
        {"approve", "reject", "start", "complete", "fail", "rollback"},
        "reject",
    )
    status_by_decision = {
        "approve": "approved",
        "reject": "rejected",
        "start": "executing",
        "complete": "completed",
        "fail": "failed",
        "rollback": "rolled_back",
    }
    status = status_by_decision[decision]
    fields = [
        "status = %s",
        "approval_note = COALESCE(%s, approval_note)",
        "evidence_id = COALESCE(%s, evidence_id)",
        "updated_at = NOW()",
    ]
    params: List[Any] = [status, request.note, request.evidence_id]
    if decision == "approve":
        fields.extend(["approved_by = %s", "approved_at = NOW()"])
        params.append(request.approved_by)
    if decision == "start":
        fields.append("executed_at = NOW()")
    if decision in {"complete", "fail", "rollback"}:
        fields.append("completed_at = NOW()")

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE remediation_actions
            SET {', '.join(fields)}
            WHERE action_id = %s AND user_id = %s AND tenant_id = %s
            RETURNING {REMEDIATION_ACTION_COLUMNS}
            """,
            tuple(params + [action_id, user_id, tenant_id]),
        )
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(status_code=404, detail="Remediation action not found")
    return _remediation_action_from_row(row)


def _generate_stride_findings(scope: str, input_artifacts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    artifact_text = json.dumps(input_artifacts, default=str).lower()
    scope_text = scope.lower()
    combined = f"{scope_text} {artifact_text}"
    findings: List[Dict[str, Any]] = []

    def add(category: str, title: str, risk: str, mitigation: str, evidence_hint: str):
        findings.append(
            {
                "category": category,
                "title": title,
                "risk": risk,
                "mitigation": mitigation,
                "evidence_hint": evidence_hint,
            }
        )

    if any(term in combined for term in ("sso", "login", "iam", "keycloak", "credential", "token")):
        add(
            "Spoofing",
            "Identity boundary must be strongly authenticated",
            "high",
            "Require SSO/MFA, short-lived credentials, tenant-scoped sessions, and audit logs for every connector.",
            "Authentication config, credential vault policy, and login audit records.",
        )
        add(
            "Elevation of privilege",
            "Scanner credentials may cross privilege boundaries",
            "high",
            "Use least-privilege roles, external IDs, tenant scoped credential references, and approval before privileged remediation.",
            "IAM/Kubernetes RBAC evidence and credential validation output.",
        )

    if any(term in combined for term in ("api", "connector", "evidence", "ingest", "queue")):
        add(
            "Tampering",
            "Evidence ingestion can be modified before storage",
            "medium",
            "Validate JSON schema, require connector tokens, checksum artifacts, and store immutable evidence metadata.",
            "Evidence checksum, source system, and connector token audit records.",
        )
        add(
            "Repudiation",
            "External scan systems need traceable submissions",
            "medium",
            "Capture source system, tenant ID, job ID, user ID, timestamps, and artifact checksums.",
            "Evidence ingestion rows and connector logs.",
        )

    if any(term in combined for term in ("s3", "spaces", "minio", "database", "postgres", "artifact", "report")):
        add(
            "Information disclosure",
            "Reports and artifacts may contain sensitive cloud data",
            "high",
            "Encrypt object storage, restrict bucket access, redact secrets, and separate tenant evidence paths.",
            "Object storage policy, encryption settings, and artifact URI structure.",
        )

    if any(term in combined for term in ("worker", "scan", "kubernetes", "zap", "nuclei", "trivy", "cloudfox", "queue")):
        add(
            "Denial of service",
            "Long scanner workloads can exhaust shared compute",
            "medium",
            "Run scanners in worker services with queue limits, TTLs, retries, and per-tenant concurrency controls.",
            "scan_jobs status, worker logs, and resource usage screenshots.",
        )

    if not findings:
        add(
            "Spoofing",
            "Define identity trust boundaries for this scope",
            "medium",
            "Document users, services, connectors, and credential flows before production use.",
            "Architecture diagram and auth configuration.",
        )
        add(
            "Tampering",
            "Protect configuration and evidence from unauthorized changes",
            "medium",
            "Add schema validation, audit logs, checksums, and restricted write paths.",
            "Config review and evidence ingestion logs.",
        )
        add(
            "Information disclosure",
            "Classify data handled by this scope",
            "medium",
            "Classify evidence, reports, credentials, and logs; enforce encryption and tenant isolation.",
            "Data classification and storage policy.",
        )

    return findings


THREAT_MODEL_COLUMNS = """
    threat_model_id, tenant_id, user_id, scope, source_type, input_artifacts,
    stride_findings, summary, status, created_at, updated_at
"""


def _threat_model_from_row(row) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "threat_model_id": row[0],
        "tenant_id": row[1],
        "user_id": row[2],
        "scope": row[3],
        "source_type": row[4],
        "input_artifacts": row[5] or [],
        "stride_findings": row[6] or [],
        "summary": row[7] or {},
        "status": row[8],
        "created_at": _iso_timestamp(row[9]),
        "updated_at": _iso_timestamp(row[10]),
    }


def create_stride_threat_model(user_id: str, tenant_id: str, request: ThreatModelRequest) -> Dict[str, Any]:
    findings = _generate_stride_findings(request.scope, request.input_artifacts or [])
    summary = {
        "total_findings": len(findings),
        "high_risks": len([item for item in findings if item["risk"] == "high"]),
        "categories": sorted({item["category"] for item in findings}),
        "next_step": "Review findings with system owners, then attach evidence to mapped GRC controls.",
    }
    threat_model_id = f"tm-{uuid.uuid4().hex}"
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO threat_models (
                threat_model_id, tenant_id, user_id, scope, source_type,
                input_artifacts, stride_findings, summary, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'generated')
            RETURNING {THREAT_MODEL_COLUMNS}
            """,
            (
                threat_model_id,
                tenant_id,
                user_id,
                request.scope,
                request.source_type or "manual",
                Json(request.input_artifacts or []),
                Json(findings),
                Json(summary),
            ),
        )
        row = cur.fetchone()
        conn.commit()
    return _threat_model_from_row(row)


def list_threat_models(user_id: str, tenant_id: str, limit: int = 100) -> List[Dict[str, Any]]:
    conn = get_conn()
    limit = max(1, min(limit, 500))
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT {THREAT_MODEL_COLUMNS}
            FROM threat_models
            WHERE user_id = %s AND tenant_id = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (user_id, tenant_id, limit),
        )
        rows = cur.fetchall()
    return [_threat_model_from_row(row) for row in rows]


SANDBOX_LAB_COLUMNS = """
    lab_id, tenant_id, user_id, provider, lab_type, status, ttl_minutes,
    credential_id, region, namespace, resource_prefix, deploy_mode,
    auto_destroy, scan_after_deploy, scan_job_id, validation_id,
    evidence_id, remediation_action_id, request_payload, resources,
    findings, proof_payload, cleanup_payload, error, worker_id,
    created_at, started_at, deployed_at, scan_started_at, completed_at,
    destroyed_at, expires_at, updated_at
"""


def _sandbox_lab_from_row(row) -> Optional[Dict[str, Any]]:
    if not row:
        return None
    return {
        "lab_id": row[0],
        "tenant_id": row[1],
        "user_id": row[2],
        "provider": row[3],
        "lab_type": row[4],
        "status": row[5],
        "ttl_minutes": row[6],
        "credential_id": row[7],
        "region": row[8],
        "namespace": row[9],
        "resource_prefix": row[10],
        "deploy_mode": row[11],
        "auto_destroy": row[12],
        "scan_after_deploy": row[13],
        "scan_job_id": row[14],
        "validation_id": row[15],
        "evidence_id": row[16],
        "remediation_action_id": row[17],
        "request_payload": row[18] or {},
        "resources": row[19] or [],
        "findings": row[20] or [],
        "proof_payload": row[21] or {},
        "cleanup_payload": row[22] or {},
        "error": row[23],
        "worker_id": row[24],
        "created_at": _iso_timestamp(row[25]),
        "started_at": _iso_timestamp(row[26]),
        "deployed_at": _iso_timestamp(row[27]),
        "scan_started_at": _iso_timestamp(row[28]),
        "completed_at": _iso_timestamp(row[29]),
        "destroyed_at": _iso_timestamp(row[30]),
        "expires_at": _iso_timestamp(row[31]),
        "updated_at": _iso_timestamp(row[32]),
    }


def _sandbox_bool_env(name: str, default: str = "false") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _sandbox_labs_enabled() -> bool:
    return _sandbox_bool_env("SANDBOX_LABS_ENABLED", "true")


def _sandbox_provider_deploy_enabled(provider: str) -> bool:
    if provider == "iac":
        return _sandbox_bool_env("SANDBOX_IAC_DEPLOY", "true")
    return _sandbox_bool_env(f"SANDBOX_{provider.upper()}_DEPLOY", "false")


def _sandbox_base_dir() -> Path:
    return Path(os.getenv("SANDBOX_LAB_BASE_DIR", "/tmp/cloudguard-sandbox-labs")).resolve()


def _sandbox_lab_dir(lab_id: str) -> Path:
    return _sandbox_base_dir() / lab_id


def _sandbox_resource_prefix(lab_id: str) -> str:
    return f"cg-{lab_id.replace('lab-', '')[:12]}".lower()


def _sandbox_credential_ready(provider: str, user_id: Optional[str], credential_id: Optional[int] = None) -> Dict[str, Any]:
    if provider == "iac":
        return {"ready": True, "source": "credentialless", "reason": "IaC demo uses generated local files."}

    try:
        credential = None
        if user_id and credential_id:
            credential = credential_manager.get_credential_by_id(user_id, int(credential_id))
        elif user_id:
            credential = credential_manager.get_default_credential(user_id, provider)
    except Exception as exc:
        logger.warning(f"Could not check {provider} sandbox credential readiness: {exc}")
        credential = None

    if provider == "aws":
        if credential and credential.aws_access_key_id and credential.aws_secret_access_key:
            return {"ready": True, "source": "stored_default_credential", "reason": "AWS sandbox credential is available."}
        if os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY"):
            return {"ready": True, "source": "environment", "reason": "AWS environment credentials are available."}
        return {"ready": False, "source": None, "reason": "Add a default AWS sandbox credential before running the AWS demo."}

    if provider == "gcp":
        if credential and credential.gcp_service_account_json:
            return {"ready": True, "source": "stored_default_credential", "reason": "GCP sandbox service account is available."}
        return {"ready": False, "source": None, "reason": "Add a default GCP sandbox service account before running the GCP demo."}

    if provider == "kubernetes":
        if credential and credential.kubernetes_kubeconfig:
            return {"ready": True, "source": "stored_default_credential", "reason": "Kubernetes sandbox kubeconfig is available."}
        if os.getenv("KUBECONFIG"):
            return {"ready": True, "source": "environment", "reason": "KUBECONFIG is available in the worker environment."}
        return {"ready": False, "source": None, "reason": "Add a default Kubernetes sandbox kubeconfig before running the Kubernetes demo."}

    return {"ready": False, "source": None, "reason": f"Unsupported sandbox provider: {provider}"}


def _sandbox_provider_readiness(provider: str, user_id: Optional[str], credential_id: Optional[int] = None) -> Dict[str, Any]:
    flag_enabled = _sandbox_provider_deploy_enabled(provider)
    credential_status = _sandbox_credential_ready(provider, user_id, credential_id)
    enabled = flag_enabled and credential_status["ready"]
    reason = credential_status["reason"] if flag_enabled else (
        "Sandbox deployment is disabled for this provider. Enable the provider flag only for isolated testing accounts."
    )
    return {
        "enabled": enabled,
        "deployment_flag_enabled": flag_enabled,
        "credential_ready": credential_status["ready"],
        "credential_source": credential_status["source"],
        "reason": reason,
    }


def _sandbox_lab_catalog(user_id: Optional[str] = None) -> List[Dict[str, Any]]:
    iac_readiness = _sandbox_provider_readiness("iac", user_id)
    aws_readiness = _sandbox_provider_readiness("aws", user_id)
    gcp_readiness = _sandbox_provider_readiness("gcp", user_id)
    kubernetes_readiness = _sandbox_provider_readiness("kubernetes", user_id)
    return [
        {
            "provider": "iac",
            "lab_type": "misconfigured_iac",
            "cost": "zero",
            "deploys_real_cloud_resources": False,
            "tests": ["Terraform public storage", "open security group", "wildcard IAM", "privileged Kubernetes YAML"],
            **iac_readiness,
        },
        {
            "provider": "aws",
            "lab_type": "public_s3_and_wildcard_iam",
            "cost": "near-zero if destroyed quickly",
            "deploys_real_cloud_resources": True,
            "tests": ["S3 public policy", "disabled public access block", "wildcard IAM policy"],
            **aws_readiness,
        },
        {
            "provider": "gcp",
            "lab_type": "public_storage_bucket",
            "cost": "near-zero if destroyed quickly",
            "deploys_real_cloud_resources": True,
            "tests": ["public Cloud Storage IAM binding", "asset inventory visibility"],
            **gcp_readiness,
        },
        {
            "provider": "kubernetes",
            "lab_type": "privileged_namespace",
            "cost": "uses existing cluster capacity",
            "deploys_real_cloud_resources": True,
            "tests": ["privileged pod", "wildcard RBAC", "missing NetworkPolicy", "NodePort service"],
            **kubernetes_readiness,
        },
    ]


def add_sandbox_lab_event(lab_id: str, event_type: str, message: str = "", payload: Optional[Dict[str, Any]] = None) -> None:
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO sandbox_lab_events (event_id, lab_id, event_type, message, payload)
            VALUES (%s, %s, %s, %s, %s)
            """,
            (f"evlab-{uuid.uuid4().hex}", lab_id, event_type, message, Json(payload or {})),
        )
        conn.commit()


def update_sandbox_lab(lab_id: str, **updates) -> Dict[str, Any]:
    allowed = {
        "status", "deploy_mode", "scan_job_id", "validation_id", "evidence_id",
        "remediation_action_id", "resources", "findings", "proof_payload",
        "cleanup_payload", "error", "worker_id", "started_at", "deployed_at",
        "scan_started_at", "completed_at", "destroyed_at", "expires_at",
    }
    json_fields = {"resources", "findings", "proof_payload", "cleanup_payload"}
    fields = ["updated_at = NOW()"]
    params: List[Any] = []

    for key, value in updates.items():
        if key not in allowed:
            continue
        fields.append(f"{key} = %s")
        params.append(Json(value) if key in json_fields else value)

    params.append(lab_id)
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE sandbox_lab_runs
            SET {', '.join(fields)}
            WHERE lab_id = %s
            RETURNING {SANDBOX_LAB_COLUMNS}
            """,
            tuple(params),
        )
        row = cur.fetchone()
        conn.commit()
    if not row:
        raise HTTPException(status_code=404, detail="Sandbox lab not found")
    return _sandbox_lab_from_row(row)


def create_sandbox_lab_run(user_id: str, tenant_id: str, request: SandboxLabRequest) -> Dict[str, Any]:
    if not _sandbox_labs_enabled():
        raise HTTPException(status_code=403, detail="Sandbox labs are disabled. Set SANDBOX_LABS_ENABLED=true.")

    provider = _normalize_allowed(request.provider, {"aws", "gcp", "kubernetes", "iac"}, "iac")
    readiness = _sandbox_provider_readiness(provider, user_id, request.credential_id)
    if not readiness["enabled"]:
        raise HTTPException(status_code=403, detail=readiness["reason"])

    ttl_minutes = max(1, min(int(request.ttl_minutes or 5), 240))
    lab_id = f"lab-{uuid.uuid4().hex}"
    resource_prefix = _sandbox_resource_prefix(lab_id)
    expires_at = datetime.utcnow() + timedelta(minutes=ttl_minutes)
    request_payload = request.dict()

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO sandbox_lab_runs (
                lab_id, tenant_id, user_id, provider, lab_type, status,
                ttl_minutes, credential_id, region, namespace, resource_prefix,
                auto_destroy, scan_after_deploy, request_payload, expires_at
            )
            VALUES (%s, %s, %s, %s, %s, 'requested', %s, %s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING {SANDBOX_LAB_COLUMNS}
            """,
            (
                lab_id,
                tenant_id,
                user_id,
                provider,
                request.lab_type or "default",
                ttl_minutes,
                request.credential_id,
                request.region,
                request.namespace,
                resource_prefix,
                request.auto_destroy,
                request.scan_after_deploy,
                Json(request_payload),
                expires_at,
            ),
        )
        row = cur.fetchone()
        conn.commit()

    lab = _sandbox_lab_from_row(row)
    add_sandbox_lab_event(lab_id, "requested", f"{provider} sandbox lab requested", request_payload)
    return lab


def list_sandbox_labs(user_id: str, tenant_id: str, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    limit = max(1, min(limit, 200))
    conn = get_conn()
    with conn.cursor() as cur:
        if status:
            cur.execute(
                f"""
                SELECT {SANDBOX_LAB_COLUMNS}
                FROM sandbox_lab_runs
                WHERE user_id = %s AND tenant_id = %s AND status = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, status, limit),
            )
        else:
            cur.execute(
                f"""
                SELECT {SANDBOX_LAB_COLUMNS}
                FROM sandbox_lab_runs
                WHERE user_id = %s AND tenant_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (user_id, tenant_id, limit),
            )
        rows = cur.fetchall()
    return [_sandbox_lab_from_row(row) for row in rows]


def get_sandbox_lab_run(lab_id: str, user_id: Optional[str] = None, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    clauses = ["lab_id = %s"]
    params: List[Any] = [lab_id]
    if user_id:
        clauses.append("user_id = %s")
        params.append(user_id)
    if tenant_id:
        clauses.append("tenant_id = %s")
        params.append(tenant_id)

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT {SANDBOX_LAB_COLUMNS}
            FROM sandbox_lab_runs
            WHERE {' AND '.join(clauses)}
            """,
            tuple(params),
        )
        row = cur.fetchone()
    return _sandbox_lab_from_row(row)


def list_sandbox_lab_events(lab_id: str) -> List[Dict[str, Any]]:
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT event_id, event_type, message, payload, created_at
            FROM sandbox_lab_events
            WHERE lab_id = %s
            ORDER BY created_at ASC
            """,
            (lab_id,),
        )
        rows = cur.fetchall()
    return [
        {
            "event_id": row[0],
            "event_type": row[1],
            "message": row[2],
            "payload": row[3] or {},
            "created_at": _iso_timestamp(row[4]),
        }
        for row in rows
    ]


def claim_next_sandbox_lab() -> Optional[Dict[str, Any]]:
    worker_id = os.getenv("SANDBOX_LAB_WORKER_ID", f"sandbox-worker-{uuid.uuid4().hex[:12]}")
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE sandbox_lab_runs
            SET status = 'provisioning',
                started_at = COALESCE(started_at, NOW()),
                worker_id = %s,
                updated_at = NOW()
            WHERE lab_id = (
                SELECT lab_id
                FROM sandbox_lab_runs
                WHERE status = 'requested'
                  AND expires_at > NOW()
                ORDER BY created_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING {SANDBOX_LAB_COLUMNS}
            """,
            (worker_id,),
        )
        row = cur.fetchone()
        conn.commit()
    return _sandbox_lab_from_row(row)


def _credential_for_lab(lab: Dict[str, Any]) -> Optional[CloudCredential]:
    credential_id = lab.get("credential_id")
    provider = lab["provider"]
    if credential_id:
        return credential_manager.get_credential_by_id(lab["user_id"], int(credential_id))
    return credential_manager.get_default_credential(lab["user_id"], provider)


def _require_provider_enabled(provider: str) -> None:
    if not _sandbox_provider_deploy_enabled(provider):
        raise RuntimeError(
            f"{provider} sandbox deployment is disabled. Set SANDBOX_{provider.upper()}_DEPLOY=true "
            "only for an isolated testing account/project/cluster."
        )


def _sandbox_iac_files(prefix: str) -> List[Dict[str, str]]:
    terraform = f"""
terraform {{
  required_version = ">= 1.4.0"
}}

provider "aws" {{
  region = "us-east-1"
}}

resource "aws_s3_bucket" "public_logs" {{
  bucket = "{prefix}-public-logs"
}}

resource "aws_s3_bucket_public_access_block" "public_logs" {{
  bucket                  = aws_s3_bucket.public_logs.id
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}}

resource "aws_s3_bucket_policy" "public_read" {{
  bucket = aws_s3_bucket.public_logs.id
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Principal = "*"
      Action = "s3:GetObject"
      Resource = "${{aws_s3_bucket.public_logs.arn}}/*"
    }}]
  }})
}}

resource "aws_security_group" "open_admin" {{
  name = "{prefix}-open-admin"
  ingress {{
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }}
}}

resource "aws_iam_policy" "wildcard_admin" {{
  name = "{prefix}-wildcard-admin"
  policy = jsonencode({{
    Version = "2012-10-17"
    Statement = [{{
      Effect = "Allow"
      Action = "*"
      Resource = "*"
    }}]
  }})
}}
""".strip()

    kubernetes = f"""
apiVersion: v1
kind: Namespace
metadata:
  name: {prefix}
---
apiVersion: v1
kind: Pod
metadata:
  name: privileged-demo
  namespace: {prefix}
spec:
  containers:
    - name: pause
      image: registry.k8s.io/pause:3.9
      securityContext:
        privileged: true
  hostNetwork: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: wildcard-role
  namespace: {prefix}
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: ["*"]
---
apiVersion: v1
kind: Service
metadata:
  name: exposed-nodeport
  namespace: {prefix}
spec:
  type: NodePort
  selector:
    app: missing-selector
  ports:
    - port: 80
      targetPort: 8080
""".strip()

    return [
        {"filename": "sandbox_public_storage.tf", "content": terraform},
        {"filename": "sandbox_privileged_kubernetes.yaml", "content": kubernetes},
    ]


async def _deploy_iac_sandbox_lab(lab: Dict[str, Any]) -> Dict[str, Any]:
    _require_provider_enabled("iac")
    lab_dir = _sandbox_lab_dir(lab["lab_id"])
    lab_dir.mkdir(parents=True, exist_ok=True)
    files = _sandbox_iac_files(lab["resource_prefix"])

    for item in files:
        (lab_dir / item["filename"]).write_text(item["content"], encoding="utf-8")

    result_data: Dict[str, Any] = {"findings": [], "resources": [], "errors": []}
    scan_id = None
    response: Dict[str, Any] = {}
    try:
        server = create_iac_server({"root_path": os.getcwd()})
        result_data = await server._full_scan(
            account_id=f"sandbox-{lab['lab_id']}",
            deep_scan=True,
            files=files,
        )
        scan_result = _mcp_to_scan_result("iac", result_data)
        scan_id = await store_scan_result(scan_result)
        response = format_scan_completion_response([scan_id], [scan_result], {})
    except Exception as exc:
        logger.warning(f"IaC sandbox scan failed, storing generated files as proof only: {exc}")
        result_data["errors"] = [str(exc)]

    findings = result_data.get("findings") or []
    resources = [
        {
            "type": "local_iac_file",
            "name": item["filename"],
            "path": str(lab_dir / item["filename"]),
            "size_bytes": len(item["content"].encode("utf-8")),
        }
        for item in files
    ]
    proof_payload = {
        "scan_id": scan_id,
        "generated_files": [{"filename": item["filename"], "size_bytes": len(item["content"].encode("utf-8"))} for item in files],
        "scan_result": response,
        "raw_result_summary": result_data.get("summary", {}),
        "errors": result_data.get("errors", []),
    }
    return {
        "deploy_mode": "local_iac_files",
        "resources": resources,
        "findings": findings,
        "proof_payload": proof_payload,
    }


def _aws_session_for_lab(lab: Dict[str, Any], require_enabled: bool = True):
    if require_enabled:
        _require_provider_enabled("aws")
    credential = _credential_for_lab(lab)
    region = lab.get("region") or getattr(credential, "aws_region", None) or os.getenv("AWS_REGION") or "us-east-1"
    try:
        import boto3
    except ImportError as exc:
        raise RuntimeError("boto3 is required for AWS sandbox labs") from exc

    kwargs: Dict[str, Any] = {"region_name": region}
    if credential and credential.aws_access_key_id and credential.aws_secret_access_key:
        kwargs.update(
            {
                "aws_access_key_id": credential.aws_access_key_id,
                "aws_secret_access_key": credential.aws_secret_access_key,
                "aws_session_token": credential.aws_session_token,
            }
        )
    return boto3.Session(**kwargs), region


async def _deploy_aws_sandbox_lab(lab: Dict[str, Any]) -> Dict[str, Any]:
    session, region = _aws_session_for_lab(lab)
    sts = session.client("sts")
    s3 = session.client("s3")
    iam = session.client("iam")
    account_id = sts.get_caller_identity().get("Account", "unknown")
    suffix = uuid.uuid4().hex[:8]
    bucket_name = f"{lab['resource_prefix']}-{suffix}".replace("_", "-")[:63]
    role_name = f"{lab['resource_prefix']}-wildcard-role-{suffix}"[:64]
    resources: List[Dict[str, Any]] = []

    try:
        create_bucket_kwargs: Dict[str, Any] = {"Bucket": bucket_name}
        if region != "us-east-1":
            create_bucket_kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
        s3.create_bucket(**create_bucket_kwargs)
        resources.append({"type": "s3_bucket", "name": bucket_name, "region": region})

        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            },
        )
        s3.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "SandboxPublicRead",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::{bucket_name}/*",
                        }
                    ],
                }
            ),
        )

        iam.create_role(
            RoleName=role_name,
            AssumeRolePolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole",
                        }
                    ],
                }
            ),
            Tags=[{"Key": "cloudguard-lab-id", "Value": lab["lab_id"]}],
        )
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="CloudGuardSandboxWildcard",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
                }
            ),
        )
        resources.append({"type": "iam_role", "name": role_name, "region": "global"})
    except Exception:
        try:
            _destroy_aws_sandbox_resources(lab, resources)
        except Exception as cleanup_exc:
            logger.warning(f"Partial AWS sandbox cleanup failed: {cleanup_exc}")
        raise

    findings = [
        {
            "severity": "HIGH",
            "issue": "Public S3 bucket policy created for scanner validation",
            "resource": bucket_name,
            "expected_detection": "public bucket policy / public access block disabled",
        },
        {
            "severity": "CRITICAL",
            "issue": "Wildcard IAM policy created for scanner validation",
            "resource": role_name,
            "expected_detection": "overly permissive IAM role inline policy",
        },
    ]
    return {
        "deploy_mode": "aws_api",
        "account_id": account_id,
        "resources": resources,
        "findings": findings,
        "proof_payload": {"account_id": account_id, "region": region, "created_resources": resources},
    }


def _destroy_aws_sandbox_resources(lab: Dict[str, Any], resources: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    session, _region = _aws_session_for_lab(lab, require_enabled=False)
    s3 = session.client("s3")
    iam = session.client("iam")
    deleted: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for resource in resources or lab.get("resources", []):
        try:
            if resource.get("type") == "s3_bucket":
                bucket = resource["name"]
                try:
                    s3.delete_bucket_policy(Bucket=bucket)
                except Exception:
                    pass
                try:
                    s3.put_public_access_block(
                        Bucket=bucket,
                        PublicAccessBlockConfiguration={
                            "BlockPublicAcls": True,
                            "IgnorePublicAcls": True,
                            "BlockPublicPolicy": True,
                            "RestrictPublicBuckets": True,
                        },
                    )
                except Exception:
                    pass
                s3.delete_bucket(Bucket=bucket)
                deleted.append(resource)
            elif resource.get("type") == "iam_role":
                role_name = resource["name"]
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName="CloudGuardSandboxWildcard")
                except Exception:
                    pass
                iam.delete_role(RoleName=role_name)
                deleted.append(resource)
        except Exception as exc:
            errors.append({"resource": resource, "error": str(exc)})
    return {"deleted": deleted, "errors": errors}


async def _deploy_gcp_sandbox_lab(lab: Dict[str, Any]) -> Dict[str, Any]:
    _require_provider_enabled("gcp")
    credential = _credential_for_lab(lab)
    if not credential or not credential.gcp_service_account_json:
        raise RuntimeError("A GCP service account credential is required for GCP sandbox labs.")
    try:
        from google.cloud import storage
        from google.oauth2 import service_account
    except ImportError as exc:
        raise RuntimeError("google-cloud-storage is required for GCP sandbox labs") from exc

    info = json.loads(credential.gcp_service_account_json)
    project_id = credential.gcp_project_id or info.get("project_id")
    if not project_id:
        raise RuntimeError("GCP project_id is required for GCP sandbox labs.")

    creds = service_account.Credentials.from_service_account_info(info)
    client = storage.Client(project=project_id, credentials=creds)
    location = (lab.get("region") or os.getenv("GCP_SANDBOX_LOCATION") or "ASIA-SOUTH1").upper()
    bucket_name = f"{lab['resource_prefix']}-{uuid.uuid4().hex[:8]}".replace("_", "-")
    bucket = client.bucket(bucket_name)
    bucket.storage_class = "STANDARD"
    bucket = client.create_bucket(bucket, location=location)
    policy = bucket.get_iam_policy(requested_policy_version=3)
    policy.bindings.append({"role": "roles/storage.objectViewer", "members": {"allUsers"}})
    bucket.set_iam_policy(policy)

    resources = [{"type": "gcs_bucket", "name": bucket_name, "project_id": project_id, "location": location}]
    findings = [
        {
            "severity": "HIGH",
            "issue": "Public GCS bucket IAM binding created for scanner validation",
            "resource": bucket_name,
            "expected_detection": "allUsers has storage object viewer access",
        }
    ]
    return {
        "deploy_mode": "gcp_api",
        "account_id": project_id,
        "resources": resources,
        "findings": findings,
        "proof_payload": {"project_id": project_id, "location": location, "created_resources": resources},
    }


def _destroy_gcp_sandbox_resources(lab: Dict[str, Any]) -> Dict[str, Any]:
    credential = _credential_for_lab(lab)
    if not credential or not credential.gcp_service_account_json:
        raise RuntimeError("A GCP service account credential is required for GCP sandbox cleanup.")
    try:
        from google.cloud import storage
        from google.oauth2 import service_account
    except ImportError as exc:
        raise RuntimeError("google-cloud-storage is required for GCP sandbox cleanup") from exc

    info = json.loads(credential.gcp_service_account_json)
    project_id = credential.gcp_project_id or info.get("project_id")
    creds = service_account.Credentials.from_service_account_info(info)
    client = storage.Client(project=project_id, credentials=creds)
    deleted: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    for resource in lab.get("resources", []):
        try:
            if resource.get("type") == "gcs_bucket":
                bucket = client.bucket(resource["name"])
                bucket.delete(force=True)
                deleted.append(resource)
        except Exception as exc:
            errors.append({"resource": resource, "error": str(exc)})
    return {"deleted": deleted, "errors": errors}


def _kube_clients_for_lab(lab: Dict[str, Any], require_enabled: bool = True):
    if require_enabled:
        _require_provider_enabled("kubernetes")
    try:
        from kubernetes import client, config
    except ImportError as exc:
        raise RuntimeError("kubernetes Python package is required for Kubernetes sandbox labs.") from exc

    credential = _credential_for_lab(lab)
    context = getattr(credential, "kubernetes_context", None) if credential else None
    if credential and credential.kubernetes_kubeconfig:
        lab_dir = _sandbox_lab_dir(lab["lab_id"])
        lab_dir.mkdir(parents=True, exist_ok=True)
        kubeconfig_path = lab_dir / "kubeconfig"
        kubeconfig_path.write_text(credential.kubernetes_kubeconfig, encoding="utf-8")
        config.load_kube_config(config_file=str(kubeconfig_path), context=context)
    elif os.getenv("KUBECONFIG"):
        config.load_kube_config(config_file=os.getenv("KUBECONFIG"), context=context)
    else:
        try:
            config.load_incluster_config()
        except Exception as exc:
            raise RuntimeError("KUBECONFIG, stored Kubernetes credential, or in-cluster config is required.") from exc

    api_client = client.ApiClient()
    return api_client, client.CoreV1Api(api_client), client.RbacAuthorizationV1Api(api_client)


def _create_kubernetes_object(core_api, rbac_api, namespace: str, obj: Dict[str, Any]) -> None:
    try:
        from kubernetes.client.exceptions import ApiException
    except ImportError:
        ApiException = Exception

    kind = obj.get("kind")
    metadata = obj.get("metadata", {})
    name = metadata.get("name")
    try:
        if kind == "Namespace":
            core_api.create_namespace(body=obj)
        elif kind == "Pod":
            core_api.create_namespaced_pod(namespace=metadata.get("namespace") or namespace, body=obj)
        elif kind == "Service":
            core_api.create_namespaced_service(namespace=metadata.get("namespace") or namespace, body=obj)
        elif kind == "Role":
            rbac_api.create_namespaced_role(namespace=metadata.get("namespace") or namespace, body=obj)
        elif kind == "RoleBinding":
            rbac_api.create_namespaced_role_binding(namespace=metadata.get("namespace") or namespace, body=obj)
        else:
            raise RuntimeError(f"Unsupported Kubernetes sandbox object kind: {kind}")
    except ApiException as exc:
        if getattr(exc, "status", None) == 409:
            logger.info(f"Kubernetes sandbox object already exists: {kind}/{name}")
            return
        raise


async def _deploy_kubernetes_sandbox_lab(lab: Dict[str, Any]) -> Dict[str, Any]:
    _api_client, core_api, rbac_api = _kube_clients_for_lab(lab)
    namespace = (lab.get("namespace") or lab["resource_prefix"]).lower()
    manifest = _sandbox_iac_files(namespace)[1]["content"]
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError("PyYAML is required for Kubernetes sandbox labs.") from exc

    for obj in yaml.safe_load_all(manifest):
        if obj:
            _create_kubernetes_object(core_api, rbac_api, namespace, obj)

    resources = [
        {"type": "namespace", "name": namespace},
        {"type": "pod", "name": "privileged-demo", "namespace": namespace},
        {"type": "role", "name": "wildcard-role", "namespace": namespace},
        {"type": "service", "name": "exposed-nodeport", "namespace": namespace},
    ]
    findings = [
        {
            "severity": "CRITICAL",
            "issue": "Privileged pod with hostNetwork created for scanner validation",
            "resource": f"{namespace}/privileged-demo",
            "expected_detection": "privileged container / host networking",
        },
        {
            "severity": "HIGH",
            "issue": "Wildcard RBAC role created for scanner validation",
            "resource": f"{namespace}/wildcard-role",
            "expected_detection": "overly permissive namespace RBAC",
        },
    ]
    return {
        "deploy_mode": "kubernetes_client",
        "account_id": namespace,
        "resources": resources,
        "findings": findings,
        "proof_payload": {"namespace": namespace, "created_resources": resources},
    }


def _destroy_kubernetes_sandbox_resources(lab: Dict[str, Any]) -> Dict[str, Any]:
    _api_client, core_api, _rbac_api = _kube_clients_for_lab(lab, require_enabled=False)
    namespace = lab.get("namespace") or next(
        (item.get("name") for item in lab.get("resources", []) if item.get("type") == "namespace"),
        lab["resource_prefix"],
    )
    deleted: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    try:
        try:
            from kubernetes.client.exceptions import ApiException
        except ImportError:
            ApiException = Exception
        try:
            core_api.delete_namespace(name=namespace)
        except ApiException as exc:
            if getattr(exc, "status", None) != 404:
                raise
        deleted.append({"type": "namespace", "name": namespace})
    except Exception as exc:
        errors.append({"resource": {"type": "namespace", "name": namespace}, "error": str(exc)})
    return {"deleted": deleted, "errors": errors}


async def _deploy_sandbox_lab(lab: Dict[str, Any]) -> Dict[str, Any]:
    provider = lab["provider"]
    if provider == "iac":
        return await _deploy_iac_sandbox_lab(lab)
    if provider == "aws":
        return await _deploy_aws_sandbox_lab(lab)
    if provider == "gcp":
        return await _deploy_gcp_sandbox_lab(lab)
    if provider == "kubernetes":
        return await _deploy_kubernetes_sandbox_lab(lab)
    raise RuntimeError(f"Unsupported sandbox provider: {provider}")


def _destroy_sandbox_lab_resources(lab: Dict[str, Any]) -> Dict[str, Any]:
    provider = lab["provider"]
    if provider == "iac":
        lab_dir = _sandbox_lab_dir(lab["lab_id"])
        existed = lab_dir.exists()
        shutil.rmtree(lab_dir, ignore_errors=True)
        return {"deleted": [{"type": "local_iac_dir", "path": str(lab_dir), "existed": existed}], "errors": []}
    if provider == "aws":
        return _destroy_aws_sandbox_resources(lab)
    if provider == "gcp":
        return _destroy_gcp_sandbox_resources(lab)
    if provider == "kubernetes":
        return _destroy_kubernetes_sandbox_resources(lab)
    raise RuntimeError(f"Unsupported sandbox provider: {provider}")


def _record_sandbox_evidence_and_workflow(lab: Dict[str, Any], deployment: Dict[str, Any]) -> Dict[str, Any]:
    finding_ref = f"sandbox.{lab['provider']}.{lab['lab_type']}.{lab['lab_id']}"
    proof_payload = {
        "lab_id": lab["lab_id"],
        "provider": lab["provider"],
        "lab_type": lab["lab_type"],
        "deploy_mode": deployment.get("deploy_mode"),
        "resources": deployment.get("resources", []),
        "expected_findings": deployment.get("findings", []),
        "proof": deployment.get("proof_payload", {}),
        "expires_at": lab["expires_at"],
        "auto_destroy": lab["auto_destroy"],
    }
    evidence = store_evidence_artifact(
        lab["user_id"],
        EvidenceIngestionRequest(
            control_id=f"sandbox.{lab['provider']}",
            control_name=f"{lab['provider'].upper()} sandbox lab validation",
            source_system="CloudGuard Sandbox Lab",
            scanner_type=lab["provider"],
            artifact_type="sandbox_lab_proof",
            filename=f"{lab['lab_id']}.json",
            payload=proof_payload,
            metadata={
                "tenant_id": lab["tenant_id"],
                "lab_id": lab["lab_id"],
                "provider": lab["provider"],
                "ttl_minutes": lab["ttl_minutes"],
            },
        ),
    )

    validation = create_validation_job(
        lab["user_id"],
        lab["tenant_id"],
        ValidationJobRequest(
            finding_ref=finding_ref,
            evidence_id=evidence["evidence_id"],
            asset_ref=deployment.get("account_id") or lab["resource_prefix"],
            validation_type="sandbox",
            ttl_minutes=lab["ttl_minutes"],
            requested_by=lab["request_payload"].get("requested_by"),
            request_payload={
                "lab_id": lab["lab_id"],
                "provider": lab["provider"],
                "resources": deployment.get("resources", []),
            },
        ),
    )
    validation = update_validation_job(
        lab["user_id"],
        lab["tenant_id"],
        validation["validation_id"],
        ValidationJobUpdateRequest(
            status="validated",
            evidence_id=evidence["evidence_id"],
            proof_payload=proof_payload,
            result_summary=f"Sandbox lab {lab['lab_id']} deployed and proof captured.",
        ),
    )

    remediation = create_remediation_action(
        lab["user_id"],
        lab["tenant_id"],
        RemediationActionRequest(
            finding_ref=finding_ref,
            validation_id=validation["validation_id"],
            mode="enforce" if lab["auto_destroy"] else "approve",
            title=f"Destroy sandbox lab {lab['lab_id']}",
            priority="high",
            risk_score=90,
            action_type="sandbox_cleanup",
            evidence_id=evidence["evidence_id"],
            requested_by=lab["request_payload"].get("requested_by"),
            recommended_steps=[
                {"step": "Delete all tagged/namespaced sandbox resources", "automated": True},
                {"step": "Store cleanup proof in evidence", "automated": True},
            ],
            automation_payload={"lab_id": lab["lab_id"], "provider": lab["provider"], "resources": deployment.get("resources", [])},
            rollback_plan={"rollback_available": False, "reason": "Sandbox resources are intentionally temporary."},
        ),
    )
    if lab["auto_destroy"]:
        remediation = decide_remediation_action(
            lab["user_id"],
            lab["tenant_id"],
            remediation["action_id"],
            RemediationDecisionRequest(
                decision="approve",
                approved_by="sandbox-lab-orchestrator",
                note="Auto-destroy approved by sandbox lab request.",
                evidence_id=evidence["evidence_id"],
            ),
        )

    return {
        "evidence_id": evidence["evidence_id"],
        "validation_id": validation["validation_id"],
        "remediation_action_id": remediation["action_id"],
        "proof_payload": proof_payload,
    }


def _queue_sandbox_scan_job(lab: Dict[str, Any], deployment: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not lab["scan_after_deploy"] or lab["provider"] == "iac":
        return None
    account_id = deployment.get("account_id") or lab["resource_prefix"]
    job = create_scan_job(
        lab["user_id"],
        MultiCloudScanRequest(
            providers=[lab["provider"]],
            account_ids={lab["provider"]: account_id},
            deep_scan=True,
            offensive_scan=True,
            user_id=lab["user_id"],
            credential_id=lab["credential_id"],
        ),
    )
    return job


async def process_sandbox_lab(lab: Dict[str, Any]) -> Dict[str, Any]:
    add_sandbox_lab_event(lab["lab_id"], "provisioning", "Sandbox lab provisioning started")
    try:
        deployment = await _deploy_sandbox_lab(lab)
        lab = update_sandbox_lab(
            lab["lab_id"],
            status="deployed",
            deploy_mode=deployment.get("deploy_mode", "api"),
            resources=deployment.get("resources", []),
            findings=deployment.get("findings", []),
            proof_payload=deployment.get("proof_payload", {}),
            deployed_at=datetime.utcnow(),
            error=None,
        )
        add_sandbox_lab_event(lab["lab_id"], "deployed", "Sandbox lab resources deployed", deployment)

        workflow = _record_sandbox_evidence_and_workflow(lab, deployment)
        lab = update_sandbox_lab(
            lab["lab_id"],
            evidence_id=workflow["evidence_id"],
            validation_id=workflow["validation_id"],
            remediation_action_id=workflow["remediation_action_id"],
            proof_payload=workflow["proof_payload"],
        )

        scan_job = _queue_sandbox_scan_job(lab, deployment)
        if scan_job:
            lab = update_sandbox_lab(
                lab["lab_id"],
                status="scanning",
                scan_job_id=scan_job["job_id"],
                scan_started_at=datetime.utcnow(),
            )
            add_sandbox_lab_event(lab["lab_id"], "scan_queued", "Scanner job queued for sandbox lab", {"job_id": scan_job["job_id"]})
        else:
            lab = update_sandbox_lab(lab["lab_id"], status="scan_completed", completed_at=datetime.utcnow())
            add_sandbox_lab_event(lab["lab_id"], "scan_completed", "Sandbox lab proof captured without a separate scan job")

        if lab["auto_destroy"] and not scan_job:
            lab = await destroy_sandbox_lab(lab["lab_id"], lab["user_id"], lab["tenant_id"], reason="scan_completed")
        return lab
    except Exception as exc:
        logger.exception(f"Sandbox lab {lab['lab_id']} failed")
        failed_lab = update_sandbox_lab(
            lab["lab_id"],
            status="failed",
            error=str(exc),
            completed_at=datetime.utcnow(),
        )
        add_sandbox_lab_event(lab["lab_id"], "failed", str(exc))
        if failed_lab["auto_destroy"] and failed_lab.get("resources"):
            try:
                await destroy_sandbox_lab(failed_lab["lab_id"], failed_lab["user_id"], failed_lab["tenant_id"], reason="failed_cleanup")
            except Exception as cleanup_exc:
                logger.warning(f"Failed lab cleanup also failed for {failed_lab['lab_id']}: {cleanup_exc}")
        return failed_lab


async def destroy_sandbox_lab(
    lab_id: str,
    user_id: Optional[str] = None,
    tenant_id: Optional[str] = None,
    reason: str = "manual_destroy",
) -> Dict[str, Any]:
    lab = get_sandbox_lab_run(lab_id, user_id=user_id, tenant_id=tenant_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Sandbox lab not found")
    if lab["status"] in {"destroyed", "cancelled"}:
        return lab

    add_sandbox_lab_event(lab_id, "destroying", f"Destroying sandbox lab: {reason}")
    lab = update_sandbox_lab(lab_id, status="destroying")
    if lab.get("remediation_action_id"):
        try:
            decide_remediation_action(
                lab["user_id"],
                lab["tenant_id"],
                lab["remediation_action_id"],
                RemediationDecisionRequest(decision="start", note=f"Sandbox cleanup started: {reason}"),
            )
        except Exception as exc:
            logger.warning(f"Could not mark sandbox remediation as executing: {exc}")

    cleanup = _destroy_sandbox_lab_resources(lab)
    evidence_payload = {
        "lab_id": lab_id,
        "provider": lab["provider"],
        "reason": reason,
        "cleanup": cleanup,
        "destroyed_at": datetime.utcnow().isoformat(),
    }
    cleanup_evidence = store_evidence_artifact(
        lab["user_id"],
        EvidenceIngestionRequest(
            control_id=f"sandbox.{lab['provider']}.cleanup",
            control_name=f"{lab['provider'].upper()} sandbox cleanup proof",
            source_system="CloudGuard Sandbox Lab",
            scanner_type=lab["provider"],
            artifact_type="sandbox_cleanup_proof",
            filename=f"{lab_id}-cleanup.json",
            payload=evidence_payload,
            metadata={"tenant_id": lab["tenant_id"], "lab_id": lab_id, "reason": reason},
        ),
    )

    if lab.get("remediation_action_id"):
        try:
            decide_remediation_action(
                lab["user_id"],
                lab["tenant_id"],
                lab["remediation_action_id"],
                RemediationDecisionRequest(
                    decision="complete" if not cleanup.get("errors") else "fail",
                    note="Sandbox cleanup finished" if not cleanup.get("errors") else "Sandbox cleanup finished with errors",
                    evidence_id=cleanup_evidence["evidence_id"],
                    result_payload=evidence_payload,
                ),
            )
        except Exception as exc:
            logger.warning(f"Could not finalize sandbox remediation action: {exc}")

    final_status = "destroyed" if not cleanup.get("errors") else "failed"
    lab = update_sandbox_lab(
        lab_id,
        status=final_status,
        cleanup_payload=evidence_payload,
        destroyed_at=datetime.utcnow() if final_status == "destroyed" else None,
        completed_at=datetime.utcnow(),
        error=json.dumps(cleanup.get("errors")) if cleanup.get("errors") else None,
    )
    add_sandbox_lab_event(lab_id, final_status, "Sandbox cleanup completed", evidence_payload)
    return lab


async def reconcile_sandbox_labs() -> Dict[str, Any]:
    conn = get_conn()
    labs_to_destroy: List[Dict[str, Any]] = []
    expired_requested = 0

    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT {SANDBOX_LAB_COLUMNS}
            FROM sandbox_lab_runs
            WHERE status IN ('requested','provisioning','deployed','scanning','scan_completed','completed','failed')
              AND expires_at <= NOW()
            ORDER BY expires_at ASC
            LIMIT 25
            """
        )
        expired_rows = cur.fetchall()

    for row in expired_rows:
        lab = _sandbox_lab_from_row(row)
        if lab["status"] == "requested":
            update_sandbox_lab(lab["lab_id"], status="expired", completed_at=datetime.utcnow(), error="Lab request expired before provisioning.")
            add_sandbox_lab_event(lab["lab_id"], "expired", "Lab request expired before provisioning")
            expired_requested += 1
        elif lab["auto_destroy"]:
            labs_to_destroy.append(lab)

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            f"""
            SELECT {SANDBOX_LAB_COLUMNS}
            FROM sandbox_lab_runs
            WHERE status = 'scanning'
              AND scan_job_id IS NOT NULL
              AND auto_destroy = TRUE
            ORDER BY updated_at ASC
            LIMIT 25
            """
        )
        scanning_rows = cur.fetchall()

    for row in scanning_rows:
        lab = _sandbox_lab_from_row(row)
        job = get_scan_job(lab["scan_job_id"])
        if job and job["status"] in {"completed", "failed", "dead_letter", "cancelled"}:
            update_sandbox_lab(lab["lab_id"], status="scan_completed", completed_at=datetime.utcnow())
            add_sandbox_lab_event(
                lab["lab_id"],
                "scan_completed",
                f"Linked scan job finished with status {job['status']}",
                {"job_id": job["job_id"], "status": job["status"]},
            )
            labs_to_destroy.append(get_sandbox_lab_run(lab["lab_id"]) or lab)

    destroyed: List[str] = []
    errors: List[Dict[str, Any]] = []
    for lab in labs_to_destroy:
        try:
            await destroy_sandbox_lab(lab["lab_id"], lab["user_id"], lab["tenant_id"], reason="ttl_or_scan_completed")
            destroyed.append(lab["lab_id"])
        except Exception as exc:
            logger.warning(f"Sandbox cleanup failed for {lab['lab_id']}: {exc}")
            errors.append({"lab_id": lab["lab_id"], "error": str(exc)})

    return {"expired_requested": expired_requested, "destroyed": destroyed, "errors": errors}


async def process_sandbox_labs_once() -> Dict[str, Any]:
    reconciliation = await reconcile_sandbox_labs()
    lab = claim_next_sandbox_lab()
    if not lab:
        return {"status": "idle", "reconciliation": reconciliation, "message": "No sandbox lab requests are queued"}
    processed = await process_sandbox_lab(lab)
    return {"status": "processed", "lab": processed, "reconciliation": reconciliation}


def _permission_required_payload(exc: Exception, user_id: str, credential_id: Optional[int]) -> Dict[str, Any]:
    cred_id = credential_id
    if not cred_id:
        try:
            aws_cred = credential_manager.get_default_credential(user_id, "aws")
            cred_id = aws_cred.id if aws_cred else None
        except Exception:
            cred_id = None

    iam_user_arn = getattr(exc, "iam_user_arn", "")
    iam_user_name = iam_user_arn.split("/")[-1] if "/" in iam_user_arn else iam_user_arn
    return {
        "status": "permission_required",
        "permission_error": {
            "type": "missing_assume_role_permission",
            "iam_user_name": iam_user_name,
            "iam_user_arn": iam_user_arn,
            "role_arn": getattr(exc, "role_arn", None),
            "policy_arn": getattr(exc, "recommended_policy_arn", None),
            "credential_id": cred_id,
            "can_auto_grant": True,
        },
    }


def create_scan_job(user_id: str, request: MultiCloudScanRequest) -> Dict[str, Any]:
    job_id = f"job-{uuid.uuid4().hex}"
    conn = get_conn()

    with conn.cursor() as cur:
        cur.execute(
            f"""
            INSERT INTO scan_jobs (
                job_id, user_id, providers, account_ids, deep_scan,
                offensive_scan, credential_id, status
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, 'queued')
            RETURNING {SCAN_JOB_COLUMNS}
            """,
            (
                job_id,
                user_id,
                Json(request.providers),
                Json(request.account_ids),
                request.deep_scan,
                request.offensive_scan,
                request.credential_id,
            ),
        )
        row = cur.fetchone()
        conn.commit()

    return _scan_job_from_row(row)


def get_scan_job(job_id: str, user_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_conn()

    with conn.cursor() as cur:
        if user_id:
            cur.execute(
                f"SELECT {SCAN_JOB_COLUMNS} FROM scan_jobs WHERE job_id = %s AND user_id = %s",
                (job_id, user_id),
            )
        else:
            cur.execute(
                f"SELECT {SCAN_JOB_COLUMNS} FROM scan_jobs WHERE job_id = %s",
                (job_id,),
            )
        return _scan_job_from_row(cur.fetchone())


def list_scan_jobs(user_id: str, status: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_conn()
    limit = max(1, min(limit, 200))

    with conn.cursor() as cur:
        if status:
            cur.execute(
                f"""
                SELECT {SCAN_JOB_COLUMNS}
                FROM scan_jobs
                WHERE user_id = %s AND status = %s
                ORDER BY queued_at DESC
                LIMIT %s
                """,
                (user_id, status, limit),
            )
        else:
            cur.execute(
                f"""
                SELECT {SCAN_JOB_COLUMNS}
                FROM scan_jobs
                WHERE user_id = %s
                ORDER BY queued_at DESC
                LIMIT %s
                """,
                (user_id, limit),
            )
        rows = cur.fetchall()

    return [_scan_job_from_row(row) for row in rows]


def record_scanner_worker_heartbeat(
    worker_id: str,
    worker_type: str = "scan",
    status: str = "online",
    metadata: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    conn = get_conn()
    metadata = metadata or {}

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scanner_worker_heartbeats (
                worker_id, worker_type, status, last_seen_at, metadata
            )
            VALUES (%s, %s, %s, NOW(), %s)
            ON CONFLICT (worker_id)
            DO UPDATE SET
                worker_type = EXCLUDED.worker_type,
                status = EXCLUDED.status,
                last_seen_at = NOW(),
                metadata = EXCLUDED.metadata,
                updated_at = NOW()
            RETURNING worker_id, worker_type, status, last_seen_at, metadata
            """,
            (worker_id, worker_type, status, Json(metadata)),
        )
        row = cur.fetchone()
        conn.commit()

    return {
        "worker_id": row[0],
        "worker_type": row[1],
        "status": row[2],
        "last_seen_at": row[3].isoformat() if row[3] else None,
        "metadata": row[4] or {},
    }


def list_scanner_worker_statuses(stale_after_seconds: Optional[int] = None) -> Dict[str, Any]:
    stale_after_seconds = stale_after_seconds or int(os.getenv("WORKER_HEARTBEAT_STALE_SECONDS", "45"))
    inline_enabled = os.getenv("SCAN_JOB_INLINE_WORKER", "true").lower() == "true"
    conn = get_conn()

    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT
                worker_id,
                worker_type,
                status,
                last_seen_at,
                metadata,
                EXTRACT(EPOCH FROM (NOW() - last_seen_at))::INT AS age_seconds
            FROM scanner_worker_heartbeats
            ORDER BY worker_type, last_seen_at DESC
            """
        )
        rows = cur.fetchall()

    workers = []
    for row in rows:
        age_seconds = int(row[5] or 0)
        fresh = age_seconds <= stale_after_seconds
        online = fresh and row[2] in ("online", "idle", "busy")
        workers.append(
            {
                "worker_id": row[0],
                "worker_type": row[1],
                "status": row[2],
                "online": online,
                "age_seconds": age_seconds,
                "last_seen_at": row[3].isoformat() if row[3] else None,
                "metadata": row[4] or {},
            }
        )

    if inline_enabled:
        workers.insert(
            0,
            {
                "worker_id": "backend-inline-worker",
                "worker_type": "inline",
                "status": "online",
                "online": True,
                "age_seconds": 0,
                "last_seen_at": datetime.now(timezone.utc).isoformat(),
                "metadata": {"source": "SCAN_JOB_INLINE_WORKER"},
            },
        )

    scan_workers_online = any(
        worker["online"] and worker["worker_type"] in ("scan", "inline")
        for worker in workers
    )
    worker_counts: Dict[str, int] = {}
    online_counts: Dict[str, int] = {}
    for worker in workers:
        worker_counts[worker["worker_type"]] = worker_counts.get(worker["worker_type"], 0) + 1
        if worker["online"]:
            online_counts[worker["worker_type"]] = online_counts.get(worker["worker_type"], 0) + 1

    return {
        "status": "online" if scan_workers_online else "offline",
        "scan_workers_online": scan_workers_online,
        "stale_after_seconds": stale_after_seconds,
        "worker_counts": worker_counts,
        "online_counts": online_counts,
        "workers": workers,
    }


def retry_scan_job(job_id: str, user_id: str) -> Dict[str, Any]:
    conn = get_conn()

    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE scan_jobs
            SET status = 'queued',
                attempts = 0,
                scan_ids = '[]'::jsonb,
                result = NULL,
                error = NULL,
                last_error = NULL,
                started_at = NULL,
                completed_at = NULL,
                locked_at = NULL,
                worker_id = NULL,
                updated_at = NOW()
            WHERE job_id = %s
              AND user_id = %s
              AND status IN ('failed', 'dead_letter', 'cancelled')
            RETURNING {SCAN_JOB_COLUMNS}
            """,
            (job_id, user_id),
        )
        row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Retryable scan job not found")
    return _scan_job_from_row(row)


def cancel_scan_job(job_id: str, user_id: str) -> Dict[str, Any]:
    conn = get_conn()

    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE scan_jobs
            SET status = 'cancelled',
                error = 'Cancelled by user',
                last_error = 'Cancelled by user',
                completed_at = NOW(),
                locked_at = NULL,
                worker_id = NULL,
                updated_at = NOW()
            WHERE job_id = %s
              AND user_id = %s
              AND status IN ('queued', 'running')
            RETURNING {SCAN_JOB_COLUMNS}
            """,
            (job_id, user_id),
        )
        row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Cancellable scan job not found")
    return _scan_job_from_row(row)


def update_scan_job(job_id: str, status: str, **updates) -> Dict[str, Any]:
    conn = get_conn()
    fields = ["status = %s", "updated_at = NOW()"]
    params: List[Any] = [status]

    if status == "running":
        fields.append("started_at = COALESCE(started_at, NOW())")
    if status in ("completed", "failed", "dead_letter", "cancelled"):
        fields.append("completed_at = NOW()")
        fields.append("locked_at = NULL")
        fields.append("worker_id = NULL")

    for key in ("scan_ids", "result", "error", "last_error"):
        if key not in updates:
            continue
        value = updates[key]
        fields.append(f"{key} = %s")
        params.append(Json(value) if key in ("scan_ids", "result") else value)

    params.append(job_id)
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE scan_jobs
            SET {', '.join(fields)}
            WHERE job_id = %s
            RETURNING {SCAN_JOB_COLUMNS}
            """,
            tuple(params),
        )
        row = cur.fetchone()
        conn.commit()

    if not row:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return _scan_job_from_row(row)


def start_scan_job(job_id: str) -> Optional[Dict[str, Any]]:
    conn = get_conn()
    worker_id = os.getenv("SCAN_WORKER_ID", f"worker-{uuid.uuid4().hex[:12]}")
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE scan_jobs
            SET status = 'running',
                attempts = attempts + 1,
                started_at = COALESCE(started_at, NOW()),
                locked_at = NOW(),
                worker_id = %s,
                updated_at = NOW()
            WHERE job_id = %s
              AND status = 'queued'
              AND attempts < max_attempts
            RETURNING {SCAN_JOB_COLUMNS}
            """,
            (worker_id, job_id),
        )
        row = cur.fetchone()
        conn.commit()

    return _scan_job_from_row(row)


def requeue_stale_scan_jobs() -> int:
    timeout_minutes = int(os.getenv("SCAN_JOB_TIMEOUT_MINUTES", "20"))
    conn = get_conn()

    with conn.cursor() as cur:
        cur.execute(
            """
            UPDATE scan_jobs
            SET status = CASE WHEN attempts >= max_attempts THEN 'dead_letter' ELSE 'queued' END,
                error = COALESCE(error, 'Scan job timed out while running'),
                last_error = 'Scan job timed out while running',
                locked_at = NULL,
                worker_id = NULL,
                completed_at = CASE WHEN attempts >= max_attempts THEN NOW() ELSE completed_at END,
                updated_at = NOW()
            WHERE status = 'running'
              AND COALESCE(locked_at, updated_at) < NOW() - (%s * INTERVAL '1 minute')
            RETURNING job_id
            """,
            (timeout_minutes,),
        )
        rows = cur.fetchall()
        conn.commit()

    if rows:
        logger.warning(f"Requeued or dead-lettered {len(rows)} stale scan job(s)")
    return len(rows)


def claim_next_scan_job() -> Optional[Dict[str, Any]]:
    requeue_stale_scan_jobs()
    conn = get_conn()
    worker_id = os.getenv("SCAN_WORKER_ID", f"worker-{uuid.uuid4().hex[:12]}")
    with conn.cursor() as cur:
        cur.execute(
            f"""
            UPDATE scan_jobs
            SET status = 'running',
                attempts = attempts + 1,
                started_at = COALESCE(started_at, NOW()),
                locked_at = NOW(),
                worker_id = %s,
                updated_at = NOW()
            WHERE job_id = (
                SELECT job_id
                FROM scan_jobs
                WHERE status = 'queued'
                  AND attempts < max_attempts
                ORDER BY priority ASC, queued_at ASC
                FOR UPDATE SKIP LOCKED
                LIMIT 1
            )
            RETURNING {SCAN_JOB_COLUMNS}
            """,
            (worker_id,),
        )
        row = cur.fetchone()
        conn.commit()

    return _scan_job_from_row(row)


def _scan_job_result_payload(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    scan_ids = scan_result.get("scan_ids", [])
    scan_results = scan_result.get("scan_results", [])
    payload = format_scan_completion_response(
        scan_ids,
        scan_results,
        scan_result.get("ai_analysis", {}),
    )
    payload.update(
        {
            "deep_scan_enabled": scan_result.get("deep_scan_enabled", False),
            "user_credentials_used": scan_result.get("user_credentials_used", False),
        }
    )
    return payload


def store_evidence_artifact(user_id: str, request: EvidenceIngestionRequest) -> Dict[str, Any]:
    payload = request.payload or {}
    metadata = request.metadata or {}
    evidence_id = request.evidence_id or f"ev-{uuid.uuid4().hex}"
    payload_bytes = json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    checksum = hashlib.sha256(payload_bytes).hexdigest()
    storage_type = "database"
    uri = f"db://evidence_artifacts/{evidence_id}"
    payload_to_store = payload

    object_bucket = os.getenv("OBJECT_STORAGE_BUCKET") or os.getenv("EVIDENCE_S3_BUCKET")
    if object_bucket:
        try:
            import boto3

            object_endpoint = os.getenv("OBJECT_STORAGE_ENDPOINT_URL") or os.getenv("AWS_S3_ENDPOINT_URL")
            object_region = os.getenv("OBJECT_STORAGE_REGION") or os.getenv("AWS_REGION") or "blr1"
            object_access_key = os.getenv("OBJECT_STORAGE_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID")
            object_secret_key = os.getenv("OBJECT_STORAGE_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")
            storage_provider = os.getenv("OBJECT_STORAGE_PROVIDER", "s3-compatible")
            key_prefix = (os.getenv("OBJECT_STORAGE_PREFIX") or os.getenv("EVIDENCE_S3_PREFIX") or "cloudguard/evidence").strip("/")
            key = f"{key_prefix}/{user_id}/{evidence_id}.json"
            client_kwargs = {
                "service_name": "s3",
                "region_name": object_region,
            }
            if object_endpoint:
                client_kwargs["endpoint_url"] = object_endpoint
            if object_access_key and object_secret_key:
                client_kwargs["aws_access_key_id"] = object_access_key
                client_kwargs["aws_secret_access_key"] = object_secret_key

            boto3.client(**client_kwargs).put_object(
                Bucket=object_bucket,
                Key=key,
                Body=payload_bytes,
                ContentType=request.content_type or "application/json",
                Metadata={
                    "evidence_id": evidence_id,
                    "checksum_sha256": checksum,
                    "source_system": request.source_system[:255],
                },
            )
            storage_type = storage_provider
            uri_scheme = "spaces" if storage_provider == "digitalocean-spaces" else "s3"
            uri = f"{uri_scheme}://{object_bucket}/{key}"
            payload_to_store = {
                "externalized": True,
                "storage_type": storage_type,
                "uri": uri,
                "size_bytes": len(payload_bytes),
            }
        except Exception as exc:
            logger.warning(f"Falling back to database evidence storage after object storage upload failed: {exc}")

    conn = get_conn()

    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO evidence_artifacts (
                evidence_id, job_id, user_id, control_id, control_name,
                source_system, scanner_type, artifact_type, storage_type,
                uri, filename, content_type, checksum_sha256, payload, metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (evidence_id) DO UPDATE SET
                job_id = EXCLUDED.job_id,
                control_id = EXCLUDED.control_id,
                control_name = EXCLUDED.control_name,
                source_system = EXCLUDED.source_system,
                scanner_type = EXCLUDED.scanner_type,
                artifact_type = EXCLUDED.artifact_type,
                storage_type = EXCLUDED.storage_type,
                uri = EXCLUDED.uri,
                filename = EXCLUDED.filename,
                content_type = EXCLUDED.content_type,
                checksum_sha256 = EXCLUDED.checksum_sha256,
                payload = EXCLUDED.payload,
                metadata = EXCLUDED.metadata
            RETURNING evidence_id, uri, checksum_sha256, created_at
            """,
            (
                evidence_id,
                request.job_id,
                user_id,
                request.control_id,
                request.control_name,
                request.source_system,
                request.scanner_type,
                request.artifact_type,
                storage_type,
                uri,
                request.filename,
                request.content_type,
                checksum,
                Json(payload_to_store),
                Json(metadata),
            ),
        )
        row = cur.fetchone()
        conn.commit()

    return {
        "evidence_id": row[0],
        "uri": row[1],
        "checksum_sha256": row[2],
        "created_at": _iso_timestamp(row[3]),
    }


def list_evidence_artifacts(user_id: str, job_id: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_conn()
    limit = max(1, min(limit, 200))

    with conn.cursor() as cur:
        if job_id:
            cur.execute(
                """
                SELECT evidence_id, job_id, control_id, control_name, source_system,
                       scanner_type, artifact_type, storage_type, uri, checksum_sha256, metadata, created_at
                FROM evidence_artifacts
                WHERE user_id = %s AND job_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (user_id, job_id, limit),
            )
        else:
            cur.execute(
                """
                SELECT evidence_id, job_id, control_id, control_name, source_system,
                       scanner_type, artifact_type, storage_type, uri, checksum_sha256, metadata, created_at
                FROM evidence_artifacts
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (user_id, limit),
            )
        rows = cur.fetchall()

    return [
        {
            "evidence_id": row[0],
            "job_id": row[1],
            "control_id": row[2],
            "control_name": row[3],
            "source_system": row[4],
            "scanner_type": row[5],
            "artifact_type": row[6],
            "storage_type": row[7],
            "uri": row[8],
            "checksum_sha256": row[9],
            "metadata": row[10] or {},
            "created_at": _iso_timestamp(row[11]),
        }
        for row in rows
    ]


COMPLIANCE_CONTROL_CATALOG = [
    {"framework": "DPDP", "control_id": "DPDP-A.1.2.5", "control_name": "Consent capture and retention"},
    {"framework": "DPDP", "control_id": "DPDP-A.1.3.7", "control_name": "Enable access controls"},
    {"framework": "DPDP", "control_id": "DPDP-A.1.4.2", "control_name": "Maintain audit-ready processing evidence"},
    {"framework": "CIS AWS", "control_id": "CIS AWS 1.2", "control_name": "Ensure multi-factor authentication for privileged users"},
    {"framework": "CIS AWS", "control_id": "CIS AWS 2.1.1", "control_name": "Ensure S3 bucket encryption is enabled"},
    {"framework": "CIS AWS", "control_id": "CIS AWS 2.1.5", "control_name": "Ensure S3 buckets are not publicly accessible"},
    {"framework": "CIS AWS", "control_id": "CIS AWS 4.1", "control_name": "Restrict ingress from 0.0.0.0/0 to administrative ports"},
    {"framework": "CIS GCP", "control_id": "CIS-GCP-5.1", "control_name": "Ensure logging metric filters and alerts are configured"},
    {"framework": "CIS Kubernetes", "control_id": "CIS Kubernetes Benchmark", "control_name": "Apply Kubernetes benchmark controls"},
    {"framework": "Kubernetes", "control_id": "Kubernetes Pod Security Standards", "control_name": "Restrict privileged workload execution"},
    {"framework": "IaC", "control_id": "CIS Infrastructure as Code", "control_name": "Detect insecure infrastructure-as-code patterns"},
    {"framework": "OWASP", "control_id": "OWASP-A06:2021", "control_name": "Vulnerable and outdated components"},
    {"framework": "OWASP", "control_id": "OWASP-API-2", "control_name": "Broken authentication controls"},
    {"framework": "NIST", "control_id": "NIST-800-53-AU-2", "control_name": "Audit event logging"},
    {"framework": "ISO 27001", "control_id": "ISO 27001 A.5.15", "control_name": "Access control"},
]


def _infer_compliance_framework(control_id: Optional[str], control_name: Optional[str] = None) -> str:
    text = f"{control_id or ''} {control_name or ''}".upper()
    if "DPDP" in text or text.startswith("A."):
        return "DPDP"
    if "CIS-GCP" in text or "CIS GCP" in text:
        return "CIS GCP"
    if "CIS AWS" in text or "CIS-" in text:
        return "CIS AWS"
    if "KUBERNETES" in text:
        return "Kubernetes"
    if "INFRASTRUCTURE AS CODE" in text or "IAC" in text:
        return "IaC"
    if "OWASP" in text:
        return "OWASP"
    if "NIST" in text:
        return "NIST"
    if "ISO" in text:
        return "ISO 27001"
    if "SOC" in text:
        return "SOC 2"
    return "Unmapped"


def _normalize_severity(value: Any) -> str:
    if hasattr(value, "value"):
        value = value.value
    severity = str(value or "info").lower()
    if severity in {"critical", "high", "medium", "low", "info"}:
        return severity
    return "info"


def _iter_dicts(value: Any):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _iter_dicts(child)
    elif isinstance(value, list):
        for item in value:
            yield from _iter_dicts(item)


def _extract_compliance_findings(payload: Any) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    for item in _iter_dicts(payload):
        compliance = item.get("compliance")
        if isinstance(compliance, str):
            controls = [compliance]
        elif isinstance(compliance, list):
            controls = [str(control) for control in compliance if control]
        else:
            controls = []

        if not controls:
            explicit_control = item.get("control_id") or item.get("control")
            controls = [str(explicit_control)] if explicit_control else []

        if not controls:
            continue

        severity = _normalize_severity(item.get("severity"))
        title = item.get("issue") or item.get("title") or item.get("description") or "Compliance finding"
        recommendation = item.get("recommendation") or item.get("remediation")
        resource = item.get("resource") or item.get("resource_id") or item.get("resource_name")

        for control in controls:
            findings.append(
                {
                    "control_id": control,
                    "severity": severity,
                    "title": str(title)[:240],
                    "recommendation": recommendation,
                    "resource": resource,
                }
            )
    return findings


def _blank_control(control_id: str, control_name: Optional[str] = None, framework: Optional[str] = None) -> Dict[str, Any]:
    return {
        "control_id": control_id,
        "control_name": control_name or control_id,
        "framework": framework or _infer_compliance_framework(control_id, control_name),
        "status": "no_evidence",
        "evidence_count": 0,
        "finding_count": 0,
        "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "sources": [],
        "latest_evidence_at": None,
        "latest_job_id": None,
        "latest_evidence_id": None,
        "sample_findings": [],
    }


def _control_matches_framework(control: Dict[str, Any], framework: str) -> bool:
    if framework in {"all", "", None}:
        return True
    return control.get("framework", "").lower() == framework.lower()


def build_compliance_summary(user_id: str, framework: str = "all") -> Dict[str, Any]:
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT evidence_id, job_id, control_id, control_name, source_system,
                   scanner_type, artifact_type, storage_type, uri, checksum_sha256,
                   payload, metadata, created_at
            FROM evidence_artifacts
            WHERE user_id = %s
            ORDER BY created_at DESC
            LIMIT 1000
            """,
            (user_id,),
        )
        evidence_rows = cur.fetchall()

    controls: Dict[str, Dict[str, Any]] = {}
    for item in COMPLIANCE_CONTROL_CATALOG:
        controls[item["control_id"]] = _blank_control(
            item["control_id"],
            item["control_name"],
            item["framework"],
        )

    recent_evidence: List[Dict[str, Any]] = []
    source_counts: Dict[str, int] = {}

    for row in evidence_rows:
        evidence = {
            "evidence_id": row[0],
            "job_id": row[1],
            "control_id": row[2],
            "control_name": row[3],
            "source_system": row[4],
            "scanner_type": row[5],
            "artifact_type": row[6],
            "storage_type": row[7],
            "uri": row[8],
            "checksum_sha256": row[9],
            "payload": row[10] or {},
            "metadata": row[11] or {},
            "created_at": _iso_timestamp(row[12]),
        }
        recent_evidence.append({k: v for k, v in evidence.items() if k != "payload"})

        source = evidence["source_system"] or "unknown"
        source_counts[source] = source_counts.get(source, 0) + 1

        explicit_control_id = evidence["control_id"] or "unmapped.evidence"
        control = controls.setdefault(
            explicit_control_id,
            _blank_control(explicit_control_id, evidence["control_name"]),
        )
        if evidence["control_name"] and control["control_name"] == explicit_control_id:
            control["control_name"] = evidence["control_name"]
        control["framework"] = _infer_compliance_framework(control["control_id"], control["control_name"])
        control["evidence_count"] += 1
        control["latest_evidence_at"] = evidence["created_at"] or control["latest_evidence_at"]
        control["latest_job_id"] = evidence["job_id"] or control["latest_job_id"]
        control["latest_evidence_id"] = evidence["evidence_id"]
        if source not in control["sources"]:
            control["sources"].append(source)

        for finding in _extract_compliance_findings(evidence["payload"]):
            finding_control_id = finding["control_id"]
            finding_control = controls.setdefault(
                finding_control_id,
                _blank_control(finding_control_id),
            )
            finding_control["framework"] = _infer_compliance_framework(
                finding_control["control_id"],
                finding_control["control_name"],
            )
            finding_control["finding_count"] += 1
            finding_control["severity_counts"][finding["severity"]] += 1
            finding_control["latest_evidence_at"] = evidence["created_at"] or finding_control["latest_evidence_at"]
            finding_control["latest_job_id"] = evidence["job_id"] or finding_control["latest_job_id"]
            finding_control["latest_evidence_id"] = evidence["evidence_id"]
            if source not in finding_control["sources"]:
                finding_control["sources"].append(source)
            if len(finding_control["sample_findings"]) < 3:
                finding_control["sample_findings"].append(finding)

    for control in controls.values():
        critical_high = control["severity_counts"]["critical"] + control["severity_counts"]["high"]
        medium_low = control["severity_counts"]["medium"] + control["severity_counts"]["low"]
        if critical_high:
            control["status"] = "non_compliant"
        elif medium_low or control["finding_count"]:
            control["status"] = "partial"
        elif control["evidence_count"]:
            control["status"] = "compliant"
        else:
            control["status"] = "no_evidence"
        control["sources"] = sorted(control["sources"])

    framework_options = sorted({control["framework"] for control in controls.values()})
    filtered_controls = [
        control for control in controls.values()
        if _control_matches_framework(control, framework)
    ]
    filtered_controls.sort(
        key=lambda item: (
            {"non_compliant": 0, "partial": 1, "no_evidence": 2, "compliant": 3}.get(item["status"], 4),
            item["framework"],
            item["control_id"],
        )
    )

    counts = {
        "total_controls": len(filtered_controls),
        "compliant": sum(1 for control in filtered_controls if control["status"] == "compliant"),
        "partial": sum(1 for control in filtered_controls if control["status"] == "partial"),
        "non_compliant": sum(1 for control in filtered_controls if control["status"] == "non_compliant"),
        "no_evidence": sum(1 for control in filtered_controls if control["status"] == "no_evidence"),
        "evidence_artifacts": sum(control["evidence_count"] for control in filtered_controls),
        "findings": sum(control["finding_count"] for control in filtered_controls),
    }
    weighted_score = 0
    if counts["total_controls"]:
        weighted_score = round(
            (
                counts["compliant"] * 100
                + counts["partial"] * 50
            )
            / counts["total_controls"],
            1,
        )

    return {
        "status": "ok",
        "generated_at": datetime.utcnow().isoformat(),
        "framework": framework or "all",
        "frameworks": ["all"] + framework_options,
        "score": weighted_score,
        "counts": counts,
        "source_counts": source_counts,
        "controls": filtered_controls,
        "recent_evidence": recent_evidence[:20],
    }


def list_control_evidence(user_id: str, control_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_conn()
    limit = max(1, min(limit, 200))
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT evidence_id, job_id, control_id, control_name, source_system,
                   scanner_type, artifact_type, storage_type, uri, checksum_sha256,
                   payload, metadata, created_at
            FROM evidence_artifacts
            WHERE user_id = %s AND control_id = %s
            ORDER BY created_at DESC
            LIMIT %s
            """,
            (user_id, control_id, limit),
        )
        rows = cur.fetchall()
    return [
        {
            "evidence_id": row[0],
            "job_id": row[1],
            "control_id": row[2],
            "control_name": row[3],
            "source_system": row[4],
            "scanner_type": row[5],
            "artifact_type": row[6],
            "storage_type": row[7],
            "uri": row[8],
            "checksum_sha256": row[9],
            "payload": row[10],
            "metadata": row[11] or {},
            "created_at": _iso_timestamp(row[12]),
        }
        for row in rows
    ]


def _store_scan_job_evidence(job: Dict[str, Any], payload: Dict[str, Any]) -> None:
    try:
        store_evidence_artifact(
            job["user_id"],
            EvidenceIngestionRequest(
                job_id=job["job_id"],
                control_id="scan.summary",
                control_name="CloudGuard scan output",
                source_system="CloudGuard Scan Worker",
                scanner_type="multi-cloud",
                artifact_type="scan_result",
                payload=payload,
                metadata={
                    "providers": job.get("providers", []),
                    "scan_ids": payload.get("scan_ids", []),
                },
            ),
        )
    except Exception as exc:
        logger.warning(f"Failed to persist scan evidence for {job['job_id']}: {exc}")


def _validated_iac_uploads(files: List[IaCUploadedFile]) -> List[Dict[str, str]]:
    if not files:
        raise HTTPException(status_code=400, detail="Add at least one IaC file to scan.")
    if len(files) > 20:
        raise HTTPException(status_code=400, detail="Scan up to 20 IaC files at a time.")

    validated: List[Dict[str, str]] = []
    total_bytes = 0
    for item in files:
        filename = (item.filename or "").strip()
        content = item.content or ""
        if not filename:
            raise HTTPException(status_code=400, detail="Every IaC file needs a filename.")
        if not content.strip():
            raise HTTPException(status_code=400, detail=f"{filename} is empty.")

        size = len(content.encode("utf-8"))
        if size > 2 * 1024 * 1024:
            raise HTTPException(status_code=400, detail=f"{filename} is larger than the 2 MB per-file limit.")
        total_bytes += size
        validated.append({"filename": filename, "content": content})

    if total_bytes > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="IaC upload is larger than the 5 MB total limit.")

    return validated


async def process_scan_job(job_id: Optional[str] = None) -> Dict[str, Any]:
    job = start_scan_job(job_id) if job_id else claim_next_scan_job()
    if not job:
        return {"status": "idle", "message": "No queued scan job is available"}

    logger.info(f"🧾 Processing scan job {job['job_id']} for providers={job['providers']}")

    try:
        scan_result = await run_multi_cloud_scan_internal(
            providers=job["providers"],
            account_ids=job["account_ids"],
            deep_scan=job["deep_scan"],
            user_id=job["user_id"],
            credential_id=job["credential_id"],
            offensive_scan=job["offensive_scan"],
        )
        result_payload = _scan_job_result_payload(scan_result)
        _store_scan_job_evidence(job, result_payload)
        return update_scan_job(
            job["job_id"],
            "completed",
            scan_ids=result_payload.get("scan_ids", []),
            result=result_payload,
            error=None,
            last_error=None,
        )
    except Exception as exc:
        logger.exception(f"Scan job {job['job_id']} failed")

        if hasattr(exc, "iam_user_arn") and hasattr(exc, "recommended_policy_arn"):
            payload = _permission_required_payload(exc, job["user_id"], job["credential_id"])
            return update_scan_job(
                job["job_id"],
                "dead_letter",
                result=payload,
                error="AWS assume-role permission is required",
                last_error="AWS assume-role permission is required",
            )

        next_status = "queued" if job["attempts"] < job["max_attempts"] else "dead_letter"
        return update_scan_job(job["job_id"], next_status, error=str(exc), last_error=str(exc))


@app.post("/api/evidence")
async def ingest_evidence(request: EvidenceIngestionRequest, req: Request):
    if not _is_connector_request_authorized(req):
        raise HTTPException(status_code=401, detail="Connector token required")
    user_id = _connector_user_id(req)
    artifact = store_evidence_artifact(user_id, request)
    return {"status": "accepted", **artifact}


@app.get("/api/evidence")
async def get_evidence(req: Request, job_id: Optional[str] = None, limit: int = 50):
    user_id = get_user_id(req)
    return {
        "status": "ok",
        "evidence": list_evidence_artifacts(user_id, job_id=job_id, limit=limit),
    }


@app.get("/api/evidence/{evidence_id}")
async def get_evidence_detail(evidence_id: str, req: Request):
    user_id = get_user_id(req)
    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT evidence_id, job_id, control_id, control_name, source_system,
                   scanner_type, artifact_type, storage_type, uri, checksum_sha256,
                   payload, metadata, created_at
            FROM evidence_artifacts
            WHERE evidence_id = %s AND user_id = %s
            """,
            (evidence_id, user_id),
        )
        row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=404, detail="Evidence not found")

    return {
        "evidence_id": row[0],
        "job_id": row[1],
        "control_id": row[2],
        "control_name": row[3],
        "source_system": row[4],
        "scanner_type": row[5],
        "artifact_type": row[6],
        "storage_type": row[7],
        "uri": row[8],
        "checksum_sha256": row[9],
        "payload": row[10],
        "metadata": row[11] or {},
        "created_at": _iso_timestamp(row[12]),
    }


@app.post("/api/risk/context")
async def save_asset_risk_context(request: AssetRiskContextRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    context = upsert_asset_risk_context(user_id, tenant_id, request)
    return {"status": "ok", "context": context}


@app.get("/api/risk/context")
async def get_asset_risk_contexts(
    req: Request,
    tenant_id: Optional[str] = None,
    asset_ref: Optional[str] = None,
    limit: int = 100,
):
    user_id = get_user_id(req)
    resolved_tenant_id = _request_tenant_id(req, tenant_id, user_id)
    return {
        "status": "ok",
        "tenant_id": resolved_tenant_id,
        "contexts": list_asset_risk_contexts(user_id, resolved_tenant_id, asset_ref=asset_ref, limit=limit),
    }


@app.post("/api/risk/prioritize")
async def prioritize_security_findings(request: FindingPrioritizationRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    return prioritize_findings(user_id, tenant_id, request)


@app.post("/api/validation/jobs")
async def create_security_validation(request: ValidationJobRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    job = create_validation_job(user_id, tenant_id, request)
    return {"status": "accepted", "validation_job": job}


@app.get("/api/validation/jobs")
async def get_security_validation_jobs(
    req: Request,
    tenant_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
):
    user_id = get_user_id(req)
    resolved_tenant_id = _request_tenant_id(req, tenant_id, user_id)
    return {
        "status": "ok",
        "tenant_id": resolved_tenant_id,
        "validation_jobs": list_validation_jobs(user_id, resolved_tenant_id, status=status, limit=limit),
    }


@app.post("/api/validation/jobs/{validation_id}/status")
async def update_security_validation(validation_id: str, request: ValidationJobUpdateRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    job = update_validation_job(user_id, tenant_id, validation_id, request)
    return {"status": "ok", "validation_job": job}


@app.post("/api/remediation/actions")
async def create_remediation(request: RemediationActionRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    action = create_remediation_action(user_id, tenant_id, request)
    return {"status": "ok", "remediation_action": action}


@app.get("/api/remediation/actions")
async def get_remediation_actions(
    req: Request,
    tenant_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 100,
):
    user_id = get_user_id(req)
    resolved_tenant_id = _request_tenant_id(req, tenant_id, user_id)
    return {
        "status": "ok",
        "tenant_id": resolved_tenant_id,
        "remediation_actions": list_remediation_actions(user_id, resolved_tenant_id, status=status, limit=limit),
    }


@app.post("/api/remediation/actions/{action_id}/decision")
async def decide_remediation(action_id: str, request: RemediationDecisionRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    action = decide_remediation_action(user_id, tenant_id, action_id, request)
    return {"status": "ok", "remediation_action": action}


@app.post("/api/threat-models/stride")
async def create_threat_model(request: ThreatModelRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    threat_model = create_stride_threat_model(user_id, tenant_id, request)
    return {"status": "ok", "threat_model": threat_model}


@app.get("/api/threat-models")
async def get_threat_models(req: Request, tenant_id: Optional[str] = None, limit: int = 100):
    user_id = get_user_id(req)
    resolved_tenant_id = _request_tenant_id(req, tenant_id, user_id)
    return {
        "status": "ok",
        "tenant_id": resolved_tenant_id,
        "threat_models": list_threat_models(user_id, resolved_tenant_id, limit=limit),
    }


@app.get("/api/sandbox-labs/catalog")
async def get_sandbox_labs_catalog(req: Request):
    user_id = get_user_id(req)
    return {
        "status": "ok",
        "sandbox_labs_enabled": _sandbox_labs_enabled(),
        "user_id": user_id,
        "catalog": _sandbox_lab_catalog(user_id),
        "guardrails": {
            "creates_full_cloud_accounts": False,
            "creates_temporary_resources_inside_existing_sandbox_accounts": True,
            "default_ttl_minutes": 5,
            "cloud_resource_deployment_requires_provider_env_flags": True,
        },
    }


@app.post("/api/sandbox-labs")
async def create_sandbox_lab(request: SandboxLabRequest, req: Request, background_tasks: BackgroundTasks):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    lab = create_sandbox_lab_run(user_id, tenant_id, request)
    if os.getenv("SANDBOX_LAB_INLINE_WORKER", "true").lower() == "true":
        background_tasks.add_task(process_sandbox_labs_once)
    return {
        "status": "accepted",
        "lab": lab,
        "message": "Sandbox lab queued. Resources will be cleaned after scan completion or TTL expiry.",
    }


@app.get("/api/sandbox-labs")
async def get_sandbox_labs(
    req: Request,
    tenant_id: Optional[str] = None,
    status: Optional[str] = None,
    limit: int = 50,
):
    user_id = get_user_id(req)
    resolved_tenant_id = _request_tenant_id(req, tenant_id, user_id)
    labs = list_sandbox_labs(user_id, resolved_tenant_id, status=status, limit=limit)
    return {
        "status": "ok",
        "tenant_id": resolved_tenant_id,
        "labs": labs,
        "counts": {
            "requested": len([lab for lab in labs if lab["status"] == "requested"]),
            "provisioning": len([lab for lab in labs if lab["status"] == "provisioning"]),
            "scanning": len([lab for lab in labs if lab["status"] == "scanning"]),
            "destroyed": len([lab for lab in labs if lab["status"] == "destroyed"]),
            "failed": len([lab for lab in labs if lab["status"] == "failed"]),
        },
    }


@app.post("/api/sandbox-labs/worker/run-once")
async def run_sandbox_labs_worker_once(req: Request):
    if not _is_worker_request_authorized(req):
        raise HTTPException(status_code=401, detail="Worker token required")
    if not _sandbox_labs_enabled():
        raise HTTPException(status_code=403, detail="Sandbox labs are disabled")
    return await process_sandbox_labs_once()


@app.get("/api/sandbox-labs/{lab_id}")
async def get_sandbox_lab(lab_id: str, req: Request, tenant_id: Optional[str] = None):
    user_id = get_user_id(req)
    resolved_tenant_id = _request_tenant_id(req, tenant_id, user_id)
    lab = get_sandbox_lab_run(lab_id, user_id=user_id, tenant_id=resolved_tenant_id)
    if not lab:
        raise HTTPException(status_code=404, detail="Sandbox lab not found")
    return {"status": "ok", "lab": lab, "events": list_sandbox_lab_events(lab_id)}


@app.post("/api/sandbox-labs/{lab_id}/destroy")
async def destroy_sandbox_lab_endpoint(lab_id: str, request: SandboxLabDestroyRequest, req: Request):
    user_id = get_user_id(req)
    tenant_id = _request_tenant_id(req, request.tenant_id, user_id)
    lab = await destroy_sandbox_lab(lab_id, user_id=user_id, tenant_id=tenant_id, reason=request.reason or "manual_destroy")
    return {"status": lab["status"], "lab": lab}


@app.get("/api/compliance/summary")
async def get_compliance_summary(req: Request, framework: str = "all"):
    user_id = get_user_id(req)
    return build_compliance_summary(user_id, framework=framework)


@app.get("/api/compliance/controls/{control_id}/evidence")
async def get_compliance_control_evidence(control_id: str, req: Request, limit: int = 50):
    user_id = get_user_id(req)
    return {
        "status": "ok",
        "control_id": control_id,
        "evidence": list_control_evidence(user_id, control_id, limit=limit),
    }


@app.post("/api/iac/scan-files")
async def scan_iac_uploaded_files(request: IaCFileScanRequest, req: Request):
    user_id = request.user_id or get_user_id(req)
    files = _validated_iac_uploads(request.files)

    server = create_iac_server({"root_path": os.getcwd()})
    result_data = await server._full_scan(
        account_id="uploaded-iac-files",
        deep_scan=request.deep_scan,
        files=files,
    )
    scan_result = _mcp_to_scan_result("iac", result_data)
    scan_id = await store_scan_result(scan_result)

    try:
        ai_analysis = await ai_engine.analyze_scan_results([scan_result])
    except Exception as exc:
        logger.error(f"IaC uploaded file AI analysis failed: {exc}")
        ai_analysis = {"error": "AI unavailable"}

    response = format_scan_completion_response([scan_id], [scan_result], ai_analysis)
    response.update(
        {
            "uploaded_files": [item["filename"] for item in files],
            "errors": result_data.get("errors", []),
            "summary": {
                **response["summary"],
                "files_scanned": result_data.get("summary", {}).get("files_scanned", 0),
                "scan_source": "uploaded_files",
            },
        }
    )

    try:
        store_evidence_artifact(
            user_id,
            EvidenceIngestionRequest(
                control_id="iac.uploaded_files",
                control_name="Uploaded IaC file scan",
                source_system="CloudGuard IaC Upload",
                scanner_type="iac",
                artifact_type="scan_result",
                payload={
                    "files": [{"filename": item["filename"], "size": len(item["content"].encode("utf-8"))} for item in files],
                    "result": response,
                },
                metadata={"scan_id": scan_id, "files_scanned": len(files)},
            ),
        )
    except Exception as exc:
        logger.warning(f"Failed to persist uploaded IaC evidence: {exc}")

    return response


@app.post("/api/jobs/scan")
async def enqueue_scan_job(
    request: MultiCloudScanRequest,
    req: Request,
    background_tasks: BackgroundTasks,
):
    user_id = request.user_id or get_user_id(req)
    logger.info(f"📥 Enqueue scan job for user={user_id}: {request.dict()}")

    try:
        await initialize_mcp_servers_for_user(user_id, request.providers, request.credential_id)
    except Exception as exc:
        if hasattr(exc, "iam_user_arn") and hasattr(exc, "recommended_policy_arn"):
            return JSONResponse(status_code=200, content=_permission_required_payload(exc, user_id, request.credential_id))
        raise

    available_providers = set(mcp_registry.list_providers())
    missing_providers = [provider for provider in request.providers if provider not in available_providers]
    if missing_providers:
        raise HTTPException(
            status_code=400,
            detail=f"Missing credentials for: {', '.join(missing_providers)}. Please add credentials in Settings.",
        )

    job = create_scan_job(user_id, request)
    if os.getenv("SCAN_JOB_INLINE_WORKER", "true").lower() == "true":
        background_tasks.add_task(process_scan_job, job["job_id"])

    return JSONResponse(
        status_code=202,
        content={
            "status": job["status"],
            "job_id": job["job_id"],
            "dashboard_url": generate_dashboard_url([]),
            "message": "Scan job queued. The dashboard will update when processing finishes.",
        },
    )


@app.get("/api/jobs")
async def get_scan_jobs(req: Request, status: Optional[str] = None, limit: int = 50):
    user_id = get_user_id(req)
    jobs = list_scan_jobs(user_id, status=status, limit=limit)
    return {
        "status": "ok",
        "jobs": jobs,
        "counts": {
            "queued": len([job for job in jobs if job["status"] == "queued"]),
            "running": len([job for job in jobs if job["status"] == "running"]),
            "completed": len([job for job in jobs if job["status"] == "completed"]),
            "failed": len([job for job in jobs if job["status"] == "failed"]),
            "dead_letter": len([job for job in jobs if job["status"] == "dead_letter"]),
            "cancelled": len([job for job in jobs if job["status"] == "cancelled"]),
        },
    }


@app.post("/api/jobs/{job_id}/retry")
async def retry_scan_job_endpoint(job_id: str, req: Request, background_tasks: BackgroundTasks):
    user_id = get_user_id(req)
    job = retry_scan_job(job_id, user_id)
    if os.getenv("SCAN_JOB_INLINE_WORKER", "true").lower() == "true":
        background_tasks.add_task(process_scan_job, job["job_id"])
    return {"status": "queued", "job": job}


@app.post("/api/jobs/{job_id}/cancel")
async def cancel_scan_job_endpoint(job_id: str, req: Request):
    user_id = get_user_id(req)
    job = cancel_scan_job(job_id, user_id)
    return {"status": "cancelled", "job": job}


@app.get("/api/jobs/{job_id}")
async def get_scan_job_status(job_id: str, req: Request):
    user_id = get_user_id(req)
    job = get_scan_job(job_id, user_id=user_id)
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return job


def _is_worker_request_authorized(req: Request) -> bool:
    expected_token = os.getenv("WORKER_TOKEN")
    expected_cron_secret = os.getenv("CRON_SECRET")
    auth_header = req.headers.get("authorization", "")
    provided_token = _request_token(req, "x-worker-token", "token")

    if expected_token and provided_token == expected_token:
        return True
    if expected_cron_secret and auth_header == f"Bearer {expected_cron_secret}":
        return True

    auth_required = os.getenv(
        "WORKER_AUTH_REQUIRED",
        "true" if os.getenv("VERCEL_ENV") == "production" else "false",
    ).lower() == "true"
    return not auth_required and not expected_token and not expected_cron_secret


def _worker_identity_from_request(req: Request, default_type: str = "scan") -> Dict[str, str]:
    allowed_types = {"scan", "scheduler", "sandbox", "evidence", "inline", "unknown"}
    worker_type = req.headers.get("x-worker-type") or req.query_params.get("worker_type") or default_type
    if worker_type not in allowed_types:
        worker_type = default_type if default_type in allowed_types else "unknown"
    worker_id = req.headers.get("x-worker-id") or req.query_params.get("worker_id") or f"api-{worker_type}-worker"
    return {"worker_id": worker_id[:128], "worker_type": worker_type}


@app.post("/api/workers/heartbeat")
async def worker_heartbeat(request: WorkerHeartbeatRequest, req: Request):
    if request.worker_type == "evidence":
        if not _is_connector_request_authorized(req):
            raise HTTPException(status_code=401, detail="Connector token required")
    elif not _is_worker_request_authorized(req):
        raise HTTPException(status_code=401, detail="Worker token required")

    heartbeat = record_scanner_worker_heartbeat(
        request.worker_id,
        request.worker_type,
        request.status,
        request.metadata,
    )
    return {"status": "accepted", "worker": heartbeat}


@app.get("/api/workers/status")
async def get_workers_status():
    return list_scanner_worker_statuses()


@app.post("/api/jobs/worker/run-once")
async def run_scan_worker_once(req: Request):
    if not _is_worker_request_authorized(req):
        raise HTTPException(status_code=401, detail="Worker token required")
    identity = _worker_identity_from_request(req, default_type="scan")
    record_scanner_worker_heartbeat(
        identity["worker_id"],
        identity["worker_type"],
        "busy",
        {"source": "api-run-once"},
    )
    return await process_scan_job()


@app.get("/api/cron/scan-worker")
async def run_scan_worker_cron(req: Request):
    if not _is_worker_request_authorized(req):
        raise HTTPException(status_code=401, detail="Cron secret required")
    return await process_scan_job()



# ============================================================
# 🆕 MCP SERVER-BASED SCAN ENDPOINTS
# ============================================================

@app.post("/scan/multi-cloud")
async def multi_cloud_scan(request: MultiCloudScanRequest, req: Request):
    """Direct multi-cloud scan with USER credentials (MCP-based)"""
    logger.info(f"🚀 [ScanAPI] Multi-cloud scan request received.")
    logger.info(f"📦 Payload: {request.dict()}")

    user_id = get_user_id(req)
    # If the request has an explicit user_id, use it (though cookies are safer)
    if "user_id" in request.dict() and request.user_id:
        user_id = request.user_id

    logger.info(f"👤 Resolved User ID for scan: {user_id}")

    # 🔥 Initialize MCP servers FIRST
    try:
        await initialize_mcp_servers_for_user(user_id, request.providers, request.credential_id)
    except Exception as e:
        # Check if this is our structured permission error from aws_assume_role.py
        if hasattr(e, 'iam_user_arn') and hasattr(e, 'recommended_policy_arn'):
            logger.warning(f"🛡️ Detected missing assume-role permission for user: {e.iam_user_arn}")

            # Find the AWS credential ID (needed for the auto-grant request)
            # Use specific credential if provided, otherwise use default
            if request.credential_id:
                aws_cred = credential_manager.get_credential_by_id(user_id, request.credential_id)
            else:
                aws_cred = credential_manager.get_default_credential(user_id, "aws")
            cred_id = aws_cred.id if aws_cred else None

            # Extract simple name from ARN: arn:aws:iam::123:user/vuln_scan_test -> vuln_scan_test
            iam_user_name = e.iam_user_arn.split('/')[-1] if '/' in e.iam_user_arn else e.iam_user_arn

            return JSONResponse(
                status_code=200, # Return 200 so the frontend can handle it as a flow, not a crash
                content={
                    "status": "permission_required",
                    "permission_error": {
                        "type": "missing_assume_role_permission",
                        "iam_user_name": iam_user_name,
                        "iam_user_arn": e.iam_user_arn,
                        "role_arn": getattr(e, 'role_arn', None),
                        "policy_arn": e.recommended_policy_arn,
                        "credential_id": cred_id,
                        "can_auto_grant": True
                    }
                }
            )

        # Log other initialization errors
        logger.error(f"❌ MCP Server initialization failed: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"Initialization failed: {str(e)}"
        )

    # ✅ NOW validate
    available_providers = mcp_registry.list_providers()
    logger.info(f"✅ Available MCP providers: {available_providers}")

    missing_providers = [provider for provider in request.providers if provider not in available_providers]
    if missing_providers:
        raise HTTPException(
            status_code=400,
            detail=f"Missing credentials for: {', '.join(missing_providers)}. Please add credentials in Settings."
        )


    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    for provider in request.providers:
        try:
            account_id = request.account_ids.get(provider, "default") or "default"
            logger.info(f"📡 Scanning {provider} with account_id: {account_id}")
            mcp_result = await mcp_registry.scan(
            provider=provider,
            account_id=account_id,
            options={
                "deep_scan": request.deep_scan,
                "offensive_scan": request.offensive_scan,
                }
            )

            # Convert MCP dict → ScanResult
            scan_result_obj = _mcp_to_scan_result(provider, mcp_result)
            scan_results.append(scan_result_obj)

            # 🔥 FIX: resolve credential_id safely
            credential_id = None
            if provider == "aws":
                aws_server = mcp_registry.get_plugin("aws")
                if aws_server:
                    credential_id = aws_server.config.get("credential_id")

            scan_id = await store_scan_result(
                scan_result_obj,
                aws_credential_id=credential_id,
            )
            stored_ids.append(scan_id)



            logger.info(
                f"✅ {provider.upper()} scan finished, "
                f"stored as scan_id={scan_id}"
            )

        except Exception as e:
            logger.exception(f"❌ Scan failed for {provider}")
            raise HTTPException(
                status_code=500,
                detail=f"{provider} scan failed: {e}",
            )

    # ✅ AI analysis (non-blocking failure)
    try:
        ai_analysis = await ai_engine.analyze_scan_results(scan_results)
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        ai_analysis = {"error": "AI unavailable"}

    # ✅ Final response (NO legacy fields)
    response = format_scan_completion_response(
        stored_ids,
        scan_results,
        ai_analysis,
    )

    response.update({
        "deep_scan_enabled": request.deep_scan,
        "offensive_scan_enabled": request.offensive_scan and "aws" in request.providers,
        "providers_scanned": request.providers,
        "scan_results": [
            {
                "provider": r.provider,
                "resources": len(r.resources),
                "findings": len(r.findings),
                "duration": r.scan_duration,
            }
            for r in scan_results
        ],
    })

    return response

@app.post("/scan/offensive-enhanced")
async def offensive_enhanced_scan(
    profile: str = "default",
    region: str = "us-east-1",
    req: Request = None,
    include_aws_scan: bool = True  # NEW: Combine AWS and CloudFox
):
    """
    Enhanced offensive security scan combining AWS config scan + CloudFox
    """
    user_id = get_user_id(req)
    logger.info(f"⚔️ Enhanced offensive scan: user={user_id}")

    try:
        results = {}

        # 1. Run AWS security scan if enabled
        if include_aws_scan:
            logger.info("Running AWS security scan...")
            aws_results = await mcp_scanner.scan_multi_cloud(
                user_id=user_id,
                providers=["aws"],
                account_ids={"aws": "default"},
                deep_scan=True,
                offensive_scan=False  # We'll run CloudFox separately
            )
            results["aws_scan"] = aws_results

        # 2. Run CloudFox offensive scan
        logger.info("Running CloudFox offensive scan...")
        cloudfox_result = await mcp_scanner.run_offensive_scan(
            user_id=user_id,
            profile=profile,
            region=region
        )
        results["cloudfox_scan"] = cloudfox_result

        # 3. Combine findings
        all_findings = []

        if include_aws_scan:
            for provider_result in results.get("aws_scan", {}).get("results", {}).values():
                all_findings.extend(provider_result.get("findings", []))

        all_findings.extend(cloudfox_result.get("findings", []))

        # 4. Categorize findings
        categorized = {
            "config_violations": [f for f in all_findings if f.get("source") != "cloudfox"],
            "offensive_findings": [f for f in all_findings if f.get("source") == "cloudfox"],
            "critical_paths": [f for f in all_findings if f.get("severity") == "CRITICAL"],
            "privilege_escalation": [f for f in all_findings if "privilege" in str(f.get("description", "")).lower() or "escalation" in str(f.get("description", "")).lower()]
        }

        # 5. Store in database
        if all_findings:
            scan_id = await _store_offensive_scan({
                "profile": profile,
                "findings": all_findings,
                "categorized": categorized
            })
            results["stored_scan_id"] = scan_id

        return {
            "status": "completed",
            "scan_type": "offensive_enhanced",
            "architecture": "MCP-SERVER",
            "aws_scan_included": include_aws_scan,
            "total_findings": len(all_findings),
            "config_violations": len(categorized["config_violations"]),
            "offensive_findings": len(categorized["offensive_findings"]),
            "critical_paths": len(categorized["critical_paths"]),
            "privilege_escalation_paths": len(categorized["privilege_escalation"]),
            "result": results
        }

    except Exception as e:
        logger.error(f"Enhanced offensive scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan/offensive")
async def offensive_security_scan(
    profile: str = "default",
    region: str = "us-east-1",
    req: Request = None
):
    """
    Run CloudFox offensive security scan via MCP server

    This provides attacker's perspective:
    - Attack path enumeration
    - Privilege escalation vectors
    - Secret discovery
    - Trust relationship exploitation
    """
    user_id = get_user_id(req)
    logger.info(f"⚔️ Offensive scan: user={user_id}")

    try:
        result = await mcp_scanner.run_offensive_scan(
            user_id=user_id,
            profile=profile,
            region=region
        )

        # Store findings in database
        if result.get("findings"):
            scan_id = await _store_offensive_scan(result)
            result["stored_scan_id"] = scan_id

        return {
            "status": "completed",
            "scan_type": "offensive",
            "architecture": "MCP-SERVER",
            "result": result
        }

    except Exception as e:
        logger.error(f"Offensive scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/scan")
async def intelligent_scan(request: ScanRequest, req: Request):
    """AI-orchestrated multi-cloud scan with MCP architecture"""
    logger.info(f"🧠 Intelligent scan request: {request.message}")

    user_id = get_user_id(req)
    logger.info(f"👤 User ID: {user_id}")

    # 🔁 AI decides which providers to scan
    valid_providers = ["aws", "gcp", "openai"]

    providers = []
    account_ids = {}

    try:
        if not orchestrator_client:
            raise RuntimeError("OPENAI_API_KEY is not configured")

        response = orchestrator_client.chat.completions.create(
            model=OPENAI_AGENT_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a security orchestration AI.\n"
                        "From the user's message, decide which of these providers to scan:\n"
                        f"- {', '.join(valid_providers)}\n\n"
                        "Return ONLY a JSON object with this exact shape:\n"
                        "{\n"
                        '  "providers": ["aws", "gcp", "openai"],\n'
                        '  "account_ids": {\n'
                        '    "aws": "optional-account-id",\n'
                        '    "gcp": "optional-project-id"\n'
                        "  }\n"
                        "}\n"
                    ),
                },
                {"role": "user", "content": request.message},
            ],
            temperature=0.1,
        )

        plan_raw = response.choices[0].message.content.strip()
        if plan_raw.startswith("```"):
            parts = plan_raw.split("```")
            if len(parts) >= 2:
                plan_raw = parts[1].strip()

        plan = json.loads(plan_raw)
        providers = [
            p.lower() for p in plan.get("providers", []) if isinstance(p, str)
        ]
        providers = [p for p in providers if p in valid_providers]
        account_ids = plan.get("account_ids", {})
        if not isinstance(account_ids, dict):
            account_ids = {}

    except Exception as e:
        logger.error("LLM plan extraction error: %s", e)
        providers = []
        account_ids = {}

    # 🔁 Heuristic fallbacks
    msg_lower = request.message.lower()
    if "aws" in msg_lower and "aws" in valid_providers and "aws" not in providers:
        providers.append("aws")
    if ("gcp" in msg_lower or "google cloud" in msg_lower) and "gcp" in valid_providers and "gcp" not in providers:
        providers.append("gcp")
    if "openai" in msg_lower and "openai" in valid_providers and "openai" not in providers:
        providers.append("openai")

    if not providers:
        providers = list(valid_providers)

    logger.info(f"🎯 Final providers to scan: {providers}")

    # Run MCP scan
    try:
        scan_results = await mcp_scanner.scan_multi_cloud(
            user_id=user_id,
            providers=providers,
            account_ids=account_ids,
            deep_scan=request.deep_scan
        )

        # Store results
        stored_ids = []
        for provider, result in scan_results["results"].items():
            scan_id = await _store_mcp_scan_result(
                provider=provider,
                result=result,
                credential_id=scan_results["credential_mapping"].get(provider)
            )
            stored_ids.append(scan_id)

        # AI analysis
        try:
            scan_result_objects = [
                _mcp_to_scan_result(provider, result)
                for provider, result in scan_results["results"].items()
            ]
            ai_analysis = await ai_engine.analyze_scan_results(scan_result_objects)
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            ai_analysis = {"error": "AI unavailable"}

        return {
            "status": "completed",
            "scan_ids": stored_ids,
            "providers_scanned": providers,
            "deep_scan_enabled": request.deep_scan,
            "architecture": "MCP-SERVER",
            "total_resources": sum(len(r.get("resources", {})) for r in scan_results["results"].values()),
            "total_findings": sum(len(r.get("findings", [])) for r in scan_results["results"].values()),
            "vulnerability_tools_used": list(vuln_scanner.tools_available.keys())
            if request.deep_scan
            else [],
            "ai_analysis": ai_analysis.get("ai_analysis", ""),
            "remediation_plan": ai_analysis.get("remediation_plan", {}),
            "executive_summary": ai_analysis.get("executive_summary", {}),
        }

    except Exception as e:
        logger.error(f"❌ Scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")

@app.get("/api/mcp/resources/{provider}")
async def discover_provider_resources(provider: str, req: Request):
    """
    Discover resources in a cloud provider using MCP server
    """
    user_id = get_user_id(req)
    logger.info(f"🔍 Discovering {provider} resources for user={user_id}")

    try:
        # Initialize server if needed
        await mcp_scanner.initialize_provider_servers(user_id, [provider])

        # Discover resources
        resources = await mcp_scanner.discover_resources(provider)

        return {
            "provider": provider,
            "resources": resources,
            "timestamp": datetime.utcnow().isoformat()
        }

    except Exception as e:
        logger.error(f"Resource discovery failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mcp/architecture/status")
async def mcp_architecture_status():
    """
    Get MCP server architecture status
    """
    servers = mcp_server_manager.list_servers()

    return {
        "architecture": "MCP-SERVER",
        "servers": servers,
        "total_servers": len(servers),
        "running_servers": sum(1 for s in servers if s.get("running")),
        "capabilities": [
            "Multi-cloud scanning",
            "Offensive security testing",
            "Protocol-based communication",
            "Resource discovery",
            "Tool orchestration"
        ]
    }

# ============================================================
# REST OF ENDPOINTS (unchanged)
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    try:
        with open("/app/frontend/index.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        try:
            with open("frontend/index.html", "r") as f:
                return f.read()
        except:
            return """
            <html>
                <body style="font-family: Arial; padding: 40px; background: #1a1f3a; color: white;">
                    <h1>🚀 CloudGuard Security Scanner</h1>
                    <p>AI-powered multi-cloud security scanning with vulnerability detection</p>
                    <p><a href="/dashboard" style="color: #667eea;">Go to Dashboard</a></p>
                </body>
            </html>
            """

@app.get("/cloudguard-theme.css", include_in_schema=False)
async def cloudguard_theme():
    try:
        return Response(read_frontend_asset("cloudguard-theme.css"), media_type="text/css")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Theme asset not found")


@app.get("/cloudguard-ui.js", include_in_schema=False)
async def cloudguard_ui():
    try:
        return Response(read_frontend_asset("cloudguard-ui.js"), media_type="application/javascript")
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="UI asset not found")

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    try:
        with open("/app/frontend/dashboard.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        try:
            with open("frontend/dashboard.html", "r") as f:
                return f.read()
        except:
            return "<h1>Dashboard HTML not found</h1>"


@app.get("/operations", response_class=HTMLResponse)
@app.get("/operations.html", response_class=HTMLResponse)
async def operations_page():
    try:
        return HTMLResponse(read_frontend_asset("operations.html"))
    except FileNotFoundError:
        return HTMLResponse("<h1>Operations page not found</h1>", status_code=404)


@app.get("/compliance", response_class=HTMLResponse)
@app.get("/compliance.html", response_class=HTMLResponse)
async def compliance_page():
    try:
        return HTMLResponse(read_frontend_asset("compliance.html"))
    except FileNotFoundError:
        return HTMLResponse("<h1>Compliance page not found</h1>", status_code=404)


@app.get("/reason-act", response_class=HTMLResponse)
@app.get("/reason_act.html", response_class=HTMLResponse)
async def reason_act_page():
    try:
        return HTMLResponse(read_frontend_asset("reason_act.html"))
    except FileNotFoundError:
        return HTMLResponse("<h1>Reason and act page not found</h1>", status_code=404)


@app.get("/health")
async def health():
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")

        credential_manager._get_connection()
        worker_status = list_scanner_worker_statuses()

        return {
            "status": "healthy",
            "database": "connected",
            "credential_manager": "ready",
            "vulnerability_scanner": "ready",
            "scanner_workers": worker_status,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Service unhealthy: {e}")

@app.get("/history")
@app.get("/frontend/history.html")
async def serve_history_page():
    """Serve the scan history page"""
    import os
    from fastapi.responses import FileResponse

    # Try multiple possible paths for robustness in Docker/outside
    possible_paths = [
        os.path.join(os.path.dirname(__file__), "../frontend/history.html"),
        "/app/frontend/history.html",
        "frontend/history.html",
        "./frontend/history.html"
    ]

    for path in possible_paths:
        abs_path = os.path.abspath(path)
        if os.path.exists(abs_path):
            logger.info(f"Serving history page from: {abs_path}")
            return FileResponse(abs_path)

    logger.error(f"History page not found. Checked paths: {possible_paths}")
    raise HTTPException(status_code=404, detail="History page not found")

@app.get("/api/info")
async def api_info():
    return {
        "service": "CloudGuard - Multi-Cloud Security Scanner (MCP Architecture)",
        "version": "4.0.0",
        "agent_model": OPENAI_AGENT_MODEL,
        "architecture": "MCP-SERVER",
        "vulnerability_tools": vuln_scanner.tools_available,
        "credential_manager_ready": True,
        "features": [
            "User Credential Management",
            "MCP Server Architecture",
            "AI Recommendations",
            "Security Dashboard",
            "Deep Vulnerability Scanning",
            "Offensive Security Testing",
            "Kubernetes Manifest Scanning",
            "Infrastructure as Code Scanning",
        ],
    }

@app.get("/providers")
async def list_providers():
    return {
        "supported_providers": ["aws", "gcp", "openai", "kubernetes", "iac"],
        "architecture": "MCP-SERVER",
        "vulnerability_scanner_ready": len(vuln_scanner.tools_available) > 0,
        "available_vuln_tools": list(vuln_scanner.tools_available.keys()),
        "credential_manager_ready": True
    }

@app.get("/posture/dashboard")
async def posture_dashboard(scan_ids: Optional[str] = None):
    # Pass scan_ids to get_multi_cloud_summary if implemented
    # or filter here if not.
    logger.info(f"📊 Dashboard request with scan_ids={scan_ids}")
    summary = get_multi_cloud_summary(scan_ids=scan_ids)
    logger.info(f"📉 Resulting summary from DB: {summary}")

    dashboard = {
        "clouds": [],
        "total_resources": 0,
        "total_findings": 0,
        "public_resources": 0,
        "vulnerability_tools_available": vuln_scanner.tools_available,
        "timestamp": datetime.utcnow().isoformat()
    }

    for provider, res, find, public in summary:
        dashboard["clouds"].append({
            "provider": provider,
            "resources": res,
            "findings": find,
            "public": public,
        })
        dashboard["total_resources"] += res
        dashboard["total_findings"] += find
        dashboard["public_resources"] += public

    if dashboard["total_resources"]:
        risk_ratio = dashboard["total_findings"] / dashboard["total_resources"]
        score = max(0, 100 - (risk_ratio * 100))
    else:
        score = 100

    dashboard["security_score"] = round(score, 2)
    return dashboard

# Dashboard API endpoints
@app.get("/api/severity-breakdown")
async def get_severity_breakdown():
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT severity, COUNT(*) as count
                FROM findings
                GROUP BY severity
                ORDER BY
                    CASE severity
                        WHEN 'CRITICAL' THEN 1
                        WHEN 'HIGH' THEN 2
                        WHEN 'MEDIUM' THEN 3
                        WHEN 'LOW' THEN 4
                        ELSE 5
                    END
            """)
            results = cur.fetchall()

        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for severity, count in results:
            if severity in breakdown:
                breakdown[severity] = count

        return {"status": "success", "data": breakdown, "total": sum(breakdown.values())}
    except Exception as e:
        logger.exception("Failed to get severity breakdown")
        return {
            "status": "error",
            "message": str(e),
            "data": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        }

@app.get("/api/provider-breakdown")
async def get_provider_breakdown(scan_ids: Optional[str] = None):
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            query = """
                SELECT
                    r.cloud as provider,
                    COUNT(DISTINCT r.id) as resources,
                    COUNT(DISTINCT f.id) as findings
                FROM resources r
                LEFT JOIN findings f ON r.id = f.resource_id
            """
            params = []

            if scan_ids:
                try:
                    ids = [int(i.strip()) for i in scan_ids.split(",")]
                    query += " WHERE r.scan_id = ANY(%s)"
                    params.append(ids)
                except ValueError:
                    pass

            query += """
                GROUP BY r.cloud
                ORDER BY resources DESC
            """

            cur.execute(query, tuple(params))
            results = cur.fetchall()

        data = []
        for provider, resources, findings in results:
            # Calculate security score per provider
            if resources > 0:
                risk_ratio = findings / resources
                # Simple scoring: start at 100, deduct based on risk ratio
                # Capped at 0
                score = max(0, 100 - (risk_ratio * 100))
            else:
                score = 100

            data.append({
                "provider": provider,
                "resources": resources,
                "findings": findings,
                "security_score": round(score, 1)
            })

        return {
            "status": "success",
            "data": data
        }
    except Exception as e:
        logger.exception("Failed to get provider breakdown")
        return {"status": "error", "message": str(e), "data": []}

@app.get("/api/scan-history")
async def get_scan_history(days: int = 30):
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    DATE(s.started_at) as scan_date,
                    COUNT(DISTINCT s.id) as scan_count,
                    COUNT(DISTINCT f.id) as findings_count,
                    COUNT(DISTINCT CASE WHEN f.severity = 'CRITICAL' THEN f.id END) as critical_count
                FROM scans s
                LEFT JOIN findings f ON s.id = f.scan_id
                WHERE s.started_at >= NOW() - INTERVAL %s
                GROUP BY DATE(s.started_at)
                ORDER BY scan_date ASC
            """, (f"{days} days",))
            results = cur.fetchall()

        return {
            "status": "success",
            "data": [
                {
                    "date": scan_date.isoformat() if scan_date else None,
                    "scans": scan_count,
                    "findings": findings_count,
                    "critical": critical_count
                }
                for scan_date, scan_count, findings_count, critical_count in results
            ]
        }
    except Exception as e:
        logger.exception("Failed to get scan history")
        return {"status": "error", "message": str(e), "data": []}

@app.get("/api/latest-findings")
async def get_latest_findings(limit: int = 10, scan_ids: Optional[str] = None):
    try:
        conn = get_conn()
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
                JOIN resources r ON f.resource_id = r.id
            """
            params = []

            if scan_ids:
                try:
                    ids = [int(i.strip()) for i in scan_ids.split(",")]
                    query += " WHERE f.scan_id = ANY(%s)"
                    params.append(ids)
                except ValueError:
                    pass

            query += " ORDER BY f.created_at DESC LIMIT %s"
            params.append(limit)

            cur.execute(query, tuple(params))
            results = cur.fetchall()

        return {
            "status": "success",
            "data": [
                {
                    "resource_name": resource_name,
                    "cloud": cloud,
                    "severity": severity,
                    "description": description,
                    "tool": tool,
                    "timestamp": created_at.isoformat() if created_at else None
                }
                for resource_name, cloud, severity, description, tool, created_at in results
            ]
        }
    except Exception as e:
        logger.exception("Failed to get latest findings")
        return {"status": "error", "message": str(e), "data": []}

@app.get("/api/scans")
async def get_scans(
    user_id: str,
    limit: int = 20,
    offset: int = 0,
    provider: Optional[str] = None,
    status: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None
):
    """Get all scans with filters and pagination for history page"""
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            # Build query with filters
            query = """
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
                WHERE 1=1
            """
            params = []

            # Add filters
            if provider:
                query += " AND s.cloud = %s"
                params.append(provider)

            if status:
                query += " AND s.status = %s"
                params.append(status)

            if from_date:
                query += " AND s.started_at >= %s"
                params.append(from_date)

            if to_date:
                query += " AND s.started_at <= %s"
                params.append(to_date)

            query += """
                GROUP BY s.id, s.cloud, s.account_id, s.status, s.started_at, s.duration_seconds
                ORDER BY s.started_at DESC
                LIMIT %s OFFSET %s
            """
            params.extend([limit, offset])

            cur.execute(query, tuple(params))
            results = cur.fetchall()

            # Get total count
            count_query = "SELECT COUNT(*) FROM scans WHERE 1=1"
            count_params = []
            if provider:
                count_query += " AND cloud = %s"
                count_params.append(provider)
            if status:
                count_query += " AND status = %s"
                count_params.append(status)
            if from_date:
                count_query += " AND started_at >= %s"
                count_params.append(from_date)
            if to_date:
                count_query += " AND started_at <= %s"
                count_params.append(to_date)

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
                    "critical_count": critical_count
                }
                for scan_id, cloud, account_id, scan_status, started_at, duration, resource_count, finding_count, critical_count in results
            ],
            "total": total
        }
    except Exception as e:
        logger.exception("Failed to get scans")
        return {"status": "error", "message": str(e), "scans": [], "total": 0}

@app.get("/report/{scan_id}")
async def get_report(scan_id: int):
    """Get scan report"""
    return build_scan_report(scan_id)

@app.get("/report/{scan_id}/pdf")
async def get_report_pdf(scan_id: int):
    """Generate PDF report"""
    data = build_scan_report(scan_id)

    providers = data.get("providers", [])

    if not providers:
        provider_line = "Cloud Provider(s): Unknown"
    elif len(providers) == 1:
        provider_line = f"Cloud Provider: {providers[0].upper()}"
    else:
        provider_line = "Cloud Providers: " + ", ".join(p.upper() for p in providers)

    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=A4)
    width, height = A4

    y = height - 60

    # COVER TITLE
    p.setFont("Helvetica-Bold", 20)
    p.drawCentredString(width / 2, y, "CloudGuard Security Assessment Report")
    y -= 40

    p.setFont("Helvetica", 12)
    p.drawCentredString(width / 2, y, f"Scan ID: {scan_id}")
    y -= 18
    p.drawCentredString(width / 2, y, provider_line)
    y -= 18
    p.drawCentredString(width / 2, y, "Generated by CloudGuard Security Scanner v4.0 (MCP)")
    y -= 40

    # EXECUTIVE SUMMARY
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "1. Executive Summary")
    y -= 20

    p.setFont("Helvetica", 11)

    if len(providers) == 1:
        cloud_name = providers[0].upper()
        summary_text = (
            f"This assessment focused on the {cloud_name} environment. "
            f"It analyzed {data['total_resources']} resources in this cloud "
            f"and identified {data['total_findings']} security findings. "
            "The key risks are related to configuration, access control, and monitoring gaps."
        )
    else:
        clouds_str = ", ".join(p.upper() for p in providers)
        summary_text = (
            f"This assessment covered multiple cloud providers: {clouds_str}. "
            f"A total of {data['total_resources']} resources were analyzed and "
            f"{data['total_findings']} security findings were identified across these environments. "
            "The assessment highlights cross-cloud risks related to identity, access, and observability."
        )

    for line in _wrap_text(summary_text):
        p.drawString(60, y, line)
        y -= 14

    p.showPage()
    p.save()
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="cloudguard_report_{scan_id}.pdf"'
        },
    )

@app.post("/agent/chat", response_model=AgentChatResponse)
async def agent_chat(request: AgentChatRequest):
    """Chat with AI security agent"""
    reply = await run_gpt_agent(request.message)
    return AgentChatResponse(reply=reply)

@app.post("/agent/scan/explain", response_model=AgentChatResponse)
async def agent_explain_scan(request: AgentExplainScanRequest):
    """Explain scan results with AI"""
    data = build_scan_report(request.scan_id)

    prompt = f"""
You are analyzing Scan ID {request.scan_id}.

Structured Findings (JSON):
{json.dumps(data, indent=2)}

User Question:
{request.question or "Provide executive summary, key risks and a prioritized remediation plan."}
"""

    reply = await run_gpt_agent(prompt)
    return AgentChatResponse(reply=reply)

@app.post("/scan/vulnerabilities")
async def scan_vulnerabilities(request: VulnScanRequest):
    """Direct vulnerability scan endpoint"""
    logger.info(f"Vulnerability scan requested: {request.target_type} - {request.path}")

    try:
        target = ScanTarget(
            target_type=request.target_type,
            path=request.path,
            metadata=request.metadata
        )

        vulnerabilities = await vuln_scanner.scan_all(target)
        report = vuln_scanner.generate_report(vulnerabilities)

        return {
            "status": "completed",
            "target": request.path,
            "target_type": request.target_type,
            "report": report,
            "vulnerabilities": [
                {
                    "id": v.vuln_id,
                    "title": v.title,
                    "severity": v.severity.value,
                    "description": v.description[:200] + "..." if len(v.description) > 200 else v.description,
                    "affected_package": v.affected_package,
                    "fixed_version": v.fixed_version,
                    "cvss_score": v.cvss_score,
                    "tool": v.tool,
                    "references": v.references[:3]
                }
                for v in vulnerabilities[:100]
            ]
        }

    except Exception as e:
        logger.error(f"Vulnerability scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Vulnerability scan failed: {str(e)}")


# ============================================================
# ENHANCED SCAN ENDPOINTS WITH MULTI-AGENT & MEMORY
# ============================================================

@app.post("/scan/multi-cloud-enhanced")
async def multi_cloud_scan_enhanced(request: MultiCloudScanRequest, req: Request):
    """
    Enhanced multi-cloud scan with:
    - Multi-agent parallel analysis (AWS/GCP/OpenAI specialists)
    - Persistent memory tracking
    - Task management
    """
    logger.info(f"🚀 ENHANCED multi-cloud scan: {request.providers}")

    user_id = get_user_id(req)

    # Initialize MCP servers
    await initialize_mcp_servers_for_user(user_id, request.providers)

    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    # Run scans
    for provider in request.providers:
        try:
            account_id = request.account_ids.get(provider, "default") or "default"
            mcp_result = await mcp_registry.scan(
                provider=provider,
                account_id=account_id,
                options={
                    "deep_scan": request.deep_scan,
                    "offensive_scan": request.offensive_scan,
                }
            )

            scan_result_obj = _mcp_to_scan_result(provider, mcp_result)
            scan_results.append(scan_result_obj)

            credential_id = None
            if provider == "aws":
                aws_server = mcp_registry.get_plugin("aws")
                if aws_server:
                    credential_id = aws_server.config.get("credential_id")

            scan_id = await store_scan_result(
                scan_result_obj,
                aws_credential_id=credential_id,
            )
            stored_ids.append(scan_id)

            # 🆕 PROCESS WITH MEMORY SYSTEM
            findings_for_memory = [
                {
                    "provider": provider,
                    "resource_name": f.resource.name,
                    "issue": f.issue,
                    "description": f.description,
                    "severity": f.severity.value,
                    "recommendation": f.recommendation
                }
                for f in scan_result_obj.findings
            ]

            memory_stats = memory_system.process_scan_findings(
                scan_id=scan_id,
                findings=findings_for_memory
            )

            logger.info(f"📝 Memory stats: {memory_stats}")

        except Exception as e:
            logger.exception(f"Scan failed for {provider}")
            raise HTTPException(status_code=500, detail=str(e))

    # 🆕 MULTI-AGENT ANALYSIS (parallel specialist agents)
    try:
        logger.info("🤖 Running multi-agent analysis...")
        multi_agent_result = await multi_agent_analyzer.analyze(scan_results)
    except Exception as e:
        logger.error(f"Multi-agent analysis failed: {e}")
        multi_agent_result = {"error": str(e)}

    # Get memory dashboard summary
    memory_summary = memory_system.get_dashboard_summary()

    response = {
        "status": "completed",
        "architecture": "multi-agent + persistent memory",
        "scan_ids": stored_ids,
        "timestamp": datetime.utcnow().isoformat(),

        # Multi-agent analysis
        "ai_analysis": multi_agent_result,

        # Memory tracking
        "memory_summary": memory_summary,

        # Traditional metrics
        "summary": {
            "total_resources": sum(len(r.resources) for r in scan_results),
            "total_findings": sum(len(r.findings) for r in scan_results),
            "providers_scanned": request.providers,
        }
    }

    return response


# ============================================================
# MEMORY & TASK MANAGEMENT ENDPOINTS
# ============================================================

@app.get("/api/memory/dashboard")
async def get_memory_dashboard():
    """Get persistent memory dashboard summary"""
    try:
        summary = memory_system.get_dashboard_summary()

        # Get top open tasks
        open_tasks = memory_system.get_open_tasks()[:10]

        return {
            "status": "success",
            "summary": summary,
            "top_tasks": open_tasks,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get memory dashboard: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/memory/tasks")
async def get_security_tasks(
    priority: Optional[str] = None,
    status: Optional[str] = None
):
    """Get security remediation tasks"""
    try:
        from backend.ai.persistent_memory import TaskPriority

        priority_filter = TaskPriority[priority.upper()] if priority else None
        tasks = memory_system.get_open_tasks(priority=priority_filter)

        if status:
            tasks = [t for t in tasks if t["status"] == status]

        return {
            "status": "success",
            "tasks": tasks,
            "total": len(tasks)
        }
    except Exception as e:
        logger.error(f"Failed to get tasks: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/memory/finding/{finding_hash}")
async def get_finding_history(finding_hash: str):
    """Get complete history of a security finding"""
    try:
        history = memory_system.get_finding_history(finding_hash)

        if not history:
            raise HTTPException(status_code=404, detail="Finding not found")

        return {
            "status": "success",
            "history": history
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get finding history: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/memory/task/{task_id}/update")
async def update_task_status(
    task_id: int,
    status: str,
    note: Optional[str] = None
):
    """Update task status"""
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            # Update task
            cur.execute("""
                UPDATE security_tasks
                SET status = %s,
                    updated_at = NOW(),
                    resolved_at = CASE WHEN %s = 'resolved' THEN NOW() ELSE resolved_at END
                WHERE id = %s
                RETURNING finding_hash
            """, (status, status, task_id))

            result = cur.fetchone()
            if not result:
                raise HTTPException(status_code=404, detail="Task not found")

            finding_hash = result[0]

            # Add note if provided
            if note:
                memory_system._add_note(
                    finding_hash=finding_hash,
                    note_type="remediation",
                    content=note,
                    author="user"
                )

            conn.commit()

        return {
            "status": "success",
            "task_id": task_id,
            "new_status": status
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to update task: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/agent/status")
async def get_agent_status():
    """Get multi-agent system status"""
    try:
        if not multi_agent_analyzer:
            return {
                "status": "not_initialized",
                "message": "Multi-agent system not initialized"
            }

        agent_status = multi_agent_analyzer.get_agent_status()

        return {
            "status": "active",
            "architecture": "multi-agent",
            **agent_status,
            "memory_system": "active"
        }
    except Exception as e:
        logger.error(f"Failed to get agent status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
# COMPARISON ENDPOINT
# ============================================================

@app.post("/scan/compare-analysis")
async def compare_analysis_methods(request: MultiCloudScanRequest, req: Request):
    """
    Compare old single-agent vs new multi-agent analysis
    For demonstration and validation purposes
    """
    logger.info("📊 Running comparison scan...")

    user_id = get_user_id(req)
    await initialize_mcp_servers_for_user(user_id, request.providers)

    scan_results: list[ScanResult] = []

    # Run scans (same for both)
    for provider in request.providers:
        mcp_result = await mcp_registry.scan(
            provider=provider,
            account_id=request.account_ids.get(provider, "default"),
            options={"deep_scan": request.deep_scan}
        )
        scan_results.append(_mcp_to_scan_result(provider, mcp_result))

    # Method 1: Old single-agent
    import time
    start_old = time.time()
    old_analysis = await ai_engine.analyze_scan_results(scan_results)
    old_time = time.time() - start_old

    # Method 2: New multi-agent
    start_new = time.time()
    new_analysis = await multi_agent_analyzer.analyze(scan_results)
    new_time = time.time() - start_new

    return {
        "comparison": {
            "old_method": {
                "architecture": "single-agent",
                "execution_time": old_time,
                "result": old_analysis
            },
            "new_method": {
                "architecture": "multi-agent",
                "execution_time": new_time,
                "result": new_analysis,
                "speedup": f"{old_time / new_time:.2f}x"
            }
        }
    }

# ============================================================
# SCHEDULED SCANS MANAGEMENT
# ============================================================

@app.get("/scheduled_scans")
@app.get("/schedules")
async def scheduled_scans_page():
    """Serve the scheduled scans page"""
    try:
        with open("/app/frontend/scheduled_scans.html", "r") as f:
            return HTMLResponse(f.read())
    except FileNotFoundError:
        try:
            with open("frontend/scheduled_scans.html", "r") as f:
                return HTMLResponse(f.read())
        except:
            return HTMLResponse("<h1>Scheduled scans page not found</h1>")

@app.get("/api/schedules")
async def get_all_schedules(user_id: Optional[str] = None):
    """Get all scheduled scans"""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if user_id:
                cur.execute("""
                    SELECT id, user_id, providers, account_ids, deep_scan,
                           schedule, status, next_run_at, created_at
                    FROM scan_schedules
                    WHERE user_id = %s
                    ORDER BY created_at DESC
                """, (user_id,))
            else:
                cur.execute("""
                    SELECT id, user_id, providers, account_ids, deep_scan,
                           schedule, status, next_run_at, created_at
                    FROM scan_schedules
                    ORDER BY created_at DESC
                """)

            rows = cur.fetchall()

            schedules = []
            for row in rows:
                schedule_id, user_id, providers_json, account_ids_json, deep_scan, schedule_json, status, next_run_at, created_at = row

                schedules.append({
                    "id": schedule_id,
                    "user_id": user_id,
                    "providers": json.loads(providers_json) if providers_json else [],
                    "account_ids": json.loads(account_ids_json) if account_ids_json else {},
                    "deep_scan": deep_scan,
                    "schedule": schedule_json,
                    "status": status,
                    "next_run_at": next_run_at.isoformat() if next_run_at else None,
                    "created_at": created_at.isoformat() if created_at else None
                })

            return {"schedules": schedules, "total": len(schedules)}

    except Exception as e:
        logger.error(f"Failed to get schedules: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/schedules/{schedule_id}")
async def get_schedule(schedule_id: int):
    """Get a specific scheduled scan"""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                SELECT id, user_id, providers, account_ids, deep_scan,
                       schedule, status, next_run_at, created_at
                FROM scan_schedules
                WHERE id = %s
            """, (schedule_id,))

            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Schedule not found")

            schedule_id, user_id, providers_json, account_ids_json, deep_scan, schedule_json, status, next_run_at, created_at = row

            return {
                "id": schedule_id,
                "user_id": user_id,
                "providers": json.loads(providers_json) if providers_json else [],
                "account_ids": json.loads(account_ids_json) if account_ids_json else {},
                "deep_scan": deep_scan,
                "schedule": schedule_json,
                "status": status,
                "next_run_at": next_run_at.isoformat() if next_run_at else None,
                "created_at": created_at.isoformat() if created_at else None
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/schedules/{schedule_id}/run")
async def run_schedule_now(schedule_id: int, background_tasks: BackgroundTasks):
    """Run a scheduled scan immediately"""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # Get schedule details
            cur.execute("""
                SELECT user_id, providers, account_ids, deep_scan, credential_id
                FROM scan_schedules
                WHERE id = %s
            """, (schedule_id,))

            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="Schedule not found")

            user_id, providers_json, account_ids_json, deep_scan, credential_id = row

            providers = json.loads(providers_json) if providers_json else []
            account_ids = json.loads(account_ids_json) if account_ids_json else {}

            # 🛡️ Permission Check
            if "aws" in providers:
                logger.info(f"🛡️ Testing AWS permissions for schedule {schedule_id} before run...")
                try:
                    await initialize_mcp_servers_for_user(user_id, ["aws"], credential_id)
                except Exception as e:
                    if hasattr(e, 'iam_user_arn') and hasattr(e, 'recommended_policy_arn'):
                        logger.warning(f"🛡️ Permission check failed for schedule {schedule_id}")
                        iam_user_name = e.iam_user_arn.split('/')[-1] if '/' in e.iam_user_arn else e.iam_user_arn
                        return JSONResponse(
                            status_code=200,
                            content={
                                "status": "permission_required",
                                "permission_error": {
                                    "type": "missing_assume_role_permission",
                                    "iam_user_name": iam_user_name,
                                    "iam_user_arn": e.iam_user_arn,
                                    "role_arn": getattr(e, 'role_arn', None),
                                    "policy_arn": e.recommended_policy_arn,
                                    "credential_id": credential_id,
                                    "can_auto_grant": True
                                }
                            }
                        )

            scan_request = MultiCloudScanRequest(
                providers=providers,
                account_ids=account_ids,
                deep_scan=deep_scan,
                offensive_scan=True,
                user_id=user_id,
                credential_id=credential_id,
            )
            job = create_scan_job(user_id, scan_request)
            if os.getenv("SCAN_JOB_INLINE_WORKER", "true").lower() == "true":
                background_tasks.add_task(process_scan_job, job["job_id"])

            return {
                "status": "queued",
                "job_id": job["job_id"],
                "message": "Scheduled scan job queued",
            }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to run schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/schedules/{schedule_id}")
async def delete_schedule(schedule_id: int, user_id: Optional[str] = None):
    """Delete a scheduled scan"""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            if user_id:
                cur.execute("""
                    DELETE FROM scan_schedules
                    WHERE id = %s AND user_id = %s
                    RETURNING id
                """, (schedule_id, user_id))
            else:
                cur.execute("""
                    DELETE FROM scan_schedules
                    WHERE id = %s
                    RETURNING id
                """, (schedule_id,))

            deleted = cur.fetchone()
            if not deleted:
                raise HTTPException(status_code=404, detail="Schedule not found")

            conn.commit()
            return {"status": "deleted", "schedule_id": schedule_id}

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to delete schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.put("/api/schedules/{schedule_id}")
async def update_schedule(schedule_id: int, request: ScheduledScanRequest):
    """Update a scheduled scan"""
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE scan_schedules
                SET providers = %s,
                    account_ids = %s,
                    deep_scan = %s,
                    schedule = %s,
                    updated_at = NOW()
                WHERE id = %s
                RETURNING id
            """, (
                json.dumps(request.providers),
                json.dumps(request.account_ids),
                request.deep_scan,
                Json(request.schedule),
                schedule_id
            ))

            updated = cur.fetchone()
            if not updated:
                raise HTTPException(status_code=404, detail="Schedule not found")

            conn.commit()
            return {"status": "updated", "schedule_id": schedule_id}

    except HTTPException:
        raise
    except Exception as e:
        conn.rollback()
        logger.error(f"Failed to update schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# CLOUDFOX ENDPOINTS (MCP Server Architecture)
# ============================================================

@app.get("/api/cloudfox/status")
async def cloudfox_status():
    """Check CloudFox MCP server status"""
    try:
        server = mcp_server_manager.get_server("cloudfox")

        if not server:
            return {
                "available": False,
                "message": "CloudFox MCP server not initialized"
            }

        # Get status from server
        message = MCPMessage(
            method="resources/read",
            params={"uri": "cloudfox://status"}
        )

        response = await mcp_server_manager.send_request("cloudfox", message)

        if response.error:
            return {
                "available": False,
                "error": response.error
            }

        return response.result

    except Exception as e:
        logger.error(f"Failed to get CloudFox status: {e}")
        return {
            "available": False,
            "error": str(e)
        }

@app.post("/api/cloudfox/scan/secrets")
async def cloudfox_scan_secrets(
    profile: str = "default",
    region: str = "us-east-1"
):
    """Scan for exposed secrets using CloudFox MCP server"""
    try:
        message = MCPMessage(
            method="tools/call",
            params={
                "name": "cloudfox/discover_secrets",
                "arguments": {
                    "profile": profile,
                    "region": region
                }
            }
        )

        response = await mcp_server_manager.send_request("cloudfox", message)

        if response.error:
            raise HTTPException(status_code=500, detail=response.error)

        return response.result

    except Exception as e:
        logger.error(f"CloudFox secrets scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/cloudfox/scan/attack-paths")
async def cloudfox_scan_attack_paths(
    profile: str = "default",
    region: str = "us-east-1"
):
    """Enumerate attack paths using CloudFox MCP server"""
    try:
        message = MCPMessage(
            method="tools/call",
            params={
                "name": "cloudfox/enumerate_attack_paths",
                "arguments": {
                    "profile": profile,
                    "region": region
                }
            }
        )

        response = await mcp_server_manager.send_request("cloudfox", message)

        if response.error:
            raise HTTPException(status_code=500, detail=response.error)

        return response.result

    except Exception as e:
        logger.error(f"CloudFox attack path scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/cloudfox/scan/offensive")
async def cloudfox_offensive_scan(
    profile: str = "default",
    region: str = "us-east-1",
    modules: List[str] = None,
    background_tasks: BackgroundTasks = None
):
    """
    Run comprehensive offensive security scan with CloudFox MCP server
    """
    try:
        logger.info(f"Starting CloudFox offensive scan via MCP server...")

        message = MCPMessage(
            method="tools/call",
            params={
                "name": "cloudfox/offensive_scan",
                "arguments": {
                    "profile": profile,
                    "region": region,
                    "modules": modules
                }
            }
        )

        response = await mcp_server_manager.send_request("cloudfox", message)

        if response.error:
            raise HTTPException(status_code=500, detail=response.error)

        result = response.result

        # Store findings in database
        if result.get("findings"):
            scan_id = await _store_offensive_scan(result)
            result["stored_scan_id"] = scan_id

        return result

    except Exception as e:
        logger.error(f"CloudFox offensive scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# MCP SERVER MANAGEMENT ENDPOINTS
# ============================================================

@app.get("/api/mcp/servers")
async def list_mcp_servers():
    """List all registered MCP servers"""
    servers = mcp_server_manager.list_servers()
    return {
        "servers": servers,
        "total": len(servers)
    }

@app.post("/api/mcp/servers/{provider}/initialize")
async def initialize_mcp_server(provider: str, credentials: Dict[str, Any]):
    """Initialize an MCP server for a cloud provider"""
    try:
        if provider == "aws":
            server = create_aws_server(credentials)
            mcp_server_manager.register_server(server)
            await server.start()

            return {
                "status": "initialized",
                "provider": provider,
                "server_info": server.get_info()
            }

        else:
            raise HTTPException(
                status_code=400,
                detail=f"Provider '{provider}' not supported yet"
            )

    except Exception as e:
        logger.error(f"Failed to initialize MCP server: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/mcp/servers/{provider}/request")
async def send_mcp_request(provider: str, request: Dict[str, Any]):
    """Send a request to an MCP server"""
    try:
        message = MCPMessage(
            method=request.get("method"),
            params=request.get("params", {}),
            id=request.get("id")
        )

        response = await mcp_server_manager.send_request(provider, message)

        return response.to_dict()

    except Exception as e:
        logger.error(f"MCP request failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/mcp/servers/{provider}/tools")
async def list_mcp_tools(provider: str):
    """List tools available from an MCP server"""
    try:
        message = MCPMessage(method="tools/list")
        response = await mcp_server_manager.send_request(provider, message)

        return response.to_dict()

    except Exception as e:
        logger.error(f"Failed to list tools: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/mcp/servers/{provider}/tools/{tool_name}")
async def call_mcp_tool(provider: str, tool_name: str, arguments: Dict[str, Any] = {}):
    """Call a tool on an MCP server"""
    try:
        message = MCPMessage(
            method="tools/call",
            params={
                "name": f"{provider}/{tool_name}",
                "arguments": arguments
            }
        )

        response = await mcp_server_manager.send_request(provider, message)

        return response.to_dict()

    except Exception as e:
        logger.error(f"Tool call failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


async def store_scan_result(
    result: ScanResult,
    aws_credential_id: int | None = None,
) -> int:
    conn = get_conn()
    try:
        account_id = result.account_id or "default"
        logger.info(f"DEBUG store_scan_result got aws_credential_id={aws_credential_id}")

        scan_id = create_scan_record(account_id, result.provider, aws_credential_id)

        resource_id_map: dict[str, int] = {}

        for r in result.resources:
            resource_id = store_resource(
                scan_id,
                result.provider,
                r.resource_type,
                r.name,
                r.config,
                r.is_public,
            )
            resource_id_map[r.name] = resource_id

        for f in result.findings:
            resource_id = resource_id_map.get(f.resource.name)
            if not resource_id:
                with conn.cursor() as cur:
                    cur.execute(
                        "SELECT id FROM resources WHERE scan_id=%s AND name=%s LIMIT 1",
                        (scan_id, f.resource.name),
                    )
                    row = cur.fetchone()
                    if row:
                        resource_id = row[0]
            if not resource_id:
                continue

            description_with_tool = (
                f"[{f.detection_tool}] {f.issue}: {f.description}"
                if f.detection_tool
                else f.description
            )
            store_finding(
                scan_id,
                resource_id,
                f.severity.value,
                description_with_tool,
                result.provider,
            )

            if getattr(f, "vuln_metadata", None):
                store_vulnerability(
                    scan_id,
                    resource_id,
                    f.vuln_metadata,
                )

        conn.commit()
        logger.info(f"Stored scan {scan_id}")
        return scan_id
    except Exception:
        conn.rollback()
        logger.exception("Failed to store scan result")
        raise
# ============================================================
# DEBUG ENDPOINTS
# ============================================================

@app.get("/api/debug/credentials/{user_id}")
async def debug_user_credentials(user_id: str):
    """Debug endpoint to check user credentials status"""
    try:
        from backend.credentials.manager import credential_manager

        # Get all credentials for user
        all_creds = credential_manager.get_all_user_credentials(user_id)

        # Get default credentials
        aws_default = credential_manager.get_default_credential(user_id, "aws")
        gcp_default = credential_manager.get_default_credential(user_id, "gcp")
        openai_default = credential_manager.get_default_credential(user_id, "openai")

        return {
            "user_id": user_id,
            "total_credentials": len(all_creds),
            "credentials_by_provider": {
                "aws": len([c for c in all_creds if c['cloud_provider'] == 'aws']),
                "gcp": len([c for c in all_creds if c['cloud_provider'] == 'gcp']),
                "openai": len([c for c in all_creds if c['cloud_provider'] == 'openai']),
            },
            "default_credentials": {
                "aws": {
                    "exists": aws_default is not None,
                    "id": aws_default.id if aws_default else None,
                    "name": aws_default.credential_name if aws_default else None,
                    "valid": aws_default.is_valid if aws_default else None,
                } if aws_default else None,
                "gcp": {
                    "exists": gcp_default is not None,
                    "id": gcp_default.id if gcp_default else None,
                } if gcp_default else None,
                "openai": {
                    "exists": openai_default is not None,
                    "id": openai_default.id if openai_default else None,
                } if openai_default else None,
            },
            "all_credentials": [
                {
                    "id": c['id'],
                    "provider": c['cloud_provider'],
                    "name": c['credential_name'],
                    "is_default": c['is_default'],
                    "is_valid": c['is_valid'],
                    "last_used": c['last_used'].isoformat() if c['last_used'] else None,
                }
                for c in all_creds
            ]
        }

    except Exception as e:
        logger.error(f"Debug failed: {e}")
        import traceback
        return {
            "error": str(e),
            "traceback": traceback.format_exc()
        }

@app.get("/api/debug/scheduled-scans")
async def debug_scheduled_scans():
    """Debug endpoint to check scheduled scans"""
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT
                    id,
                    user_id,
                    providers,
                    status,
                    next_run_at,
                    last_run_at,
                    created_at,
                    schedule
                FROM scan_schedules
                ORDER BY created_at DESC
                LIMIT 10
            """)
            rows = cur.fetchall()

        schedules = []
        for row in rows:
            schedules.append({
                "id": row[0],
                "user_id": row[1],
                "providers": json.loads(row[2]) if row[2] else [],
                "status": row[3],
                "next_run_at": row[4].isoformat() if row[4] else None,
                "last_run_at": row[5].isoformat() if row[5] else None,
                "created_at": row[6].isoformat() if row[6] else None,
                "schedule": row[7],
            })

        # Check for due schedules
        with conn.cursor() as cur:
            cur.execute("""
                SELECT COUNT(*)
                FROM scan_schedules
                WHERE status = 'scheduled' AND next_run_at <= NOW()
            """)
            due_count = cur.fetchone()[0]

        return {
            "total_schedules": len(schedules),
            "due_schedules": due_count,
            "schedules": schedules,
            "current_time": datetime.now(timezone.utc).isoformat()
        }

    except Exception as e:
        logger.error(f"Debug failed: {e}")
        import traceback
        return {
            "error": str(e),
            "traceback": traceback.format_exc()
        }

# ============================================================
# HELPER FUNCTIONS FOR MCP → DATABASE CONVERSION
# ============================================================

# Update the _store_mcp_scan_result function in main.py
async def _store_mcp_scan_result(
    provider: str,
    result: Dict[str, Any],
    credential_id: Optional[int] = None
) -> int:
    """
    Convert MCP scan result to database format and store
    """
    # Create scan record
    scan_id = create_scan_record(
        account_id=result.get("account_id", "default"),
        cloud=provider,
        aws_credential_id=credential_id if provider == "aws" else None
    )

    # Store resources
    resource_id_map = {}
    for resource in result.get("resources", {}).values():
        if isinstance(resource, dict):
            resource_id = store_resource(
                scan_id=scan_id,
                cloud=provider,
                resource_type=resource.get("type", "unknown"),
                name=resource.get("name", "unnamed"),
                config=resource.get("config", {}),
                is_public=resource.get("is_public", False)
            )
            resource_id_map[resource.get("name")] = resource_id

    # Store regular findings
    for finding in result.get("findings", []):
        resource_name = finding.get("resource", {}).get("name")
        resource_id = resource_id_map.get(resource_name)

        if resource_id:
            source = finding.get("source", "MCP-SERVER")
            if source == "cloudfox":
                validated_by = "CLOUDFOX-MCP"
            else:
                validated_by = "MCP-SERVER"

            store_finding(
                scan_id=scan_id,
                resource_id=resource_id,
                severity=finding.get("severity", "MEDIUM"),
                description=finding.get("description", ""),
                source=validated_by  # Mark CloudFox findings
            )

    logger.info(f"✅ Stored MCP scan result: scan_id={scan_id}, cloudfox_findings={len([f for f in result.get('findings', []) if f.get('source') == 'cloudfox'])}")
    return scan_id

def _mcp_to_scan_result(provider: str, mcp_result: Dict[str, Any]):
    """
    Convert MCP result to ScanResult object for AI analysis
    """


    # Convert resources
    resources_raw = mcp_result.get("resources", [])
    if isinstance(resources_raw, dict):
        resources_list = list(resources_raw.values())
    else:
        resources_list = resources_raw

    resources = []
    for res in resources_list:
        if isinstance(res, dict):
            resources.append(CloudResource(
                provider=provider,
                resource_type=res.get("resource_type") or res.get("type", "unknown"),
                name=res.get("name", "unnamed"),
                region=res.get("region", "global"),
                config=res.get("config", {}),
                is_public=res.get("is_public", False)
            ))

    # Convert findings
    findings = []
    for f in mcp_result.get("findings", []):
        # Find corresponding resource
        resource = next(
            (r for r in resources if r.name == f.get("resource", {}).get("name")),
            resources[0] if resources else None
        )

        if resource:
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity[f.get("severity", "MEDIUM")],
                issue=f.get("issue", "Security Issue"),
                description=f.get("description", ""),
                recommendation=f.get("recommendation", ""),
                compliance=f.get("compliance", []),
                detection_tool=f.get("detection_tool") or f.get("tool") or "MCP-SERVER",
                tool_category=f.get("tool_category")
            ))

    return ScanResult(
        provider=provider,
        account_id=mcp_result.get("account_id", "default"),
        resources=resources,
        findings=findings,
        scan_duration=mcp_result.get("scan_duration", 0.0),
        errors=mcp_result.get("errors", [])
    )

# ============================================================
# APPLICATION STARTUP
# ============================================================

@app.on_event("startup")
async def startup_mcp_architecture():
    """
    Initialize MCP server architecture
    No credentials needed at startup - servers initialized per-scan
    """
    logger.info("🚀 CloudGuard with MCP Server Architecture")
    logger.info("📊 Version: 4.0.0 (MCP-BASED)")

    # Log available vulnerability tools
    logger.info(f"🔧 Vulnerability tools: {list(vuln_scanner.tools_available.keys())}")

    # Check CloudFox availability
    if cloudfox_scanner.available:
        logger.info(f"✅ CloudFox available: {cloudfox_scanner.cloudfox_path}")
    else:
        logger.warning("⚠️ CloudFox not found - offensive scans unavailable")

    logger.info("✅ MCP server architecture ready")

@app.on_event("shutdown")
async def shutdown_mcp_architecture():
    """Cleanup MCP servers"""
    logger.info("🛑 Shutting down MCP servers")
    await mcp_scanner.cleanup()
    vuln_integration.cleanup()

@app.on_event("startup")
async def startup_enhanced():
    """Initialize enhanced AI systems"""
    global multi_agent_analyzer

    logger.info("🤖 Initializing Multi-Agent Analysis System...")
    multi_agent_analyzer = get_multi_agent_analyzer(os.getenv("OPENAI_API_KEY"))

    logger.info("🧠 Initializing Persistent Memory System...")
    memory_system._ensure_tables_exist()

    logger.info("✅ Enhanced AI systems ready")

# ============================================================
# UVICORN ENTRYPOINT
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )

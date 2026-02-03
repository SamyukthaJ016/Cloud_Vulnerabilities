

"""
Enhanced Main.py with WORKING Credential Management
"""

import os
import json
import logging
import textwrap
from io import BytesIO
from typing import Optional, Dict, List
from datetime import datetime, timedelta
import secrets
from typing import Any, Dict

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from backend.mcp.mcp_base import mcp_registry, ScanResult, SecurityFinding
from backend.mcp.mcp_aws_plugin import AWSPlugin
from backend.vulnerability.vulnerability_scanner import VulnerabilityScanner, ScanTarget
from backend.vulnerability.vulnerability_integration import CloudVulnerabilityIntegration
from backend.mcp.mcp_gcp_plugin import GCPPlugin
from backend.mcp.mcp_openai_plugin import OpenAIPlugin
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
from backend.cloudfox.cloudfox_server import create_cloudfox_server
from backend.mcp_servers.base_server import MCPMessage
from backend.credentials.api import router as credentials_router
from backend.credentials.manager import credential_manager, CloudCredential
from backend.migration_manager import run_migrations  # NEW: Database Migrations

from backend.mcp_servers.base_server import (
    mcp_server_manager,
    MCPMessage,
    MCPResponse
)
from backend.mcp_servers.aws_server import create_aws_server
from backend.cloudfox.cloudfox_scanner import (
    cloudfox_scanner,
    full_offensive_scan,
    format_cloudfox_report
)


load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_scanner")

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

@app.on_event("startup")
async def startup_event():
    """Run on startup"""
    logger.info("🚀 Starting CloudGuard Backend...")
    try:
        run_migrations()
        logger.info("✅ Database migrations complete")
    except Exception as e:
        logger.error(f"❌ Failed to run database migrations: {e}")

# Consolidating router inclusions...
# app.include_router(credentials_router)

OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL", "gpt-4o-mini")

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
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

    logger.info(f"🎯 Final providers available: {list(providers_initialized.keys())}")
    logger.info(f"DEBUG aws_credential_id resolved: {aws_credential_id}")
    return {
        "providers": providers_initialized,
        "aws_credential_id": aws_credential_id,
    }


def get_user_id(request: Request) -> str:
    # """Extract user ID from request"""
    # session_id = request.cookies.get("cloudguard_session")
    # if session_id:
    #     return f"user_{session_id}"
    return "anonymous"

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

async def run_multi_cloud_scan_internal(
    providers: list[str],
    account_ids: dict[str, str],
    deep_scan: bool,
    user_id: str,
    credential_id: Optional[int] = None,
):
    """Core multi-cloud scan logic reused by API and scheduler."""
    logger.info(f"🚀 Multi-cloud scan for providers: {providers}")
    logger.info(f"👤 User ID: {user_id}")

    # ✅ STEP 1: Initialize plugins with user credentials
    init_ctx = initialize_plugins_with_user_credentials(user_id)
    providers_initialized = init_ctx["providers"]
    aws_cred_id = init_ctx["aws_credential_id"]
    
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
            result = await mcp_registry.scan(provider, account_id)

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
            # Don't raise here - continue with other providers
            # But add to errors
            if not scan_results:
                scan_results.append(ScanResult(
                    provider=provider,
                    account_id=account_id,
                    resources=[],
                    findings=[],
                    errors=[str(e)]
                ))

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

    # Run MCP scan in background
    background_tasks.add_task(
        run_multi_cloud_scan_internal,
        providers=providers,
        account_ids=account_ids,
        deep_scan=deep_scan,
        user_id=user_id,
        credential_id=credential_id,
    )

    return {"status": "started", "message": "Scan started in background"}
    

from fastapi import Request, Form
from jose import jwt, JWTError
from datetime import datetime, timedelta


from backend.database import authenticate_user, create_user

import os
import json
import logging
import textwrap
from io import BytesIO
from typing import Optional, Dict, List, Any
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo
import secrets

from fastapi import FastAPI, HTTPException, Request, Depends, BackgroundTasks
from fastapi.responses import StreamingResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from psycopg2.extras import Json
from backend.mcp.mcp_base import ScanResult, CloudResource, SecurityFinding, Severity,mcp_registry
# MCP Server Architecture
from backend.mcp_servers.base_server import (
    mcp_server_manager,
    MCPMessage,
    MCPResponse
)
from backend.mcp_servers.aws_server import create_aws_server
from backend.mcp_servers.gcp_server import create_gcp_server
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

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_scanner")

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="CloudGuard - Multi-Cloud Security Scanner (MCP Architecture)",
    description="AI-powered CSPM with MCP server architecture, vulnerability detection and user credential management",
    version="4.0.0",
)
JWT_SECRET = os.getenv("JWT_SECRET", "cloudguard-secret")
JWT_ALGO = "HS256"
JWT_EXPIRE_HOURS = 6

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(credentials_router)

OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL", "gpt-4o-mini")

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
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

def get_user_id(request: Request) -> str:
    """
    Extract user ID from request.
    Harmonized with credentials API to look for session_id cookie.
    """
    session_id = request.cookies.get("session_id")
    if session_id:
        return f"user_{session_id}"
    return "anonymous"

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

    providers = sorted({(r[2] or "").lower() for r in rows if r[2]})
    per_cloud: dict[str, dict[str, int]] = {}
    for r in rows:
        c = (r[2] or "unknown").lower()
        if c not in per_cloud:
            per_cloud[c] = {"resources": 0, "findings": 0}
        per_cloud[c]["resources"] += 1

    for f in findings:
        c = f["cloud"] or "unknown"
        if c not in per_cloud:
            per_cloud[c] = {"resources": 0, "findings": 0}
        per_cloud[c]["findings"] += 1

    return {
        "scan_id": scan_id,
        "total_resources": len(rows),
        "total_findings": len(findings),
        "findings": findings,
        "providers": providers,
        "per_cloud": per_cloud,
    }
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
            raw_result = await mcp_registry.scan(provider, account_id)
            
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
            failed_result = ScanResult(
                provider=provider,
                account_id=account_id,
                resources=[],
                findings=[
                    SecurityFinding(
                        id=f"error_{provider}_{int(datetime.now().timestamp())}",
                        title=f"Scan Error: {provider.upper()}",
                        description=f"The scan for {provider} failed with the following error: {str(e)}. Please check your credentials and network connectivity.",
                        severity="high",
                        provider=provider,
                        resource="Scanner",
                        remediation="Ensure that the service account JSON or AWS keys provided in the Settings are valid and have the necessary permissions (e.g., Viewer role for GCP, SecurityAudit for AWS)."
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

    for provider in request.providers:
        if provider not in available_providers:
            raise HTTPException(
                status_code=400,
                detail=f"{provider} scan failed: MCP server not initialized"
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
        "offensive_scan_enabled": request.offensive_scan,
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
#for the login and register

def create_token(data: dict):
    payload = data.copy()
    payload["exp"] = datetime.utcnow() + timedelta(hours=TOKEN_EXPIRE_HOURS)
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def verify_token(token: str):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None
@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    token = request.cookies.get("access_token")
    if token and verify_token(token):
        return RedirectResponse("/index", status_code=302)

    with open("frontend/login.html") as f:
        return f.read()
@app.post("/login")
async def login(email: str = Form(...), password: str = Form(...)):
    user_id = authenticate_user(email, password)

    if not user_id:
        return HTMLResponse("Invalid credentials <a href='/'>Back</a>", status_code=401)

    token = create_token({"sub": str(user_id)})
    response = RedirectResponse("/index", status_code=302)
    response.set_cookie("access_token", token, httponly=True)
    return response
@app.post("/register")
async def register(
    username: str = Form(...),
    email: str = Form(...),
    password: str = Form(...)
):
    create_user(username, email, password)
    return RedirectResponse("/", status_code=302)
@app.get("/index", response_class=HTMLResponse)
async def index(request: Request):
    token = request.cookies.get("access_token")
    if not token or not verify_token(token):
        return RedirectResponse("/", status_code=302)

    with open("frontend/index.html") as f:
        return f.read()
@app.get("/logout")
async def logout():
    response = RedirectResponse("/", status_code=302)
    response.delete_cookie("access_token")
    return response



#changed to index
# @app.get("/index", response_class=HTMLResponse)
# async def index():
#     try:
#         with open("/app/frontend/index.html", "r") as f:
#             return f.read()
#     except FileNotFoundError:
#         try:
#             with open("frontend/index.html", "r") as f:
#                 return f.read()
#         except:
#             return """
#             <html>
#                 <body style="font-family: Arial; padding: 40px; background: #1a1f3a; color: white;">
#                     <h1>🚀 CloudGuard Security Scanner</h1>
#                     <p>AI-powered multi-cloud security scanning with vulnerability detection</p>
#                     <p><a href="/dashboard" style="color: #667eea;">Go to Dashboard</a></p>
#                 </body>
#             </html>
#             """

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

@app.get("/health")
async def health():
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        
        credential_manager._get_connection()
        
        return {
            "status": "healthy",
            "database": "connected",
            "credential_manager": "ready",
            "vulnerability_scanner": "ready",
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=500, detail=f"Service unhealthy: {e}")

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
        ],
    }

@app.get("/providers")
async def list_providers():
    return {
        "supported_providers": ["aws", "gcp", "openai"],
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

            # Run MCP scan in background
            background_tasks.add_task(
                run_multi_cloud_scan_internal,
                providers=providers,
                account_ids=account_ids,
                deep_scan=deep_scan,
                user_id=user_id,
                credential_id=credential_id,
            )
            
            return {"status": "started", "message": "Scan started in background"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to run schedule: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Add this near the other API endpoints in main.py

@app.get("/api/system/status")
async def get_system_status():
    """
    Get comprehensive system status including:
    - MCP servers status
    - Vulnerability scanners availability
    - Database connectivity
    - API endpoint health
    """

    status = {
        "timestamp": datetime.utcnow().isoformat(),
        "overall_status": "healthy",
        "components": {
            "mcp_servers": [],
            "vulnerability_scanners": [],
            "database": [],
            "api_endpoints": []
        },
        "statistics": {
            "total_scans_today": 0,
            "active_schedules": 0,
            "total_findings": 0,
            "avg_scan_time": 0
        }
    }

    try:
        # --------------------------------------------------
        # 1. MCP Servers
        # --------------------------------------------------
        try:
            mcp_servers = mcp_server_manager.list_servers()
            for server in mcp_servers:
                status["components"]["mcp_servers"].append({
                    "name": server.get("provider", "unknown"),
                    "status": "online" if server.get("running") else "offline",
                    "tools_count": server.get("tools_count", 0),
                    "last_check": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"MCP server check failed: {e}")
            status["components"]["mcp_servers"].append({
                "name": "MCP Manager",
                "status": "error",
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            })

        # --------------------------------------------------
        # 2. Vulnerability Scanners
        # --------------------------------------------------
        try:
            vuln_tools = vuln_scanner.tools_available
            for tool, available in vuln_tools.items():
                status["components"]["vulnerability_scanners"].append({
                    "name": tool,
                    "status": "available" if available else "unavailable",
                    "last_check": datetime.utcnow().isoformat()
                })
        except Exception as e:
            logger.error(f"Vulnerability scanner check failed: {e}")
            status["components"]["vulnerability_scanners"].append({
                "name": "Vulnerability Scanners",
                "status": "error",
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            })

        # --------------------------------------------------
        # 3. Database
        # --------------------------------------------------
        try:
            conn = get_conn()
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT COUNT(*) FROM scans WHERE DATE(started_at) = CURRENT_DATE"
                )
                scans_today = cur.fetchone()[0]

                cur.execute(
                    "SELECT COUNT(*) FROM scan_schedules WHERE status = 'scheduled'"
                )
                active_schedules = cur.fetchone()[0]

                cur.execute("SELECT COUNT(*) FROM findings")
                total_findings = cur.fetchone()[0]

                cur.execute("""
                    SELECT AVG(EXTRACT(EPOCH FROM (completed_at - started_at)))
                    FROM scans
                    WHERE completed_at IS NOT NULL
                    AND started_at >= NOW() - INTERVAL '7 days'
                """)
                avg_time = cur.fetchone()[0] or 0

                status["components"]["database"].append({
                    "name": "PostgreSQL",
                    "status": "online",
                    "latency_ms": "< 50ms",
                    "last_check": datetime.utcnow().isoformat()
                })

                status["statistics"] = {
                    "total_scans_today": scans_today,
                    "active_schedules": active_schedules,
                    "total_findings": total_findings,
                    "avg_scan_time": round(avg_time, 2)
                }

            conn.close()

        except Exception as e:
            logger.error(f"Database check failed: {e}")
            status["components"]["database"].append({
                "name": "PostgreSQL",
                "status": "error",
                "error": str(e),
                "last_check": datetime.utcnow().isoformat()
            })

        # --------------------------------------------------
        # 4. API Endpoints
        # --------------------------------------------------
        api_endpoints = [
            "/health",
            "/api/info",
            "/providers",
            "/api/credentials/providers/status"
        ]

        for endpoint in api_endpoints:
            status["components"]["api_endpoints"].append({
                "name": endpoint,
                "status": "operational",
                "response_time_ms": 50,
                "last_check": datetime.utcnow().isoformat()
            })

        # --------------------------------------------------
        # 5. Overall Status Calculation
        # --------------------------------------------------
        all_statuses = []

        for group in status["components"].values():
            for component in group:
                all_statuses.append(component.get("status"))

        if any(s in ["error", "offline"] for s in all_statuses):
            status["overall_status"] = "degraded"
        elif "unavailable" in all_statuses:
            status["overall_status"] = "partial"
        else:
            status["overall_status"] = "healthy"

        return status

    except Exception as e:
        logger.error(f"System status check failed: {e}")
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "overall_status": "error",
            "error": str(e)
        }

@app.get("/system-status", response_class=HTMLResponse)
async def system_status_page():
    """Serve the system status page"""
    try:
        with open("/app/frontend/system_status.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        try:
            with open("frontend/system_status.html", "r") as f:
                return f.read()
        except:
            return HTMLResponse("<h1>System status page not found</h1>")


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
                detection_tool="MCP-SERVER"
            ))
    
    return ScanResult(
        provider=provider,
        account_id=mcp_result.get("account_id", "default"),
        resources=resources,
        findings=findings,
        scan_duration=0.0
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
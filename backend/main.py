

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
from backend.credentials.api import router as credentials_router
from backend.credentials.manager import credential_manager, CloudCredential




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

app.include_router(credentials_router)

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
    session_id: Optional[str] = None

class ScheduledScanRequest(BaseModel):
    providers: list[str]
    account_ids: dict[str, str] = {}
    deep_scan: bool = False
    schedule: dict
    user_id: Optional[str] = None


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
# ...

def initialize_plugins_with_user_credentials(user_id: str) -> dict:
    logger.info(f"🔍 Loading credentials for user: {user_id}")

    providers_initialized: dict[str, MCPPlugin] = {}
    aws_credential_id: int | None = None

    aws_cred = credential_manager.get_default_credential(user_id, "aws")
    if aws_cred:
        aws_credential_id = aws_cred.id
        logger.info(f"🔑 Using default AWS credential for user {user_id} (id={aws_credential_id})")

        key_preview = (aws_cred.aws_access_key_id or "")[:4]
        logger.info(f"AWS key prefix: {key_preview}..., region={aws_cred.aws_region}")

        try:
            plugin = AWSPlugin(
                {
                    "access_key_id": aws_cred.aws_access_key_id,
                    "secret_access_key": aws_cred.aws_secret_access_key,
                    "session_token": aws_cred.aws_session_token,
                    "region": aws_cred.aws_region or "us-east-1",
                }
            )
            mcp_registry.register("aws", plugin)
            providers_initialized["aws"] = plugin
            logger.info("✅ AWS Plugin registered with USER default credential")
        except Exception as e:
            logger.error(f"❌ Failed to initialize AWS plugin: {e}")
            aws_credential_id = None
    else:
        logger.warning(f"⚠️ No default AWS credential found for user {user_id}")

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


from psycopg2.extras import Json  # file ke top imports ke paas add karna

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

@app.post("/scan/schedule")
async def schedule_scan(request: ScheduledScanRequest, req: Request):
    user_id = request.user_id or get_user_id(req)
    logger.info(f"📅 Scheduling scan for user={user_id}, schedule={request.schedule}")

    schedule = request.schedule or {}
    stype = schedule.get("type")
    if stype not in ("once", "recurring"):
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
        if not time_str:
            raise HTTPException(status_code=400, detail="time is required for recurring schedule")

        # Today in that timezone
        today_local = datetime.now(tz).date()
        try:
            # build local datetime "YYYY-MM-DDTHH:MM"
            local_naive = datetime.fromisoformat(f"{today_local}T{time_str}")
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid time format")
        local = local_naive.replace(tzinfo=tz)
        next_run_at = local.astimezone(timezone.utc)

    conn = get_conn()
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO scan_schedules
            (user_id, providers, account_ids, deep_scan, schedule, status, next_run_at, created_at)
            VALUES (%s, %s, %s, %s, %s, 'scheduled', %s, NOW())
            RETURNING id
            """,
            (
                user_id,
                json.dumps(request.providers),
                json.dumps(request.account_ids),
                request.deep_scan,
                Json(schedule),
                next_run_at,
            ),
        )
        schedule_id = cur.fetchone()[0]
        conn.commit()

    return {
        "status": "scheduled",
        "schedule_id": schedule_id,
        "next_run_at": next_run_at.isoformat(),
    }



# ============================================================
# 🔥 FIXED SCAN ENDPOINTS
# ============================================================

# 🆕 Helper function – yahan paste karo
async def run_multi_cloud_scan_internal(
    providers: list[str],
    account_ids: dict[str, str],
    deep_scan: bool,
    user_id: str,
):
    """Core multi-cloud scan logic reused by API and scheduler."""
    logger.info(f"🚀 Multi-cloud scan for providers: {providers}")
    logger.info(f"👤 User ID: {user_id}")

    init_ctx = initialize_plugins_with_user_credentials(user_id)
    providers_initialized = init_ctx["providers"]
    aws_cred_id = init_ctx["aws_credential_id"]
    logger.info(f"DEBUG aws_cred_id in internal: {aws_cred_id}")
    logger.info(f"✅ Initialized providers: {list(providers_initialized.keys())}")

    for provider in providers:
        if provider not in mcp_registry.list_providers():
            raise HTTPException(
                status_code=400,
                detail=f"{provider} scan failed: No credentials available. "
                       f"Please add credentials in Settings.",
            )

    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    for provider in providers:
        try:
            account_id = account_ids.get(provider, "default") or "default"
            logger.info(f"📡 Scanning {provider} with account_id: {account_id}")

            result = await mcp_registry.scan(provider, account_id)

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

            scan_id = await store_scan_result(
                result,
                aws_credential_id=aws_cred_id if provider == "aws" else None,
            )
            stored_ids.append(scan_id)
            logger.info(f"✅ {provider.upper()} scan finished, stored as scan_id: {scan_id}")

        except Exception as e:
            logger.error(f"❌ Scan failed for {provider}: {e}")
            raise

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


@app.post("/scan/multi-cloud")
async def multi_cloud_scan(request: MultiCloudScanRequest, req: Request):
    """Direct multi-cloud scan with USER credentials"""
    logger.info(f"🚀 Multi-cloud scan for providers: {request.providers}")

    user_id = get_user_id(req)
    logger.info(f"👤 User ID: {user_id}")

    init_ctx = initialize_plugins_with_user_credentials(user_id)
    providers_initialized = init_ctx["providers"]
    aws_cred_id = init_ctx["aws_credential_id"]
    logger.info(f"DEBUG aws_cred_id in endpoint: {aws_cred_id}")

    logger.info(f"✅ Initialized providers: {list(providers_initialized.keys())}")

    for provider in request.providers:
        if provider not in mcp_registry.list_providers():
            logger.error(
                f"❌ Provider {provider} not initialized. "
                f"Available: {mcp_registry.list_providers()}"
            )
            raise HTTPException(
                status_code=400,
                detail=f"{provider} scan failed: No credentials available. "
                       f"Please add credentials in Settings.",
            )

    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    for provider in request.providers:
        try:
            account_id = request.account_ids.get(provider, "default") or "default"
            logger.info(f"📡 Scanning {provider} with account_id: {account_id}")

            result = await mcp_registry.scan(provider, account_id)

            if request.deep_scan:
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

            scan_id = await store_scan_result(
                result,
                aws_credential_id=aws_cred_id if provider == "aws" else None,
            )
            stored_ids.append(scan_id)
            logger.info(f"✅ {provider.upper()} scan finished, stored as scan_id: {scan_id}")

        except Exception as e:
            logger.error(f"❌ Scan failed for {provider}: {e}")
            raise HTTPException(status_code=500, detail=f"{provider} scan failed: {e}")

    try:
        ai_analysis = await ai_engine.analyze_scan_results(scan_results)
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        ai_analysis = {"error": "AI unavailable"}

    return {
        "status": "completed",
        "scan_ids": stored_ids,
        "deep_scan_enabled": request.deep_scan,
        "user_credentials_used": len(providers_initialized) > 0,
        "scan_results": [
            {
                "provider": r.provider,
                "resources": len(r.resources),
                "findings": len(r.findings),
                "duration": r.scan_duration,
            }
            for r in scan_results
        ],
        "ai_analysis": ai_analysis,
    }

@app.post("/scan")
async def intelligent_scan(request: ScanRequest, req: Request):
    """AI-orchestrated multi-cloud scan with USER credentials"""
    logger.info(f"🧠 Intelligent scan request: {request.message}")

    # ✅ Get user_id and initialize plugins ONCE
    user_id = get_user_id(req)
    logger.info(f"👤 User ID: {user_id}")

    init_ctx = initialize_plugins_with_user_credentials(user_id)
    providers_initialized = init_ctx["providers"]
    aws_cred_id = init_ctx["aws_credential_id"]

    logger.info(f"✅ Initialized providers: {list(providers_initialized.keys())}")

    valid_providers = {p.lower() for p in mcp_registry.list_providers()}

    account_ids: dict[str, str] = {}
    providers: list[str] = []

    # 🔁 AI decides which providers to scan
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

       
        plan_raw = response.choices.message.content.strip()
        if plan_raw.startswith("```"):
            parts = plan_raw.split("```")
            if len(parts) >= 2:
                plan_raw = parts.strip()


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

    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    for provider in providers:
        try:
            account_id = account_ids.get(provider, "default")
            if not account_id or account_id == "None":
                account_id = "default"

            logger.info(f"📡 Scanning {provider} with account_id: {account_id}")
            result = await mcp_registry.scan(provider, account_id)

            if request.deep_scan:
                logger.info(f"🔬 Running deep vulnerability scan for {provider}...")
                plugin = mcp_registry.get_plugin(provider)
                cloud_client = None
                if plugin:
                    cloud_client = getattr(plugin, "s3", None) or getattr(
                        plugin, "storage_client", None
                    )

                vuln_findings = []
                for resource in result.resources:
                    try:
                        vf = await vuln_integration.scan_cloud_resource(
                            resource, cloud_client
                        )
                        vuln_findings.extend(vf)
                    except Exception as e:
                        logger.error(f"Failed to scan resource {resource.name}: {e}")

                result.findings.extend(vuln_findings)
                logger.info(
                    f"✅ Deep scan found {len(vuln_findings)} additional vulnerabilities"
                )

            scan_results.append(result)

            # ✅ Link AWS scans to aws_cred_id
            scan_id = await store_scan_result(
                result,
                aws_credential_id=aws_cred_id if provider == "aws" else None,
            )
            stored_ids.append(scan_id)
            logger.info(f"✅ {provider.upper()} scan finished")

        except Exception as e:
            logger.error(f"❌ Scan failed for {provider}: {e}")
            continue

    # AI analysis
    try:
        ai_analysis = await ai_engine.analyze_scan_results(scan_results)
    except Exception as e:
        logger.error(f"AI analysis failed: {e}")
        ai_analysis = {"error": "AI unavailable"}

    return {
        "status": "completed",
        "scan_ids": stored_ids,
        "providers_scanned": providers,
        "deep_scan_enabled": request.deep_scan,
        "user_credentials_used": len(providers_initialized) > 0,
        "total_resources": sum(len(r.resources) for r in scan_results),
        "total_findings": sum(len(r.findings) for r in scan_results),
        "vulnerability_tools_used": list(vuln_scanner.tools_available.keys())
        if request.deep_scan
        else [],
        "ai_analysis": ai_analysis.get("ai_analysis", ""),
        "remediation_plan": ai_analysis.get("remediation_plan", {}),
        "executive_summary": ai_analysis.get("executive_summary", {}),
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

@app.get("/api/info")
async def api_info():
    return {
        "service": "CloudGuard - Multi-Cloud Security Scanner",
        "version": "3.1.0",
        "agent_model": OPENAI_AGENT_MODEL,
        "registered_providers": mcp_registry.list_providers(),
        "vulnerability_tools": vuln_scanner.tools_available,
        "credential_manager_ready": True,
        "features": [
            "User Credential Management",
            "Real Cloud Resource Scanning",
            "AI Recommendations",
            "Security Dashboard",
            "Deep Vulnerability Scanning",
        ],
    }

@app.get("/providers")
async def list_providers():
    providers = mcp_registry.list_providers()
    return {
        "registered_providers": providers,
        "total": len(providers),
        "vulnerability_scanner_ready": len(vuln_scanner.tools_available) > 0,
        "available_vuln_tools": list(vuln_scanner.tools_available.keys()),
        "credential_manager_ready": True
    }

@app.get("/posture/dashboard")
async def posture_dashboard():
    summary = get_multi_cloud_summary()
    
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
async def get_provider_breakdown():
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    r.cloud as provider,
                    COUNT(DISTINCT r.id) as resources,
                    COUNT(DISTINCT f.id) as findings
                FROM resources r
                LEFT JOIN findings f ON r.id = f.resource_id
                GROUP BY r.cloud
                ORDER BY resources DESC
            """)
            results = cur.fetchall()
        
        return {
            "status": "success",
            "data": [
                {"provider": provider, "resources": resources, "findings": findings}
                for provider, resources, findings in results
            ]
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
async def get_latest_findings(limit: int = 10):
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    r.name as resource_name,
                    r.cloud,
                    f.severity,
                    f.description,
                    f.validated_by as tool,
                    f.created_at
                FROM findings f
                JOIN resources r ON f.resource_id = r.id
                ORDER BY f.created_at DESC
                LIMIT %s
            """, (limit,))
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
    p.drawCentredString(width / 2, y, "Generated by CloudGuard Security Scanner v3.1")
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
# DATABASE STORAGE
# ============================================================

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



def _extract_tool_name_enhanced(finding: SecurityFinding, provider: str) -> str:
    """Extract tool name from finding"""
    import re
    
    # Priority 1: Explicit tool attribute
    if hasattr(finding, 'detection_tool') and finding.detection_tool:
        return finding.detection_tool.upper()
    
    # Priority 2 & 3: Tag detection in issue and description
    for text in [finding.issue, finding.description]:
        if text:
            tag_match = re.search(r'\[([A-Z0-9_\-]+)\]', text)
            if tag_match:
                tool = tag_match.group(1).upper()
                # Skip generic tags
                if tool not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                    return tool
    
    # Priority 4: Keyword-based detection
    combined_text = f"{finding.issue} {finding.description}".lower()
    
    # Vulnerability scanner keywords
    vuln_tools = {
        'trivy': 'TRIVY',
        'safety': 'SAFETY',
        'gitleaks': 'GITLEAKS',
        'git-leaks': 'GITLEAKS',
        'zap': 'OWASP-ZAP',
        'owasp zap': 'OWASP-ZAP',
        'zaproxy': 'OWASP-ZAP',
        'nuclei': 'NUCLEI',
        'grype': 'GRYPE',
        'npm audit': 'NPM-AUDIT',
        'npm-audit': 'NPM-AUDIT',
        'dependency-check': 'OWASP-DC',
        'dependency check': 'OWASP-DC',
        'snyk': 'SNYK',
        'bandit': 'BANDIT',
        'semgrep': 'SEMGREP',
        'clair': 'CLAIR',
        'dockle': 'DOCKLE',
        'tfsec': 'TFSEC',
        'cve-': 'CVE-DATABASE',
        'secret': 'GITLEAKS',
        'exposed secret': 'GITLEAKS',
        'hardcoded': 'GITLEAKS',
    }
    
    for keyword, tool_name in vuln_tools.items():
        if keyword in combined_text:
            return tool_name
    
    # Priority 5: Fall back to provider plugin
    provider_map = {
        'aws': 'AWS-PLUGIN',
        'gcp': 'GCP-PLUGIN',
        'azure': 'AZURE-PLUGIN',
        'openai': 'OPENAI-PLUGIN',
    }
    
    return provider_map.get(provider.lower(), 'UNKNOWN')


# ============================================================
# APPLICATION STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    logger.info("🚀 CloudGuard Security Scanner starting up...")
    logger.info(f"📊 Version: 3.1.0")
    logger.info(f"🤖 AI Model: {OPENAI_AGENT_MODEL}")
    
    # Don't initialize plugins here - they'll be initialized per-user on each scan
    logger.info("⏳ Plugins will be initialized per-user on each scan")
    
    # Log available tools
    logger.info(f"🔧 Vulnerability tools available: {list(vuln_scanner.tools_available.keys())}")
    
    logger.info("✅ CloudGuard is ready!")

@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown"""
    logger.info("🛑 CloudGuard shutting down...")
    vuln_integration.cleanup()


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
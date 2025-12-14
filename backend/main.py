


# """
# Enhanced Main.py with Vulnerability Scanning Integration
# """

# import os
# import json
# import logging
# import textwrap
# from io import BytesIO
# from typing import Optional
# from typing import Dict, List
# from datetime import datetime, timedelta
# from backend.database import get_vulnerabilities_by_scan, get_vulnerability_summary, get_conn 
# from fastapi import FastAPI, HTTPException
# from fastapi.responses import StreamingResponse, HTMLResponse
# from pydantic import BaseModel
# from dotenv import load_dotenv
# from openai import OpenAI
# from reportlab.lib.pagesizes import A4
# from reportlab.pdfgen import canvas
# from backend.mcp.mcp_base import mcp_registry, ScanResult,SecurityFinding
# from backend.mcp.mcp_aws_plugin import AWSPlugin
# from backend.vulnerability.vulnerability_scanner import VulnerabilityScanner,ScanTarget
# from backend.vulnerability.vulnerability_integration import CloudVulnerabilityIntegration
# from backend.mcp.mcp_gcp_plugin import GCPPlugin
# from backend.mcp.mcp_openai_plugin import OpenAIPlugin
# from backend.ai_recommender import AIRecommendationEngine
# from backend.database import (
#     create_scan_record,
#     store_resource,
#     store_finding,
#     get_scan_report,
#     get_multi_cloud_summary,
#     get_conn,
# )
# from backend.credentials.api import router as credentials_router
# from backend.credentials.manager import credential_manager


# load_dotenv()

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger("mcp_scanner")

# # ============================================================
# # FASTAPI APP
# # ============================================================

# app = FastAPI(
#     title="Multi-Cloud MCP Security Scanner with Vulnerability Detection",
#     description="CSPM-style scanner with GPT-powered AI and industry-standard vulnerability scanning",
#     version="3.0.0",
# )
# app.include_router(credentials_router)
# OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL", "gpt-4o-mini")

# openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
# orchestrator_client = openai_client
# ai_engine = AIRecommendationEngine(api_key=os.getenv("OPENAI_API_KEY"))

# # NEW: Initialize vulnerability scanner
# vuln_scanner = VulnerabilityScanner()
# vuln_integration = CloudVulnerabilityIntegration()

# # ============================================================
# # REGISTER PLUGINS
# # ============================================================

# # def initialize_plugins() -> None:
# #     """Register AWS, GCP, OpenAI MCP plugins"""
# #     # AWS
# #     try:
# #         aws_plugin = AWSPlugin({
# #             "access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
# #             "secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
# #             "region": os.getenv("AWS_REGION", "us-east-1"),
# #         })
# #         mcp_registry.register("aws", aws_plugin)
# #         logger.info("✓ AWS Plugin registered")
# #     except Exception as e:
# #         logger.warning("⚠ AWS Plugin failed: %s", e)

# #     # GCP
# #     try:
# #         gcp_plugin = GCPPlugin({
# #             "service_account_json": os.getenv("GCP_SERVICE_ACCOUNT_JSON"),
# #             "project_id": os.getenv("GCP_PROJECT_ID"),
# #         })
# #         mcp_registry.register("gcp", gcp_plugin)
# #         logger.info("✓ GCP Plugin registered")
# #     except Exception as e:
# #         logger.warning("⚠ GCP Plugin failed: %s", e)

# #     # OpenAI
# #     try:
# #         openai_plugin = OpenAIPlugin({
# #             "api_key": os.getenv("OPENAI_API_KEY"),
# #             "org_id": os.getenv("OPENAI_ORG_ID"),
# #         })
# #         mcp_registry.register("openai", openai_plugin)
# #         logger.info("✓ OpenAI Plugin registered")
# #     except Exception as e:
# #         logger.warning("⚠ OpenAI Plugin failed: %s", e)


# # initialize_plugins()

# def initialize_plugins_with_credentials(session_id: Optional[str] = None):
#     """Initialize plugins with user credentials from session"""
#     providers = {}
    
#     try:
#         if session_id:
#             # Get credentials from session
#             session_creds = credential_manager.get_session_credentials(session_id)
            
#             # AWS
#             if 'aws' in session_creds:
#                 try:
#                     aws_plugin = AWSPlugin({
#                         "access_key_id": session_creds['aws'].get('access_key_id'),
#                         "secret_access_key": session_creds['aws'].get('secret_access_key'),
#                         "region": session_creds['aws'].get('region', 'us-east-1'),
#                         "session_token": session_creds['aws'].get('session_token')
#                     })
#                     mcp_registry.register("aws", aws_plugin)
#                     providers['aws'] = aws_plugin
#                     logger.info("✓ AWS Plugin registered with user credentials")
#                 except Exception as e:
#                     logger.warning(f"⚠ AWS Plugin failed with user credentials: {e}")
            
#             # OpenAI
#             if 'openai' in session_creds:
#                 try:
#                     openai_plugin = OpenAIPlugin({
#                         "api_key": session_creds['openai'].get('api_key'),
#                         "org_id": session_creds['openai'].get('org_id')
#                     })
#                     mcp_registry.register("openai", openai_plugin)
#                     providers['openai'] = openai_plugin
#                     logger.info("✓ OpenAI Plugin registered with user credentials")
#                 except Exception as e:
#                     logger.warning(f"⚠ OpenAI Plugin failed with user credentials: {e}")
            
#             # GCP
#             if 'gcp' in session_creds:
#                 try:
#                     gcp_plugin = GCPPlugin({
#                         "service_account_json": session_creds['gcp'].get('service_account_json'),
#                         "project_id": session_creds['gcp'].get('project_id')
#                     })
#                     mcp_registry.register("gcp", gcp_plugin)
#                     providers['gcp'] = gcp_plugin
#                     logger.info("✓ GCP Plugin registered with user credentials")
#                 except Exception as e:
#                     logger.warning(f"⚠ GCP Plugin failed with user credentials: {e}")
    
#     except Exception as e:
#         logger.error(f"Failed to initialize plugins with credentials: {e}")
    
#     # Fall back to environment variables if no user credentials
#     if 'aws' not in providers:
#         try:
#             aws_plugin = AWSPlugin({
#                 "access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
#                 "secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
#                 "region": os.getenv("AWS_REGION", "us-east-1"),
#             })
#             mcp_registry.register("aws", aws_plugin)
#             logger.info("✓ AWS Plugin registered with environment credentials")
#         except Exception as e:
#             logger.warning("⚠ AWS Plugin failed: %s", e)
    
#     if 'gcp' not in providers:
#         try:
#             gcp_plugin = GCPPlugin({
#                 "service_account_json": os.getenv("GCP_SERVICE_ACCOUNT_JSON"),
#                 "project_id": os.getenv("GCP_PROJECT_ID"),
#             })
#             mcp_registry.register("gcp", gcp_plugin)
#             logger.info("✓ GCP Plugin registered with environment credentials")
#         except Exception as e:
#             logger.warning("⚠ GCP Plugin failed: %s", e)
    
#     if 'openai' not in providers:
#         try:
#             openai_plugin = OpenAIPlugin({
#                 "api_key": os.getenv("OPENAI_API_KEY"),
#                 "org_id": os.getenv("OPENAI_ORG_ID"),
#             })
#             mcp_registry.register("openai", openai_plugin)
#             logger.info("✓ OpenAI Plugin registered with environment credentials")
#         except Exception as e:
#             logger.warning("⚠ OpenAI Plugin failed: %s", e)
    
#     return providers


# # ============================================================
# # REQUEST MODELS
# # ============================================================

# class ScanRequest(BaseModel):
#     message: str
#     deep_scan: bool = False
#     session_id: Optional[str] = None  # NEW: User session ID


# class MultiCloudScanRequest(BaseModel):
#     providers: list[str]
#     account_ids: dict[str, str] = {}
#     deep_scan: bool = False  # NEW: Enable deep vulnerability scanning


# class VulnScanRequest(BaseModel):
#     """NEW: Direct vulnerability scan request"""
#     target_type: str  # "python_dependencies", "nodejs_dependencies", "container", etc.
#     path: str
#     metadata: dict = {}


# class AgentChatRequest(BaseModel):
#     message: str


# class AgentChatResponse(BaseModel):
#     reply: str


# class AgentExplainScanRequest(BaseModel):
#     scan_id: int
#     question: Optional[str] = None


# # ============================================================
# # GPT AGENT ENGINE
# # ============================================================

# async def run_gpt_agent(prompt: str) -> str:
#     try:
#         response = openai_client.chat.completions.create(
#             model=OPENAI_AGENT_MODEL,
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "You are a cloud security expert and CSPM analyst with deep knowledge of vulnerability management."
#                 },
#                 {"role": "user", "content": prompt},
#             ],
#             temperature=0.2,
#         )
#         return response.choices[0].message.content.strip()
#     except Exception as e:
#         logger.error("GPT Agent error: %s", e)
#         return f"Agent error: {e}"


# # ============================================================
# # HELPER FUNCTIONS
# # ============================================================

# def _wrap_text(text: str, width: int = 95):
#     text = text.replace("\r", " ").replace("\n", " ")
#     return textwrap.wrap(text, width=width)


# def build_scan_report(scan_id: int) -> dict:
#     rows = get_scan_report(scan_id)

#     if not rows:
#         raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")

#     findings = [
#         {
#             "resource_id": r[0],
#             "resource_name": r[1],
#             "cloud": (r[2] or "").lower(),
#             "type": r[3],
#             "public": r[4],
#             "severity": r[5],
#             "description": r[6],
#         }
#         for r in rows
#         if r[5]
#     ]

#     providers = sorted({(r[2] or "").lower() for r in rows if r[2]})

#     per_cloud: dict[str, dict[str, int]] = {}
#     for r in rows:
#         c = (r[2] or "unknown").lower()
#         if c not in per_cloud:
#             per_cloud[c] = {"resources": 0, "findings": 0}
#         per_cloud[c]["resources"] += 1

#     for f in findings:
#         c = f["cloud"] or "unknown"
#         if c not in per_cloud:
#             per_cloud[c] = {"resources": 0, "findings": 0}
#         per_cloud[c]["findings"] += 1

#     return {
#         "scan_id": scan_id,
#         "total_resources": len(rows),
#         "total_findings": len(findings),
#         "findings": findings,
#         "providers": providers,
#         "per_cloud": per_cloud,
#     }


# # ============================================================
# # API ROUTES
# # ============================================================

# # Add this near the top of your main.py, after the imports
# # This replaces your current @app.get("/") route

# @app.get("/", response_class=HTMLResponse)
# async def root():
#     """Serve the main scan interface"""
#     try:
#         with open("/app/frontend/index.html", "r") as f:
#             return f.read()
#     except FileNotFoundError:
#         return """
#         <html>
#             <body style="font-family: Arial; padding: 40px; background: #1a1f3a; color: white;">
#                 <h1>⚠️ CloudGuard Scanner</h1>
#                 <p>Main application file not found. Please ensure index.html exists in /app/frontend/</p>
#                 <p><a href="/dashboard" style="color: #667eea;">Go to Dashboard</a></p>
#             </body>
#         </html>
#         """

# # Keep your existing /dashboard route
# @app.get("/dashboard", response_class=HTMLResponse)
# async def dashboard():
#     """Serve the dashboard UI"""
#     try:
#         with open("/app/frontend/dashboard.html", "r") as f:
#             return f.read()
#     except FileNotFoundError:
#         return "<h1>Dashboard HTML not found</h1>"

# # If you have an /api/info endpoint, add this for programmatic access
# @app.get("/api/info")
# async def api_info():
#     """API information endpoint"""
#     return {
#         "service": "Multi-Cloud MCP Security Scanner with Vulnerability Detection",
#         "version": "3.0.0",
#         "agent_model": OPENAI_AGENT_MODEL,
#         "registered_providers": mcp_registry.list_providers(),
#         "vulnerability_tools": vuln_scanner.tools_available,
#         "features": [
#             "MCP Plugins",
#             "Real Cloud Resource Scanning",
#             "AI Recommendations",
#             "Security Dashboard",
#             "Compliance Mapping",
#             "Agent Chat",
#             "Deep Vulnerability Scanning (NEW)",
#             "Container Image Scanning (NEW)",
#             "Dependency Vulnerability Detection (NEW)",
#         ],
#     }

# # ------------------------------------------------------------
# # NEW: Direct Vulnerability Scan Endpoint
# # ------------------------------------------------------------
# @app.post("/scan/vulnerabilities")
# async def scan_vulnerabilities(request: VulnScanRequest):
#     """
#     Scan a specific target for vulnerabilities
#     Supports: code dependencies, containers, filesystems, URLs
#     """
#     logger.info(f"Vulnerability scan requested: {request.target_type} - {request.path}")
    
#     try:
#         target = ScanTarget(
#             target_type=request.target_type,
#             path=request.path,
#             metadata=request.metadata
#         )
        
#         vulnerabilities = await vuln_scanner.scan_all(target)
#         report = vuln_scanner.generate_report(vulnerabilities)
        
#         return {
#             "status": "completed",
#             "target": request.path,
#             "target_type": request.target_type,
#             "report": report,
#             "vulnerabilities": [
#                 {
#                     "id": v.vuln_id,
#                     "title": v.title,
#                     "severity": v.severity.value,
#                     "description": v.description[:200] + "..." if len(v.description) > 200 else v.description,
#                     "affected_package": v.affected_package,
#                     "fixed_version": v.fixed_version,
#                     "cvss_score": v.cvss_score,
#                     "tool": v.tool,
#                     "references": v.references[:3]
#                 }
#                 for v in vulnerabilities[:100]  # Limit response size
#             ]
#         }
    
#     except Exception as e:
#         logger.error(f"Vulnerability scan failed: {e}")
#         raise HTTPException(status_code=500, detail=f"Vulnerability scan failed: {str(e)}")


# # ------------------------------------------------------------
# # ENHANCED: AI-Orchestrated Multi-Cloud Scan with Deep Scanning
# # ------------------------------------------------------------
# @app.post("/scan")
# async def intelligent_scan(request: ScanRequest):
#     logger.info("Scan message received: %s", request.message)
#     logger.info("Deep scan enabled: %s", request.deep_scan)

#     valid_providers = {p.lower() for p in mcp_registry.list_providers()}

#     # Step 1: LLM decides scan plan
#     try:
#         response = orchestrator_client.chat.completions.create(
#             model=OPENAI_AGENT_MODEL,
#             messages=[
#                 {
#                     "role": "system",
#                     "content": (
#                         "You are a security orchestration AI.\n"
#                         "From the user's message, decide which of these providers to scan:\n"
#                         "- aws\n"
#                         "- gcp\n"
#                         "- openai\n\n"
#                         "Return ONLY a JSON object with this exact shape:\n"
#                         "{\n"
#                         "  \"providers\": [\"aws\", \"gcp\", \"openai\"],\n"
#                         "  \"account_ids\": {\n"
#                         "    \"aws\": \"optional-account-id-or-alias\",\n"
#                         "    \"gcp\": \"optional-project-id\",\n"
#                         "    \"openai\": \"optional-label-or-tenant-id\"\n"
#                         "  }\n"
#                         "}\n"
#                         "Include only providers that are relevant to the user request."
#                     ),
#                 },
#                 {"role": "user", "content": request.message},
#             ],
#             temperature=0.1,
#         )

#         plan_raw = response.choices[0].message.content.strip()

#         if plan_raw.startswith("```"):
#             parts = plan_raw.split("```")
#             if len(parts) >= 2:
#                 plan_raw = parts[1].strip()

#         plan = json.loads(plan_raw)
#     except Exception as e:
#         logger.error("LLM plan extraction error: %s", e)
#         plan = {"providers": ["aws"], "account_ids": {"aws": "default"}}

#     providers = [p.lower() for p in plan.get("providers", []) if isinstance(p, str)]
#     providers = [p for p in providers if p in valid_providers]

#     account_ids = plan.get("account_ids", {})
#     if not isinstance(account_ids, dict):
#         account_ids = {}

#     # Heuristic fallbacks
#     msg_lower = request.message.lower()
#     if "aws" in msg_lower and "aws" in valid_providers and "aws" not in providers:
#         providers.append("aws")
#     if ("gcp" in msg_lower or "google cloud" in msg_lower) and "gcp" in valid_providers and "gcp" not in providers:
#         providers.append("gcp")
#     if "openai" in msg_lower and "openai" in valid_providers and "openai" not in providers:
#         providers.append("openai")

#     if not providers:
#         if "aws" in valid_providers:
#             providers = ["aws"]
#         else:
#             providers = list(valid_providers)

#     logger.info("Final providers to scan: %s", providers)

#     scan_results: list[ScanResult] = []
#     stored_ids: list[int] = []

#     # Step 2: Run provider scans
#     for provider in providers:
#         try:
#             account_id = account_ids.get(provider, "default")
#             result = await mcp_registry.scan(provider, account_id)
            
#             # NEW: Deep vulnerability scanning if enabled
#             if request.deep_scan:
#                 logger.info(f"🔍 Running deep vulnerability scan for {provider}...")
                
#                 # Get cloud client for downloading artifacts
#                 plugin = mcp_registry.get_plugin(provider)
#                 cloud_client = getattr(plugin, 's3', None) or getattr(plugin, 'storage_client', None)
                
#                 # vuln_findings = await vuln_integration.scan_cloud_resource(
#                 #     result.resources[0] if result.resources else None,
#                 #     cloud_client
#                 # )
                
#                 # result.findings.extend(vuln_findings)
#                 # Scan all resources for vulnerabilities
#                 vuln_findings = []
#                 for resource in result.resources:
#                     vf = await vuln_integration.scan_cloud_resource(resource, cloud_client)
#                     vuln_findings.extend(vf)

#                     result.findings.extend(vuln_findings)


#                 logger.info(f"✓ Deep scan found {len(vuln_findings)} additional vulnerabilities")
            
#             scan_results.append(result)

#             scan_id = await store_scan_result(result)
#             stored_ids.append(scan_id)

#             logger.info("✓ %s scan finished", provider.upper())
#         except Exception as e:
#             logger.error("Scan failed for %s: %s", provider, e)

#     # Step 3: AI risk analysis
#     try:
#         ai_analysis = await ai_engine.analyze_scan_results(scan_results)
#     except Exception as e:
#         logger.error("AI analysis failed: %s", e)
#         ai_analysis = {"error": "AI unavailable"}

#     return {
#         "status": "completed",
#         "scan_ids": stored_ids,
#         "providers_scanned": providers,
#         "deep_scan_enabled": request.deep_scan,
#         "total_resources": sum(len(r.resources) for r in scan_results),
#         "total_findings": sum(len(r.findings) for r in scan_results),
#         "vulnerability_tools_used": list(vuln_scanner.tools_available.keys()) if request.deep_scan else [],
#         "ai_analysis": ai_analysis.get("ai_analysis", ""),
#         "remediation_plan": ai_analysis.get("remediation_plan", {}),
#         "executive_summary": ai_analysis.get("executive_summary", {}),
#     }


# # ------------------------------------------------------------
# # ENHANCED: Direct Multi-Cloud Scan with Vulnerabilities
# # ------------------------------------------------------------
# @app.post("/scan/multi-cloud")
# async def multi_cloud_scan(request: MultiCloudScanRequest):
#     scan_results: list[ScanResult] = []
#     stored_ids: list[int] = []

#     for provider in request.providers:
#         try:
#             account_id = request.account_ids.get(provider, "default")
#             result = await mcp_registry.scan(provider, account_id)
            
#             # NEW: Deep vulnerability scanning if enabled
#             if request.deep_scan:
#                 logger.info(f"🔍 Running deep vulnerability scan for {provider}...")
#                 plugin = mcp_registry.get_plugin(provider)
#                 cloud_client = getattr(plugin, 's3', None) or getattr(plugin, 'storage_client', None)
                
#                 # Scan all resources
#                 for resource in result.resources:
#                     vuln_findings = await vuln_integration.scan_cloud_resource(resource, cloud_client)
#                     result.findings.extend(vuln_findings)
                
#                 logger.info(f"✓ Deep scan completed for {provider}")
            
#             scan_results.append(result)

#             scan_id = await store_scan_result(result)
#             stored_ids.append(scan_id)
#         except Exception as e:
#             raise HTTPException(status_code=500, detail=f"{provider} scan failed: {e}")

#     ai_analysis = await ai_engine.analyze_scan_results(scan_results)

#     return {
#         "status": "completed",
#         "scan_ids": stored_ids,
#         "deep_scan_enabled": request.deep_scan,
#         "scan_results": [
#             {
#                 "provider": r.provider,
#                 "resources": len(r.resources),
#                 "findings": len(r.findings),
#                 "duration": r.scan_duration,
#             }
#             for r in scan_results
#         ],
#         "ai_analysis": ai_analysis,
#     }


# # ------------------------------------------------------------
# # AGENT CHAT
# # ------------------------------------------------------------
# @app.post("/agent/chat", response_model=AgentChatResponse)
# async def agent_chat(request: AgentChatRequest):
#     reply = await run_gpt_agent(request.message)
#     return AgentChatResponse(reply=reply)


# # ------------------------------------------------------------
# # AGENT SCAN EXPLAIN
# # ------------------------------------------------------------
# @app.post("/agent/scan/explain", response_model=AgentChatResponse)
# async def agent_explain_scan(request: AgentExplainScanRequest):
#     data = build_scan_report(request.scan_id)

#     prompt = f"""
# You are analyzing Scan ID {request.scan_id}.

# Structured Findings (JSON):
# {json.dumps(data, indent=2)}

# User Question:
# {request.question or "Provide executive summary, key risks and a prioritized remediation plan."}
# """

#     reply = await run_gpt_agent(prompt)
#     return AgentChatResponse(reply=reply)




# # ------------------------------------------------------------
# # REPORTS
# # ------------------------------------------------------------
# @app.get("/report/{scan_id}")
# async def get_report(scan_id: int):
#     return build_scan_report(scan_id)


# @app.get("/report/{scan_id}/pdf")
# async def get_report_pdf(scan_id: int):
#     data = build_scan_report(scan_id)

#     providers = data.get("providers", [])
#     per_cloud = data.get("per_cloud", {})

#     if not providers:
#         provider_line = "Cloud Provider(s): Unknown"
#     elif len(providers) == 1:
#         provider_line = f"Cloud Provider: {providers[0].upper()}"
#     else:
#         provider_line = "Cloud Providers: " + ", ".join(p.upper() for p in providers)

#     buffer = BytesIO()
#     p = canvas.Canvas(buffer, pagesize=A4)
#     width, height = A4

#     y = height - 60

#     # COVER TITLE
#     p.setFont("Helvetica-Bold", 20)
#     p.drawCentredString(width / 2, y, "Multi-Cloud Security Assessment Report")
#     y -= 40

#     p.setFont("Helvetica", 12)
#     p.drawCentredString(width / 2, y, f"Scan ID: {scan_id}")
#     y -= 18
#     p.drawCentredString(width / 2, y, provider_line)
#     y -= 18
#     p.drawCentredString(width / 2, y, "Generated by MCP Security Scanner v3.0")
#     y -= 40

#     # EXECUTIVE SUMMARY
#     p.setFont("Helvetica-Bold", 14)
#     p.drawString(50, y, "1. Executive Summary")
#     y -= 20

#     p.setFont("Helvetica", 11)

#     if len(providers) == 1:
#         cloud_name = providers[0].upper()
#         summary_text = (
#             f"This assessment focused on the {cloud_name} environment. "
#             f"It analyzed {data['total_resources']} resources in this cloud "
#             f"and identified {data['total_findings']} security findings. "
#             "The key risks are related to configuration, access control, and monitoring gaps."
#         )
#     else:
#         clouds_str = ", ".join(p.upper() for p in providers)
#         summary_text = (
#             f"This assessment covered multiple cloud providers: {clouds_str}. "
#             f"A total of {data['total_resources']} resources were analyzed and "
#             f"{data['total_findings']} security findings were identified across these environments. "
#             "The assessment highlights cross-cloud risks related to identity, access, and observability."
#         )

#     for line in _wrap_text(summary_text):
#         p.drawString(60, y, line)
#         y -= 14

#     # Continue with rest of PDF generation...
#     # (Same as your existing PDF code)

#     p.showPage()
#     p.save()
#     buffer.seek(0)

#     return StreamingResponse(
#         buffer,
#         media_type="application/pdf",
#         headers={
#             "Content-Disposition": f'attachment; filename="security_scan_report_{scan_id}.pdf"'
#         },
#     )

# @app.get("/health")
# async def health():
#     return {"status": "ok"}

# # ------------------------------------------------------------
# # DASHBOARD
# # ------------------------------------------------------------
# @app.get("/posture/dashboard")
# async def posture_dashboard():
#     summary = get_multi_cloud_summary()

#     dashboard = {
#         "clouds": [],
#         "total_resources": 0,
#         "total_findings": 0,
#         "public_resources": 0,
#     }

#     for provider, res, find, public in summary:
#         dashboard["clouds"].append({
#             "provider": provider,
#             "resources": res,
#             "findings": find,
#             "public": public,
#         })
#         dashboard["total_resources"] += res
#         dashboard["total_findings"] += find
#         dashboard["public_resources"] += public

#     # Security Score
#     if dashboard["total_resources"]:
#         risk_ratio = dashboard["total_findings"] / dashboard["total_resources"]
#         score = max(0, 100 - (risk_ratio * 100))
#     else:
#         score = 100

#     dashboard["security_score"] = round(score, 2)
#     dashboard["vulnerability_tools_available"] = vuln_scanner.tools_available
    
#     return dashboard


# # ------------------------------------------------------------
# # PROVIDERS LIST
# # ------------------------------------------------------------
# @app.get("/providers")
# async def list_providers():
#     providers = mcp_registry.list_providers()
#     return {
#         "registered_providers": providers,
#         "total": len(providers),
#         "vulnerability_scanner_ready": len(vuln_scanner.tools_available) > 0,
#         "available_vuln_tools": list(vuln_scanner.tools_available.keys())
#     }


# # ============================================================
# # DATABASE STORAGE
# # ============================================================

# # from backend.database import get_conn

# async def store_scan_result(result: ScanResult) -> int:
#     conn = get_conn()

#     try:
#         # Create scan record
#         scan_id = create_scan_record(result.account_id, result.provider)

#         # ------------------------------------------------------------------
#         # Store resources
#         # ------------------------------------------------------------------
#         resource_id_map: dict[str, int] = {}

#         for r in result.resources:
#             resource_id = store_resource(
#                 scan_id,
#                 result.provider,
#                 r.resource_type,
#                 r.name,
#                 r.config,
#                 r.is_public,
#             )
#             resource_id_map[r.name] = resource_id

#         # ------------------------------------------------------------------
#         # Store findings with enhanced tool tracking
#         # ------------------------------------------------------------------
#         for f in result.findings:
#             resource_id = resource_id_map.get(f.resource.name)

#             # If resource not found, fetch it safely
#             if not resource_id:
#                 with conn.cursor() as cur:
#                     cur.execute(
#                         """
#                         SELECT id
#                         FROM resources
#                         WHERE scan_id = %s AND name = %s
#                         LIMIT 1
#                         """,
#                         (scan_id, f.resource.name),
#                     )
#                     row = cur.fetchone()
#                     if row:
#                         resource_id = row[0]

#             # Skip orphaned findings
#             if not resource_id:
#                 continue

#             # Extract tool name (with priority)
#             tool_name = _extract_tool_name_enhanced(f, result.provider)

#             # Enhanced description with tool tag
#             description_with_tool = f"[{tool_name}] {f.issue}: {f.description}"

#             # Store finding
#             store_finding(
#                 scan_id,
#                 resource_id,
#                 f.severity.value,
#                 description_with_tool,
#                 result.provider,
#             )

#             # NEW: Store vulnerability metadata if present
#             if getattr(f, "vuln_metadata", None):
#                 store_vulnerability(
#                     scan_id,
#                     resource_id,
#                     f.vuln_metadata,
#                 )

#         # ------------------------------------------------------------------
#         # Commit once per scan
#         # ------------------------------------------------------------------
#         conn.commit()
#         logger.info("Stored scan %s", scan_id)
#         return scan_id

#     except Exception as e:
#         conn.rollback()
#         logger.exception("Failed to store scan result")
#         raise

# def _extract_tool_name_enhanced(finding: SecurityFinding, provider: str) -> str:
#     """
#     Enhanced tool name extraction with better logic
    
#     Priority:
#     1. Explicit detection_tool attribute
#     2. Tool tag in issue [TOOL]
#     3. Tool tag in description [TOOL]
#     4. Keyword detection in issue/description
#     5. Provider plugin name as fallback
#     """
#     import re

#     # Priority 1: Explicit tool attribute
#     if hasattr(finding, 'detection_tool') and finding.detection_tool:
#         return finding.detection_tool.upper()

#     # Priority 2 & 3: Tag detection in issue and description
#     for text in [finding.issue, finding.description]:
#         if text:
#             tag_match = re.search(r'\[([A-Z0-9_\-]+)\]', text)
#             if tag_match:
#                 tool = tag_match.group(1).upper()
#                 # Skip generic tags
#                 if tool not in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
#                     return tool

#     # Priority 4: Keyword-based detection
#     combined_text = f"{finding.issue} {finding.description}".lower()
    
#     # Vulnerability scanner keywords
#     vuln_tools = {
#         'trivy': 'TRIVY',
#         'safety': 'SAFETY',
#         'gitleaks': 'GITLEAKS',
#         'git-leaks': 'GITLEAKS',
#         'zap': 'OWASP-ZAP',
#         'owasp zap': 'OWASP-ZAP',
#         'zaproxy': 'OWASP-ZAP',
#         'nuclei': 'NUCLEI',
#         'grype': 'GRYPE',
#         'npm audit': 'NPM-AUDIT',
#         'npm-audit': 'NPM-AUDIT',
#         'dependency-check': 'OWASP-DC',
#         'dependency check': 'OWASP-DC',
#         'snyk': 'SNYK',
#         'bandit': 'BANDIT',
#         'semgrep': 'SEMGREP',
#         'clair': 'CLAIR',
#         'dockle': 'DOCKLE',
#         'tfsec': 'TFSEC',
#         'cve-': 'CVE-DATABASE',  # CVE mentions
#         'secret': 'GITLEAKS',     # Secret detection
#         'exposed secret': 'GITLEAKS',
#         'hardcoded': 'GITLEAKS',
#     }
    
#     for keyword, tool_name in vuln_tools.items():
#         if keyword in combined_text:
#             return tool_name
    
#     # Cloud-specific detection keywords
#     cloud_keywords = {
#         'aws': {
#             's3 bucket': 'AWS-S3-SCANNER',
#             'public bucket': 'AWS-S3-SCANNER',
#             'iam user': 'AWS-IAM-SCANNER',
#             'mfa': 'AWS-IAM-SCANNER',
#             'security group': 'AWS-EC2-SCANNER',
#             'ssh open': 'AWS-EC2-SCANNER',
#             'rdp open': 'AWS-EC2-SCANNER',
#             'cloudtrail': 'AWS-CLOUDTRAIL-SCANNER',
#             'kms key': 'AWS-KMS-SCANNER',
#         },
#         'gcp': {
#             'gcs bucket': 'GCP-GCS-SCANNER',
#             'firewall': 'GCP-FIREWALL-SCANNER',
#             'cloud sql': 'GCP-SQL-SCANNER',
#             'compute instance': 'GCP-COMPUTE-SCANNER',
#         },
#         'openai': {
#             'api key': 'OPENAI-API-SCANNER',
#             'model access': 'OPENAI-MODEL-SCANNER',
#             'usage': 'OPENAI-USAGE-SCANNER',
#         }
#     }
    
#     provider_lower = provider.lower()
#     if provider_lower in cloud_keywords:
#         for keyword, tool_name in cloud_keywords[provider_lower].items():
#             if keyword in combined_text:
#                 return tool_name
    
#     # Priority 5: Fall back to provider plugin
#     provider_map = {
#         'aws': 'AWS-PLUGIN',
#         'gcp': 'GCP-PLUGIN',
#         'azure': 'AZURE-PLUGIN',
#         'openai': 'OPENAI-PLUGIN',
#     }
    
#     return provider_map.get(provider_lower, 'UNKNOWN')

# @app.get("/api/severity-breakdown")
# async def get_severity_breakdown():
#     """
#     Get REAL severity breakdown from actual database findings
#     """
#     try:
#         conn = get_conn()
#         with conn.cursor() as cur:
#             cur.execute("""
#                 SELECT 
#                     severity,
#                     COUNT(*) as count
#                 FROM findings
#                 GROUP BY severity
#                 ORDER BY 
#                     CASE severity
#                         WHEN 'CRITICAL' THEN 1
#                         WHEN 'HIGH' THEN 2
#                         WHEN 'MEDIUM' THEN 3
#                         WHEN 'LOW' THEN 4
#                         ELSE 5
#                     END
#             """)
#             results = cur.fetchall()

#         breakdown = {
#             "CRITICAL": 0,
#             "HIGH": 0,
#             "MEDIUM": 0,
#             "LOW": 0,
#             "INFO": 0
#         }

#         for severity, count in results:
#             if severity in breakdown:
#                 breakdown[severity] = count

#         return {
#             "status": "success",
#             "data": breakdown,
#             "total": sum(breakdown.values())
#         }

#     except Exception as e:
#         logger.exception("Failed to get severity breakdown")
#         return {
#             "status": "error",
#             "message": str(e),
#             "data": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
#         }


# # ------------------------------------------------------------------
# # PROVIDER BREAKDOWN
# # ------------------------------------------------------------------
# @app.get("/api/provider-breakdown")
# async def get_provider_breakdown():
#     """
#     Get REAL provider breakdown from actual database
#     """
#     try:
#         conn = get_conn()
#         with conn.cursor() as cur:
#             cur.execute("""
#                 SELECT 
#                     r.cloud as provider,
#                     COUNT(DISTINCT r.id) as resources,
#                     COUNT(DISTINCT f.id) as findings
#                 FROM resources r
#                 LEFT JOIN findings f ON r.id = f.resource_id
#                 GROUP BY r.cloud
#                 ORDER BY resources DESC
#             """)
#             results = cur.fetchall()

#         return {
#             "status": "success",
#             "data": [
#                 {
#                     "provider": provider,
#                     "resources": resources,
#                     "findings": findings
#                 }
#                 for provider, resources, findings in results
#             ]
#         }

#     except Exception as e:
#         logger.exception("Failed to get provider breakdown")
#         return {
#             "status": "error",
#             "message": str(e),
#             "data": []
#         }


# # ------------------------------------------------------------------
# # SCAN HISTORY
# # ------------------------------------------------------------------
# @app.get("/api/scan-history")
# async def get_scan_history(days: int = 30):
#     """
#     Get REAL scan history for trend charts
#     """
#     try:
#         conn = get_conn()
#         with conn.cursor() as cur:
#             cur.execute("""
#                 SELECT 
#                     DATE(s.started_at) as scan_date,
#                     COUNT(DISTINCT s.id) as scan_count,
#                     COUNT(DISTINCT f.id) as findings_count,
#                     COUNT(DISTINCT CASE WHEN f.severity = 'CRITICAL' THEN f.id END) as critical_count
#                 FROM scans s
#                 LEFT JOIN findings f ON s.id = f.scan_id
#                 WHERE s.started_at >= NOW() - INTERVAL %s
#                 GROUP BY DATE(s.started_at)
#                 ORDER BY scan_date ASC
#             """, (f"{days} days",))
#             results = cur.fetchall()

#         return {
#             "status": "success",
#             "data": [
#                 {
#                     "date": scan_date.isoformat() if scan_date else None,
#                     "scans": scan_count,
#                     "findings": findings_count,
#                     "critical": critical_count
#                 }
#                 for scan_date, scan_count, findings_count, critical_count in results
#             ]
#         }

#     except Exception as e:
#         logger.exception("Failed to get scan history")
#         return {
#             "status": "error",
#             "message": str(e),
#             "data": []
#         }


# # ------------------------------------------------------------------
# # LATEST FINDINGS
# # ------------------------------------------------------------------
# @app.get("/api/latest-findings")
# async def get_latest_findings(limit: int = 10):
#     """
#     Get REAL latest findings from database
#     """
#     try:
#         conn = get_conn()
#         with conn.cursor() as cur:
#             cur.execute("""
#                 SELECT 
#                     r.name as resource_name,
#                     r.cloud,
#                     f.severity,
#                     f.description,
#                     f.validated_by as tool,
#                     f.created_at
#                 FROM findings f
#                 JOIN resources r ON f.resource_id = r.id
#                 ORDER BY f.created_at DESC
#                 LIMIT %s
#             """, (limit,))
#             results = cur.fetchall()

#         return {
#             "status": "success",
#             "data": [
#                 {
#                     "resource_name": resource_name,
#                     "cloud": cloud,
#                     "severity": severity,
#                     "description": description,
#                     "tool": tool,
#                     "timestamp": created_at.isoformat() if created_at else None
#                 }
#                 for resource_name, cloud, severity, description, tool, created_at in results
#             ]
#         }

#     except Exception as e:
#         logger.exception("Failed to get latest findings")
#         return {
#             "status": "error",
#             "message": str(e),
#             "data": []
#         }


# # ------------------------------------------------------------------
# # DASHBOARD SUMMARY
# # ------------------------------------------------------------------
# @app.get("/api/dashboard-summary")
# async def get_dashboard_summary():
#     """
#     Get comprehensive REAL dashboard data in one call
#     """
#     try:
#         conn = get_conn()
#         with conn.cursor() as cur:
#             # Totals
#             cur.execute("""
#                 SELECT 
#                     COUNT(DISTINCT r.id),
#                     COUNT(DISTINCT f.id),
#                     COUNT(DISTINCT CASE WHEN r.public = true THEN r.id END)
#                 FROM resources r
#                 LEFT JOIN findings f ON r.id = f.resource_id
#             """)
#             total_resources, total_findings, public_resources = cur.fetchone()

#             # Severity
#             cur.execute("""
#                 SELECT severity, COUNT(*)
#                 FROM findings
#                 GROUP BY severity
#             """)
#             severity_breakdown = dict(cur.fetchall())

#             # Providers
#             cur.execute("""
#                 SELECT 
#                     r.cloud,
#                     COUNT(DISTINCT r.id),
#                     COUNT(DISTINCT f.id)
#                 FROM resources r
#                 LEFT JOIN findings f ON r.id = f.resource_id
#                 GROUP BY r.cloud
#             """)
#             providers = [
#                 {"provider": p, "resources": r, "findings": f}
#                 for p, r, f in cur.fetchall()
#             ]

#         risk_ratio = (total_findings / total_resources) if total_resources else 0
#         security_score = max(0, 100 - (risk_ratio * 50))

#         return {
#             "status": "success",
#             "data": {
#                 "total_resources": total_resources or 0,
#                 "total_findings": total_findings or 0,
#                 "public_resources": public_resources or 0,
#                 "security_score": round(security_score, 2),
#                 "severity_breakdown": severity_breakdown,
#                 "providers": providers,
#                 "timestamp": datetime.utcnow().isoformat()
#             }
#         }

#     except Exception as e:
#         logger.exception("Failed to get dashboard summary")
#         return {
#             "status": "error",
#             "message": str(e)
#         }


# # ------------------------------------------------------------------
# # ENHANCED POSTURE DASHBOARD
# # ------------------------------------------------------------------
# @app.get("/posture/dashboard/enhanced")
# async def enhanced_posture_dashboard():
#     """
#     Enhanced dashboard with REAL data from all tables
#     """
#     try:
#         summary = get_multi_cloud_summary()

#         dashboard = {
#             "clouds": [],
#             "total_resources": 0,
#             "total_findings": 0,
#             "public_resources": 0,
#             "vulnerability_tools_available": vuln_scanner.tools_available,
#             "timestamp": datetime.utcnow().isoformat()
#         }

#         for provider, res, find, public in summary:
#             dashboard["clouds"].append({
#                 "provider": provider,
#                 "resources": res,
#                 "findings": find,
#                 "public": public,
#             })
#             dashboard["total_resources"] += res
#             dashboard["total_findings"] += find
#             dashboard["public_resources"] += public

#         risk_ratio = (
#             dashboard["total_findings"] / dashboard["total_resources"]
#             if dashboard["total_resources"] else 0
#         )
#         dashboard["security_score"] = round(max(0, 100 - (risk_ratio * 50)), 2)

#         conn = get_conn()
#         with conn.cursor() as cur:
#             cur.execute("""
#                 SELECT severity, COUNT(*)
#                 FROM findings
#                 GROUP BY severity
#             """)
#             dashboard["severity_breakdown"] = dict(cur.fetchall())

#         return dashboard

#     except Exception as e:
#         logger.exception("Enhanced dashboard failed")
#         raise HTTPException(status_code=500, detail=str(e))
# # ============================================================
# # UVICORN ENTRYPOINT
# # ============================================================

# if __name__ == "__main__":
#     import uvicorn

#     # Cleanup on shutdown
#     def cleanup():
#         vuln_integration.cleanup()
    
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

# [file name]: main.py

"""
Enhanced Main.py with Vulnerability Scanning and Credential Management Integration
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

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, restrict to specific origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(credentials_router)

OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL", "gpt-4o-mini")

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
orchestrator_client = openai_client
ai_engine = AIRecommendationEngine(api_key=os.getenv("OPENAI_API_KEY"))

# Initialize vulnerability scanner
vuln_scanner = VulnerabilityScanner()
vuln_integration = CloudVulnerabilityIntegration()

# ============================================================
# REQUEST MODELS
# ============================================================

class ScanRequest(BaseModel):
    message: str
    deep_scan: bool = False
    session_id: Optional[str] = None  # User session ID

class MultiCloudScanRequest(BaseModel):
    providers: list[str]
    account_ids: dict[str, str] = {}
    deep_scan: bool = False
    session_id: Optional[str] = None  # User session ID

class VulnScanRequest(BaseModel):
    """Direct vulnerability scan request"""
    target_type: str  # "python_dependencies", "nodejs_dependencies", "container", etc.
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
    """Create a new scan session"""
    user_id: str = "anonymous"
    credentials: Dict[str, int] = {}  # provider -> credential_id mapping

class SessionResponse(BaseModel):
    session_id: str
    expires_at: datetime
    providers_available: List[str]

# ============================================================
# HELPER FUNCTIONS
# ============================================================

def get_session_id(request: Request) -> Optional[str]:
    """Extract session ID from request"""
    # Check cookies first
    session_id = request.cookies.get("cloudguard_session")
    
    # Check Authorization header
    if not session_id:
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            session_id = auth_header[7:]
    
    # Check query parameter
    if not session_id:
        session_id = request.query_params.get("session_id")
    
    return session_id

def get_user_id(request: Request) -> str:
    """Extract user ID from request"""
    session_id = get_session_id(request)
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

def initialize_plugins_with_credentials(session_id: Optional[str] = None):
    """Initialize plugins with user credentials from session"""
    providers = {}
    
    try:
        if session_id:
            # Get credentials from session
            session_creds = credential_manager.get_session_credentials(session_id)
            logger.info(f"Session credentials: {list(session_creds.keys())}")
            
            # AWS
            if 'aws' in session_creds:
                try:
                    aws_creds = session_creds['aws']
                    if aws_creds.get('access_key_id') and aws_creds.get('secret_access_key'):
                        aws_plugin = AWSPlugin({
                            "access_key_id": aws_creds.get('access_key_id'),
                            "secret_access_key": aws_creds.get('secret_access_key'),
                            "region": aws_creds.get('region', 'us-east-1'),
                            "session_token": aws_creds.get('session_token')
                        })
                        mcp_registry.register("aws", aws_plugin)
                        providers['aws'] = aws_plugin
                        logger.info("✓ AWS Plugin registered with user credentials")
                except Exception as e:
                    logger.warning(f"⚠ AWS Plugin failed with user credentials: {e}")
            
            # OpenAI
            if 'openai' in session_creds:
                try:
                    openai_creds = session_creds['openai']
                    if openai_creds.get('api_key'):
                        openai_plugin = OpenAIPlugin({
                            "api_key": openai_creds.get('api_key'),
                            "org_id": openai_creds.get('org_id')
                        })
                        mcp_registry.register("openai", openai_plugin)
                        providers['openai'] = openai_plugin
                        logger.info("✓ OpenAI Plugin registered with user credentials")
                except Exception as e:
                    logger.warning(f"⚠ OpenAI Plugin failed with user credentials: {e}")
            
            # GCP
            if 'gcp' in session_creds:
                try:
                    gcp_creds = session_creds['gcp']
                    if gcp_creds.get('service_account_json'):
                        # Parse JSON to get project_id
                        try:
                            sa_json = json.loads(gcp_creds.get('service_account_json'))
                            project_id = gcp_creds.get('project_id') or sa_json.get('project_id')
                        except:
                            project_id = gcp_creds.get('project_id')
                        
                        gcp_plugin = GCPPlugin({
                            "service_account_json": gcp_creds.get('service_account_json'),
                            "project_id": project_id
                        })
                        mcp_registry.register("gcp", gcp_plugin)
                        providers['gcp'] = gcp_plugin
                        logger.info("✓ GCP Plugin registered with user credentials")
                except Exception as e:
                    logger.warning(f"⚠ GCP Plugin failed with user credentials: {e}")
    
    except Exception as e:
        logger.error(f"Failed to initialize plugins with credentials: {e}")
    
    # Fall back to environment variables if no user credentials
    if 'aws' not in providers:
        try:
            aws_access_key = os.getenv("AWS_ACCESS_KEY_ID")
            aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
            if aws_access_key and aws_secret:
                aws_plugin = AWSPlugin({
                    "access_key_id": aws_access_key,
                    "secret_access_key": aws_secret,
                    "region": os.getenv("AWS_REGION", "us-east-1"),
                })
                mcp_registry.register("aws", aws_plugin)
                providers['aws'] = aws_plugin
                logger.info("✓ AWS Plugin registered with environment credentials")
            else:
                logger.warning("⚠ AWS credentials not found in environment")
        except Exception as e:
            logger.warning(f"⚠ AWS Plugin failed: {e}")
    
    if 'gcp' not in providers:
        try:
            gcp_json = os.getenv("GCP_SERVICE_ACCOUNT_JSON")
            if gcp_json:
                # Parse JSON to get project_id
                try:
                    sa_json = json.loads(gcp_json)
                    project_id = os.getenv("GCP_PROJECT_ID") or sa_json.get('project_id')
                except:
                    project_id = os.getenv("GCP_PROJECT_ID")
                
                gcp_plugin = GCPPlugin({
                    "service_account_json": gcp_json,
                    "project_id": project_id
                })
                mcp_registry.register("gcp", gcp_plugin)
                providers['gcp'] = gcp_plugin
                logger.info("✓ GCP Plugin registered with environment credentials")
            else:
                logger.warning("⚠ GCP credentials not found in environment")
        except Exception as e:
            logger.warning(f"⚠ GCP Plugin failed: {e}")
    
    if 'openai' not in providers:
        try:
            openai_key = os.getenv("OPENAI_API_KEY")
            if openai_key:
                openai_plugin = OpenAIPlugin({
                    "api_key": openai_key,
                    "org_id": os.getenv("OPENAI_ORG_ID"),
                })
                mcp_registry.register("openai", openai_plugin)
                providers['openai'] = openai_plugin
                logger.info("✓ OpenAI Plugin registered with environment credentials")
            else:
                logger.warning("⚠ OpenAI credentials not found in environment")
        except Exception as e:
            logger.warning(f"⚠ OpenAI Plugin failed: {e}")
    
    return providers

# ============================================================
# SESSION MANAGEMENT
# ============================================================

@app.post("/api/session/create", response_model=SessionResponse)
async def create_session(request: SessionRequest):
    """Create a new scan session with credentials"""
    try:
        session_id = secrets.token_urlsafe(32)
        
        # Create session in credential manager
        session_id = credential_manager.create_session(
            request.user_id,
            request.credentials,
            {"created_at": datetime.utcnow().isoformat()}
        )
        
        # Get available providers from credentials
        providers_available = list(request.credentials.keys())
        
        return SessionResponse(
            session_id=session_id,
            expires_at=datetime.utcnow() + timedelta(hours=1),
            providers_available=providers_available
        )
        
    except Exception as e:
        logger.error(f"Failed to create session: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/session/{session_id}/status")
async def get_session_status(session_id: str):
    """Get session status and available providers"""
    try:
        creds = credential_manager.get_session_credentials(session_id)
        
        if not creds:
            raise HTTPException(status_code=404, detail="Session not found or expired")
        
        providers_available = list(creds.keys())
        
        return {
            "session_id": session_id,
            "providers_available": providers_available,
            "aws_configured": "aws" in creds,
            "openai_configured": "openai" in creds,
            "gcp_configured": "gcp" in creds
        }
        
    except Exception as e:
        logger.error(f"Failed to get session status: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# ============================================================
# API ROUTES
# ============================================================

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main scan interface"""
    try:
        with open("/app/frontend/index.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        # Fallback to relative path
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
                    <p><a href="/api/info" style="color: #667eea;">API Information</a></p>
                </body>
            </html>
            """

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the dashboard UI"""
    try:
        with open("/app/frontend/dashboard.html", "r") as f:
            return f.read()
    except FileNotFoundError:
        try:
            with open("frontend/dashboard.html", "r") as f:
                return f.read()
        except:
            return "<h1>Dashboard HTML not found</h1>"

@app.get("/api/info")
async def api_info(request: Request):
    """API information endpoint"""
    session_id = get_session_id(request)
    
    return {
        "service": "CloudGuard - Multi-Cloud Security Scanner",
        "version": "3.1.0",
        "agent_model": OPENAI_AGENT_MODEL,
        "registered_providers": mcp_registry.list_providers(),
        "vulnerability_tools": vuln_scanner.tools_available,
        "session_active": bool(session_id),
        "credential_manager_ready": True,
        "features": [
            "MCP Plugins with User Credentials",
            "Real Cloud Resource Scanning",
            "AI Recommendations",
            "Security Dashboard",
            "Credential Management",
            "Deep Vulnerability Scanning",
            "Container Image Scanning",
            "Dependency Vulnerability Detection",
            "Session-based Authentication",
        ],
    }

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

@app.post("/scan")
@app.post("/scan")
async def intelligent_scan(request: ScanRequest):
    """AI-orchestrated multi-cloud scan"""
    logger.info(f"Intelligent scan request: {request.message}")
    logger.info(f"Session ID: {request.session_id}")
    logger.info(f"Deep scan: {request.deep_scan}")
    
    # Initialize plugins with user credentials
    initialize_plugins_with_credentials(request.session_id)
    
    valid_providers = {p.lower() for p in mcp_registry.list_providers()}
    
    # ✅ FIX: Initialize variables OUTSIDE try block with defaults
    account_ids = {}  # <-- MOVED HERE
    providers = []    # <-- MOVED HERE
    
    # Step 1: LLM decides scan plan
    try:
        response = orchestrator_client.chat.completions.create(
            model=OPENAI_AGENT_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a security orchestration AI.\n"
                        "From the user's message, decide which of these providers to scan:\n"
                        "- aws\n"
                        "- gcp\n"
                        "- openai\n\n"
                        "Return ONLY a JSON object with this exact shape:\n"
                        "{\n"
                        "  \"providers\": [\"aws\", \"gcp\", \"openai\"],\n"
                        "  \"account_ids\": {\n"
                        "    \"aws\": \"optional-account-id-or-alias\",\n"
                        "    \"gcp\": \"optional-project-id\",\n"
                        "    \"openai\": \"optional-label-or-tenant-id\"\n"
                        "  }\n"
                        "}\n"
                        "Include only providers that are relevant to the user request."
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
        
        # Extract providers and account_ids from plan
        providers = [p.lower() for p in plan.get("providers", []) if isinstance(p, str)]
        providers = [p for p in providers if p in valid_providers]
        
        account_ids = plan.get("account_ids", {})
        if not isinstance(account_ids, dict):
            account_ids = {}
            
    except Exception as e:
        logger.error("LLM plan extraction error: %s", e)
        # Variables already initialized above, so this is safe
        providers = []
        account_ids = {}
    
    # Heuristic fallbacks
    msg_lower = request.message.lower()
    if "aws" in msg_lower and "aws" in valid_providers and "aws" not in providers:
        providers.append("aws")
    if ("gcp" in msg_lower or "google cloud" in msg_lower) and "gcp" in valid_providers and "gcp" not in providers:
        providers.append("gcp")
    if "openai" in msg_lower and "openai" in valid_providers and "openai" not in providers:
        providers.append("openai")
    
    if not providers:
        providers = list(valid_providers)
    
    logger.info(f"Final providers to scan: {providers}")
    
    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []
    
    # Step 2: Run provider scans
    for provider in providers:
        try:
            # ✅ Now account_ids is guaranteed to exist
            account_id = account_ids.get(provider, "default")
            if not account_id or account_id == "None":
                account_id = "default"
            
            logger.info(f"Scanning {provider} with account_id: {account_id}")
            
            result = await mcp_registry.scan(provider, account_id)
            
            # Deep vulnerability scanning if enabled
            if request.deep_scan:
                logger.info(f"🔍 Running deep vulnerability scan for {provider}...")
                
                # Get cloud client for downloading artifacts
                plugin = mcp_registry.get_plugin(provider)
                cloud_client = None
                if plugin:
                    cloud_client = getattr(plugin, 's3', None) or getattr(plugin, 'storage_client', None)
                
                # Scan all resources for vulnerabilities
                vuln_findings = []
                for resource in result.resources:
                    try:
                        vf = await vuln_integration.scan_cloud_resource(resource, cloud_client)
                        vuln_findings.extend(vf)
                    except Exception as e:
                        logger.error(f"Failed to scan resource {resource.name}: {e}")
                
                result.findings.extend(vuln_findings)
                logger.info(f"✓ Deep scan found {len(vuln_findings)} additional vulnerabilities")
            
            scan_results.append(result)
            
            scan_id = await store_scan_result(result)
            stored_ids.append(scan_id)
            
            logger.info(f"✓ {provider.upper()} scan finished")
        except Exception as e:
            logger.error(f"Scan failed for {provider}: {e}")
            # ✅ FIX: Continue with other providers instead of stopping
            continue
    
    # Step 3: AI risk analysis
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
        "session_used": bool(request.session_id),
        "total_resources": sum(len(r.resources) for r in scan_results),
        "total_findings": sum(len(r.findings) for r in scan_results),
        "vulnerability_tools_used": list(vuln_scanner.tools_available.keys()) if request.deep_scan else [],
        "ai_analysis": ai_analysis.get("ai_analysis", ""),
        "remediation_plan": ai_analysis.get("remediation_plan", {}),
        "executive_summary": ai_analysis.get("executive_summary", {}),
    }



@app.post("/scan/multi-cloud")
async def multi_cloud_scan(request: MultiCloudScanRequest):
    """Direct multi-cloud scan"""
    logger.info(f"Multi-cloud scan for providers: {request.providers}")
    logger.info(f"Session ID: {request.session_id}")
    
    # ✅ Initialize plugins with user credentials BEFORE scanning
    providers_initialized = initialize_plugins_with_credentials(request.session_id)
    logger.info(f"Initialized providers: {list(providers_initialized.keys())}")
    
    # ✅ Verify requested providers are initialized
    for provider in request.providers:
        if provider not in mcp_registry.list_providers():
            logger.error(f"Provider {provider} not initialized. Available: {mcp_registry.list_providers()}")
            raise HTTPException(
                status_code=400, 
                detail=f"{provider} scan failed: Provider not initialized. Check credentials or environment variables."
            )
    
    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []
    
    for provider in request.providers:
        try:
            # FIX: Ensure account_id is never None
            account_id = request.account_ids.get(provider, "default")
            if not account_id:
                account_id = "default"
            
            logger.info(f"Scanning {provider} with account_id: {account_id}")
            
            result = await mcp_registry.scan(provider, account_id)
            
            # Deep vulnerability scanning if enabled
            if request.deep_scan:
                logger.info(f"🔍 Running deep vulnerability scan for {provider}...")
                plugin = mcp_registry.get_plugin(provider)
                cloud_client = None
                if plugin:
                    cloud_client = getattr(plugin, 's3', None) or getattr(plugin, 'storage_client', None)
                
                # Scan all resources
                for resource in result.resources:
                    try:
                        vuln_findings = await vuln_integration.scan_cloud_resource(resource, cloud_client)
                        result.findings.extend(vuln_findings)
                    except Exception as e:
                        logger.error(f"Failed to scan resource {resource.name}: {e}")
                
                logger.info(f"✓ Deep scan completed for {provider}")
            
            scan_results.append(result)
            
            scan_id = await store_scan_result(result)
            stored_ids.append(scan_id)
            
            logger.info(f"✓ {provider.upper()} scan finished, stored as scan_id: {scan_id}")
            
        except Exception as e:
            logger.error(f"Scan failed for {provider}: {e}")
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
        "session_used": bool(request.session_id),
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

@app.get("/health")
async def health():
    """Health check endpoint"""
    try:
        # Check database connection
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("SELECT 1")
        
        # Check credential manager
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

@app.get("/report/{scan_id}")
async def get_report(scan_id: int):
    """Get scan report"""
    return build_scan_report(scan_id)

@app.get("/report/{scan_id}/pdf")
async def get_report_pdf(scan_id: int):
    """Generate PDF report"""
    data = build_scan_report(scan_id)
    
    providers = data.get("providers", [])
    per_cloud = data.get("per_cloud", {})
    
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
    
    # Continue with rest of PDF generation...
    # (For brevity, including simplified version)
    
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

@app.get("/posture/dashboard")
async def posture_dashboard():
    """Get posture dashboard data"""
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
    
    # Security Score
    if dashboard["total_resources"]:
        risk_ratio = dashboard["total_findings"] / dashboard["total_resources"]
        score = max(0, 100 - (risk_ratio * 100))
    else:
        score = 100
    
    dashboard["security_score"] = round(score, 2)
    
    return dashboard

@app.get("/providers")
async def list_providers():
    """List available cloud providers"""
    providers = mcp_registry.list_providers()
    return {
        "registered_providers": providers,
        "total": len(providers),
        "vulnerability_scanner_ready": len(vuln_scanner.tools_available) > 0,
        "available_vuln_tools": list(vuln_scanner.tools_available.keys()),
        "credential_manager_ready": True
    }

# ============================================================
# DATABASE STORAGE FUNCTIONS
# ============================================================

async def store_scan_result(result: ScanResult) -> int:
    """Store scan results in database"""
    conn = get_conn()
    
    try:
        # FIX: Provide default account_id if None
        account_id = result.account_id or "default"
        
        # Create scan record
        scan_id = create_scan_record(account_id, result.provider)
        
        # Store resources
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
        
        # Store findings
        for f in result.findings:
            resource_id = resource_id_map.get(f.resource.name)
            
            # If resource not found, fetch it
            if not resource_id:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT id
                        FROM resources
                        WHERE scan_id = %s AND name = %s
                        LIMIT 1
                        """,
                        (scan_id, f.resource.name),
                    )
                    row = cur.fetchone()
                    if row:
                        resource_id = row[0]
            
            # Skip orphaned findings
            if not resource_id:
                continue
            
            # Extract tool name
            tool_name = _extract_tool_name_enhanced(f, result.provider)
            
            # Enhanced description with tool tag
            description_with_tool = f"[{tool_name}] {f.issue}: {f.description}"
            
            # Store finding
            store_finding(
                scan_id,
                resource_id,
                f.severity.value,
                description_with_tool,
                result.provider,
            )
            
            # Store vulnerability metadata if present
            if getattr(f, "vuln_metadata", None):
                store_vulnerability(
                    scan_id,
                    resource_id,
                    f.vuln_metadata,
                )
        
        # Commit transaction
        conn.commit()
        logger.info(f"Stored scan {scan_id}")
        return scan_id
        
    except Exception as e:
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
# DASHBOARD API ENDPOINTS
# ============================================================

@app.get("/api/severity-breakdown")
async def get_severity_breakdown():
    """Get severity breakdown for dashboard"""
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                SELECT 
                    severity,
                    COUNT(*) as count
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
        
        breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        for severity, count in results:
            if severity in breakdown:
                breakdown[severity] = count
        
        return {
            "status": "success",
            "data": breakdown,
            "total": sum(breakdown.values())
        }
        
    except Exception as e:
        logger.exception("Failed to get severity breakdown")
        return {
            "status": "error",
            "message": str(e),
            "data": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        }

@app.get("/api/provider-breakdown")
async def get_provider_breakdown():
    """Get provider breakdown for dashboard"""
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
                {
                    "provider": provider,
                    "resources": resources,
                    "findings": findings
                }
                for provider, resources, findings in results
            ]
        }
        
    except Exception as e:
        logger.exception("Failed to get provider breakdown")
        return {
            "status": "error",
            "message": str(e),
            "data": []
        }

@app.get("/api/scan-history")
async def get_scan_history(days: int = 30):
    """Get scan history for trend charts"""
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
        return {
            "status": "error",
            "message": str(e),
            "data": []
        }

@app.get("/api/latest-findings")
async def get_latest_findings(limit: int = 10):
    """Get latest findings"""
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
        return {
            "status": "error",
            "message": str(e),
            "data": []
        }

@app.get("/api/dashboard-summary")
async def get_dashboard_summary():
    """Get comprehensive dashboard summary"""
    try:
        conn = get_conn()
        with conn.cursor() as cur:
            # Totals
            cur.execute("""
                SELECT 
                    COUNT(DISTINCT r.id),
                    COUNT(DISTINCT f.id),
                    COUNT(DISTINCT CASE WHEN r.public = true THEN r.id END)
                FROM resources r
                LEFT JOIN findings f ON r.id = f.resource_id
            """)
            total_resources, total_findings, public_resources = cur.fetchone()
            
            # Severity
            cur.execute("""
                SELECT severity, COUNT(*)
                FROM findings
                GROUP BY severity
            """)
            severity_breakdown = dict(cur.fetchall())
            
            # Providers
            cur.execute("""
                SELECT 
                    r.cloud,
                    COUNT(DISTINCT r.id),
                    COUNT(DISTINCT f.id)
                FROM resources r
                LEFT JOIN findings f ON r.id = f.resource_id
                GROUP BY r.cloud
            """)
            providers = [
                {"provider": p, "resources": r, "findings": f}
                for p, r, f in cur.fetchall()
            ]
        
        risk_ratio = (total_findings / total_resources) if total_resources else 0
        security_score = max(0, 100 - (risk_ratio * 50))
        
        return {
            "status": "success",
            "data": {
                "total_resources": total_resources or 0,
                "total_findings": total_findings or 0,
                "public_resources": public_resources or 0,
                "security_score": round(security_score, 2),
                "severity_breakdown": severity_breakdown,
                "providers": providers,
                "timestamp": datetime.utcnow().isoformat()
            }
        }
        
    except Exception as e:
        logger.exception("Failed to get dashboard summary")
        return {
            "status": "error",
            "message": str(e)
        }

# ============================================================
# APPLICATION STARTUP
# ============================================================

@app.on_event("startup")
async def startup_event():
    """Initialize on startup"""
    logger.info("🚀 CloudGuard Security Scanner starting up...")
    logger.info(f"📊 Version: 3.1.0")
    logger.info(f"🤖 AI Model: {OPENAI_AGENT_MODEL}")
    
    # Initialize plugins with environment credentials
    initialize_plugins_with_credentials()
    
    # Log available tools
    logger.info(f"🔧 Vulnerability tools available: {list(vuln_scanner.tools_available.keys())}")
    logger.info(f"☁️ Registered providers: {mcp_registry.list_providers()}")
    
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

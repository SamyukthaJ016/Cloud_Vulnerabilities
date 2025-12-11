# # main.py

# import os
# import json
# import logging
# from fastapi import FastAPI, HTTPException
# from pydantic import BaseModel
# from dotenv import load_dotenv
# from openai import OpenAI

# from io import BytesIO
# from fastapi.responses import StreamingResponse
# from reportlab.lib.pagesizes import A4
# from reportlab.pdfgen import canvas
# import textwrap




# # MCP Framework
# from mcp_base import mcp_registry, ScanResult, Severity

# # Plugins (your filenames must match these imports)
# from mcp_aws_plugin import AWSPlugin
# from mcp_gcp_plugin import GCPPlugin
# from mcp_openai_plugin import OpenAIPlugin

# # AI Engine
# from ai_recommender import AIRecommendationEngine

# # DB Layer
# from database import (
#     create_scan_record,
#     store_resource,
#     store_finding,
#     get_scan_report,
#     get_multi_cloud_summary,
#     DB_CONN,
# )

# load_dotenv()

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger("mcp_scanner")


# # ============================================================
# # FASTAPI APP
# # ============================================================

# app = FastAPI(
#     title="Multi-Cloud MCP Security Scanner",
#     description="CSPM-style scanner with AI-powered recommendations",
#     version="2.0.0"
# )

# # OpenAI Client for orchestrator logic
# orchestrator_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
# ai_engine = AIRecommendationEngine(api_key=os.getenv("OPENAI_API_KEY"))


# # ============================================================
# # REGISTER PLUGINS
# # ============================================================

# def initialize_plugins():
#     """Register AWS, GCP, OpenAI MCP plugins"""

#     # AWS
#     try:
#         aws_plugin = AWSPlugin({
#             "access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
#             "secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
#             "region": os.getenv("AWS_REGION", "us-east-1")
#         })
#         mcp_registry.register("aws", aws_plugin)
#         logger.info("✓ AWS Plugin registered")
#     except Exception as e:
#         logger.warning(f"⚠ AWS Plugin failed: {e}")

#     # GCP
#     try:
#         gcp_plugin = GCPPlugin({
#             "service_account_json": os.getenv("GCP_SERVICE_ACCOUNT_JSON"),
#             "project_id": os.getenv("GCP_PROJECT_ID"),
#         })
#         mcp_registry.register("gcp", gcp_plugin)
#         logger.info("✓ GCP Plugin registered")
#     except Exception as e:
#         logger.warning(f"⚠ GCP Plugin failed: {e}")

#     # OpenAI
#     try:
#         openai_plugin = OpenAIPlugin({
#             "api_key": os.getenv("OPENAI_API_KEY"),
#             "org_id": os.getenv("OPENAI_ORG_ID")
#         })
#         mcp_registry.register("openai", openai_plugin)
#         logger.info("✓ OpenAI Plugin registered")
#     except Exception as e:
#         logger.warning(f"⚠ OpenAI Plugin failed: {e}")


# initialize_plugins()


# # ============================================================
# # REQUEST MODELS
# # ============================================================

# class ScanRequest(BaseModel):
#     message: str


# class MultiCloudScanRequest(BaseModel):
#     providers: list[str]
#     account_ids: dict[str, str] = {}


# # ============================================================
# # API ROUTES
# # ============================================================

# @app.get("/")
# async def root():
#     return {
#         "service": "Multi-Cloud MCP Security Scanner",
#         "version": "2.0.0",
#         "registered_providers": mcp_registry.list_providers(),
#         "features": [
#             "MCP Plugins",
#             "Real Cloud Resource Scanning",
#             "AI Recommendations",
#             "Security Dashboard",
#             "Compliance Mapping"
#         ]
#     }


# # ------------------------------------------------------------
# # AI-ORCHESTRATED MULTI-CLOUD SCAN
# # ------------------------------------------------------------
# @app.post("/scan")
# async def intelligent_scan(request: ScanRequest):
#     logger.info(f"Scan message received: {request.message}")

#     # Step 1: LLM decides scan plan
#     try:
#         response = orchestrator_client.chat.completions.create(
#             model="gpt-4o-mini",
#             messages=[
#                 {
#                     "role": "system",
#                     "content": (
#                         "You are a security orchestration AI. Extract cloud providers.\n"
#                         "Output ONLY JSON:\n"
#                         "{\"providers\": [\"aws\", \"gcp\"], \"account_ids\": {\"aws\": \"acc\"}}"
#                     )
#                 },
#                 {"role": "user", "content": request.message}
#             ],
#             temperature=0.1
#         )

#         plan_raw = response.choices[0].message.content.strip()

#         # Strip markdown
#         if plan_raw.startswith("```"):
#             plan_raw = plan_raw.split("```")[1].strip()

#         plan = json.loads(plan_raw)
#     except Exception as e:
#         logger.error(f"LLM error: {e}")
#         plan = {"providers": ["aws"], "account_ids": {"aws": "default"}}

#     providers = plan.get("providers", ["aws"])
#     account_ids = plan.get("account_ids", {})

#     scan_results = []
#     stored_ids = []

#     # Step 2: Run provider scans
#     for provider in providers:
#         try:
#             account_id = account_ids.get(provider, "default")
#             result = await mcp_registry.scan(provider, account_id)
#             scan_results.append(result)

#             scan_id = await store_scan_result(result)
#             stored_ids.append(scan_id)

#             logger.info(f"✓ {provider.upper()} scan finished")
#         except Exception as e:
#             logger.error(f"Scan failed for {provider}: {e}")

#     # Step 3: AI risk analysis
#     try:
#         ai_analysis = await ai_engine.analyze_scan_results(scan_results)
#     except Exception as e:
#         logger.error(f"AI analysis failed: {e}")
#         ai_analysis = {"error": "AI unavailable"}

#     return {
#         "status": "completed",
#         "scan_ids": stored_ids,
#         "providers_scanned": providers,
#         "total_resources": sum(len(r.resources) for r in scan_results),
#         "total_findings": sum(len(r.findings) for r in scan_results),
#         "ai_analysis": ai_analysis.get("ai_analysis", ""),
#         "remediation_plan": ai_analysis.get("remediation_plan", {}),
#         "executive_summary": ai_analysis.get("executive_summary", {})
#     }


# # ------------------------------------------------------------
# # DIRECT MULTI-CLOUD SCAN
# # ------------------------------------------------------------
# @app.post("/scan/multi-cloud")
# async def multi_cloud_scan(request: MultiCloudScanRequest):

#     scan_results = []
#     stored_ids = []

#     for provider in request.providers:
#         try:
#             account_id = request.account_ids.get(provider, "default")
#             result = await mcp_registry.scan(provider, account_id)
#             scan_results.append(result)

#             scan_id = await store_scan_result(result)
#             stored_ids.append(scan_id)
#         except Exception as e:
#             raise HTTPException(status_code=500, detail=f"{provider} scan failed: {e}")

#     ai_analysis = await ai_engine.analyze_scan_results(scan_results)

#     return {
#         "status": "completed",
#         "scan_ids": stored_ids,
#         "scan_results": [
#             {
#                 "provider": r.provider,
#                 "resources": len(r.resources),
#                 "findings": len(r.findings),
#                 "duration": r.scan_duration
#             }
#             for r in scan_results
#         ],
#         "ai_analysis": ai_analysis
#     }


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

#     # Providers (clouds) ka set bana lo
#     providers = sorted({(r[2] or "").lower() for r in rows if r[2]})

#     # Per-cloud summary
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
#         "providers": providers,     # e.g. ["aws"] ya ["aws", "openai"]
#         "per_cloud": per_cloud,     # e.g. {"aws": {"resources": 3,"findings":0},...}
#     }



# # ------------------------------------------------------------
# # REPORTS
# # ------------------------------------------------------------

# # @app.get("/report/{scan_id}")
# # async def get_report(scan_id: int):
# #     rows = get_scan_report(scan_id)

# #     findings = [
# #         {
# #             "resource_id": r[0],
# #             "resource_name": r[1],
# #             "cloud": r[2],
# #             "type": r[3],
# #             "public": r[4],
# #             "severity": r[5],
# #             "description": r[6]
# #         }
# #         for r in rows if r[5]
# #     ]

# #     return {
# #         "scan_id": scan_id,
# #         "total_resources": len(rows),
# #         "total_findings": len(findings),
# #         "findings": findings
# #     }

# @app.get("/report/{scan_id}")
# async def get_report(scan_id: int):
#     return build_scan_report(scan_id)


# def _wrap_text(text: str, width: int = 95):
#     text = text.replace("\r", " ").replace("\n", " ")
#     return textwrap.wrap(text, width=width)


# @app.get("/report/{scan_id}/pdf")
# async def get_report_pdf(scan_id: int):
#     data = build_scan_report(scan_id)

#     providers = data.get("providers", [])
#     per_cloud = data.get("per_cloud", {})

#     # Provider label text bana lo
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

#     # =========================================================
#     # COVER TITLE
#     # =========================================================
#     p.setFont("Helvetica-Bold", 20)
#     p.drawCentredString(width / 2, y, "Multi-Cloud Security Assessment Report")
#     y -= 40

#     p.setFont("Helvetica", 12)
#     p.drawCentredString(width / 2, y, f"Scan ID: {scan_id}")
#     y -= 18
#     p.drawCentredString(width / 2, y, provider_line)
#     y -= 18
#     p.drawCentredString(width / 2, y, "Generated by MCP Security Scanner")
#     y -= 40

#     # =========================================================
#     # 1. EXECUTIVE SUMMARY
#     # =========================================================
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

#     # =========================================================
#     # 2. RISK SUMMARY
#     # =========================================================
#     y -= 20
#     p.setFont("Helvetica-Bold", 14)
#     p.drawString(50, y, "2. Risk Summary")
#     y -= 20

#     p.setFont("Helvetica", 11)
#     p.drawString(60, y, f"Total Resources Scanned: {data['total_resources']}")
#     y -= 14
#     p.drawString(60, y, f"Total Security Findings: {data['total_findings']}")
#     y -= 18

#     if per_cloud:
#         p.drawString(60, y, "Per-Cloud Breakdown:")
#         y -= 14
#         for cloud, stats in per_cloud.items():
#             line = f"- {cloud.upper()}: {stats['resources']} resources, {stats['findings']} findings"
#             for part in _wrap_text(line, width=95):
#                 p.drawString(70, y, part)
#                 y -= 14
#             y -= 4

#     # =========================================================
#     # 3. DETAILED FINDINGS
#     # =========================================================
#     if y < 160:
#         p.showPage()
#         y = height - 60

#     p.setFont("Helvetica-Bold", 14)
#     p.drawString(50, y, "3. Detailed Findings")
#     y -= 20

#     p.setFont("Helvetica", 10)

#     findings = data.get("findings", [])

#     if not findings:
#         p.drawString(60, y, "No findings detected in this scan.")
#         y -= 14
#     else:
#         for idx, f in enumerate(findings, start=1):
#             block = (
#                 f"Finding #{idx}\n"
#                 f"Severity: {f.get('severity')}\n"
#                 f"Cloud: {f.get('cloud', '').upper()}\n"
#                 f"Resource: {f.get('resource_name')} ({f.get('type')})\n"
#                 f"Issue Description: {f.get('description')}"
#             )

#             for line in _wrap_text(block, width=95):
#                 if y < 80:
#                     p.showPage()
#                     p.setFont("Helvetica", 10)
#                     y = height - 60
#                 p.drawString(60, y, line)
#                 y -= 14

#             y -= 12  # gap between findings

#     # =========================================================
#     # 4. RECOMMENDED REMEDIATION PLAN
#     # =========================================================
#     if y < 200:
#         p.showPage()
#         y = height - 60

#     p.setFont("Helvetica-Bold", 14)
#     p.drawString(50, y, "4. Recommended Remediation Plan")
#     y -= 20

#     p.setFont("Helvetica", 11)

#     # Generic + provider-specific points
#     lines = []

#     # High priority generic
#     lines.append("High Priority (Immediate Actions):")
#     lines.append("- Review and fix high-severity issues identified in this scan.")
#     if "openai" in providers:
#         lines.append("- Rotate OpenAI API keys and move them to a secure secrets manager.")
#     if "aws" in providers:
#         lines.append("- Review AWS IAM roles and S3/public access settings.")
#     if "gcp" in providers:
#         lines.append("- Review GCP IAM bindings and firewall rules.")
#     lines.append("")

#     # Medium priority
#     lines.append("Medium Priority (Next 7 Days):")
#     lines.append("- Enable monitoring and usage alerts for suspicious activity.")
#     lines.append("- Implement least-privilege access for identities and API keys.")
#     lines.append("- Document governance for how cloud resources and models may be used.")
#     lines.append("")

#     # Long term
#     lines.append("Long-Term Improvements:")
#     lines.append("- Integrate logs with a central SIEM or monitoring platform.")
#     lines.append("- Schedule periodic security scans and posture reviews.")

#     remediation_text = "\n".join(lines)

#     for line in _wrap_text(remediation_text):
#         if y < 80:
#             p.showPage()
#             p.setFont("Helvetica", 11)
#             y = height - 60
#         p.drawString(60, y, line)
#         y -= 14

#     # =========================================================
#     # 5. CONCLUSION
#     # =========================================================
#     if y < 150:
#         p.showPage()
#         y = height - 60

#     p.setFont("Helvetica-Bold", 14)
#     p.drawString(50, y, "5. Conclusion")
#     y -= 20

#     p.setFont("Helvetica", 11)
#     conclusion_text = (
#         "This assessment provides a snapshot of the current security posture of the scanned cloud "
#         "environment(s). Addressing the identified findings and following the remediation plan will "
#         "significantly reduce risk and improve the overall security posture across AWS, GCP, OpenAI, "
#         "and other integrated platforms as applicable."
#     )

#     for line in _wrap_text(conclusion_text):
#         if y < 80:
#             p.showPage()
#             p.setFont("Helvetica", 11)
#             y = height - 60
#         p.drawString(60, y, line)
#         y -= 14

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
#         "public_resources": 0
#     }

#     for provider, res, find, public in summary:
#         dashboard["clouds"].append({
#             "provider": provider,
#             "resources": res,
#             "findings": find,
#             "public": public
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
#     return dashboard


# @app.get("/providers")
# async def list_providers():
#     return {
#         "registered_providers": mcp_registry.list_providers(),
#         "total": len(mcp_registry.list_providers())
#     }


# # ------------------------------------------------------------
# # STORE SCAN RESULT
# # ------------------------------------------------------------
# async def store_scan_result(result: ScanResult) -> int:
#     scan_id = create_scan_record(result.account_id, result.provider)

#     # Store resources
#     for r in result.resources:
#         store_resource(scan_id, result.provider, r.resource_type, r.name, r.config, r.is_public)

#     # Store findings
#     for f in result.findings:
#         cur = DB_CONN.cursor()
#         cur.execute(
#             "SELECT id FROM resources WHERE scan_id=%s AND name=%s LIMIT 1",
#             (scan_id, f.resource.name)
#         )
#         row = cur.fetchone()
#         cur.close()

#         if row:
#             resource_id = row[0]
#             store_finding(
#                 scan_id,
#                 resource_id,
#                 f.severity.value,
#                 f"{f.issue}: {f.description}",
#                 result.provider
#             )

#     logger.info(f"Stored scan {scan_id}")
#     return scan_id


# # ============================================================
# # UVICORN ENTRYPOINT
# # ============================================================

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)



# main.py

# import os
# import json
# import logging
# from io import BytesIO
# import textwrap
# from typing import Optional

# from fastapi import FastAPI, HTTPException
# from pydantic import BaseModel
# from dotenv import load_dotenv
# from openai import OpenAI

# from fastapi.responses import StreamingResponse
# from reportlab.lib.pagesizes import A4
# from reportlab.pdfgen import canvas

# from mcp_base import mcp_registry, ScanResult
# from mcp_aws_plugin import AWSPlugin
# from mcp_gcp_plugin import GCPPlugin
# from mcp_openai_plugin import OpenAIPlugin
# from ai_recommender import AIRecommendationEngine

# from database import (
#     create_scan_record,
#     store_resource,
#     store_finding,
#     get_scan_report,
#     get_multi_cloud_summary,
#     DB_CONN,
# )

# load_dotenv()

# logging.basicConfig(level=logging.INFO)
# logger = logging.getLogger("mcp_scanner")

# # ============================================================
# # FASTAPI APP
# # ============================================================

# app = FastAPI(
#     title="Multi-Cloud MCP Security Scanner",
#     description="CSPM-style scanner with GPT-powered Agentic AI",
#     version="2.2.0",
# )

# OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL", "gpt-4o-mini")

# openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
# orchestrator_client = openai_client
# ai_engine = AIRecommendationEngine(api_key=os.getenv("OPENAI_API_KEY"))

# # ============================================================
# # REGISTER PLUGINS
# # ============================================================

# def initialize_plugins() -> None:
#     try:
#         aws_plugin = AWSPlugin({
#             "access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
#             "secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
#             "region": os.getenv("AWS_REGION", "us-east-1"),
#         })
#         mcp_registry.register("aws", aws_plugin)
#     except Exception as e:
#         logger.warning("AWS Plugin failed: %s", e)

#     try:
#         gcp_plugin = GCPPlugin({
#             "service_account_json": os.getenv("GCP_SERVICE_ACCOUNT_JSON"),
#             "project_id": os.getenv("GCP_PROJECT_ID"),
#         })
#         mcp_registry.register("gcp", gcp_plugin)
#     except Exception as e:
#         logger.warning("GCP Plugin failed: %s", e)

#     try:
#         openai_plugin = OpenAIPlugin({
#             "api_key": os.getenv("OPENAI_API_KEY"),
#             "org_id": os.getenv("OPENAI_ORG_ID"),
#         })
#         mcp_registry.register("openai", openai_plugin)
#     except Exception as e:
#         logger.warning("OpenAI Plugin failed: %s", e)

# initialize_plugins()

# # ============================================================
# # REQUEST MODELS
# # ============================================================

# class ScanRequest(BaseModel):
#     message: str

# class MultiCloudScanRequest(BaseModel):
#     providers: list[str]
#     account_ids: dict[str, str] = {}

# class AgentChatRequest(BaseModel):
#     message: str

# class AgentChatResponse(BaseModel):
#     reply: str

# class AgentExplainScanRequest(BaseModel):
#     scan_id: int
#     question: Optional[str] = None

# # ============================================================
# # GPT AGENT ENGINE (REPLACES GEMINI)
# # ============================================================

# async def run_gpt_agent(prompt: str) -> str:
#     try:
#         response = openai_client.chat.completions.create(
#             model=OPENAI_AGENT_MODEL,
#             messages=[
#                 {"role": "system", "content": "You are a cloud security expert and CSPM analyst."},
#                 {"role": "user", "content": prompt},
#             ],
#             temperature=0.2,
#         )
#         return response.choices[0].message.content.strip()

#     except Exception as e:
#         logger.error("GPT Agent error: %s", e)
#         return f"Agent error: {e}"

# # ============================================================
# # API ROUTES
# # ============================================================

# @app.get("/")
# async def root():
#     return {
#         "service": "Multi-Cloud MCP Security Scanner",
#         "version": "2.2.0",
#         "agent_model": OPENAI_AGENT_MODEL,
#         "registered_providers": mcp_registry.list_providers(),
#     }

# @app.post("/scan")
# async def intelligent_scan(request: ScanRequest):
#     try:
#         response = orchestrator_client.chat.completions.create(
#             model=OPENAI_AGENT_MODEL,
#             messages=[
#                 {
#                     "role": "system",
#                     "content": "Extract cloud providers and return JSON only."
#                 },
#                 {"role": "user", "content": request.message},
#             ],
#         )
#         plan = json.loads(response.choices[0].message.content)
#     except:
#         plan = {"providers": ["aws"], "account_ids": {"aws": "default"}}

#     providers = plan["providers"]
#     account_ids = plan.get("account_ids", {})

#     scan_results = []
#     stored_ids = []

#     for provider in providers:
#         result = await mcp_registry.scan(provider, account_ids.get(provider, "default"))
#         scan_id = await store_scan_result(result)

#         scan_results.append(result)
#         stored_ids.append(scan_id)

#     ai_analysis = await ai_engine.analyze_scan_results(scan_results)

#     return {
#         "scan_ids": stored_ids,
#         "providers_scanned": providers,
#         "ai_analysis": ai_analysis,
#     }

# @app.post("/agent/chat", response_model=AgentChatResponse)
# async def agent_chat(request: AgentChatRequest):
#     reply = await run_gpt_agent(request.message)
#     return AgentChatResponse(reply=reply)

# @app.post("/agent/scan/explain", response_model=AgentChatResponse)
# async def agent_explain_scan(request: AgentExplainScanRequest):
#     data = get_scan_report(request.scan_id)

#     prompt = f"""
# You are analyzing Scan ID {request.scan_id}.
# Findings:
# {json.dumps(data, indent=2)}

# User Question:
# {request.question or "Provide executive summary, risks and remediation"}
# """

#     reply = await run_gpt_agent(prompt)
#     return AgentChatResponse(reply=reply)

# # ============================================================
# # DATABASE STORAGE
# # ============================================================

# async def store_scan_result(result: ScanResult) -> int:
#     scan_id = create_scan_record(result.account_id, result.provider)

#     for r in result.resources:
#         store_resource(scan_id, result.provider, r.resource_type, r.name, r.config, r.is_public)

#     for f in result.findings:
#         cur = DB_CONN.cursor()
#         cur.execute(
#             "SELECT id FROM resources WHERE scan_id=%s AND name=%s LIMIT 1",
#             (scan_id, f.resource.name),
#         )
#         row = cur.fetchone()
#         cur.close()

#         if row:
#             store_finding(scan_id, row[0], f.severity.value,
#                           f"{f.issue}: {f.description}", result.provider)

#     return scan_id

# # ============================================================
# # UVICORN
# # ============================================================

# if __name__ == "__main__":
#     import uvicorn
#     uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)


import os
import json
import logging
import textwrap
from io import BytesIO
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from openai import OpenAI

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas

from mcp_base import mcp_registry, ScanResult
from mcp_aws_plugin import AWSPlugin
from mcp_gcp_plugin import GCPPlugin
from mcp_openai_plugin import OpenAIPlugin
from ai_recommender import AIRecommendationEngine
from fastapi.responses import HTMLResponse
from database import (
    create_scan_record,
    store_resource,
    store_finding,
    get_scan_report,
    get_multi_cloud_summary,
    DB_CONN,
)

load_dotenv()

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp_scanner")

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI(
    title="Multi-Cloud MCP Security Scanner",
    description="CSPM-style scanner with GPT-powered Agentic AI",
    version="2.2.0",
)

OPENAI_AGENT_MODEL = os.getenv("OPENAI_AGENT_MODEL", "gpt-4o-mini")

openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
orchestrator_client = openai_client
ai_engine = AIRecommendationEngine(api_key=os.getenv("OPENAI_API_KEY"))

# ============================================================
# REGISTER PLUGINS
# ============================================================

def initialize_plugins() -> None:
    """Register AWS, GCP, OpenAI MCP plugins"""
    # AWS
    try:
        aws_plugin = AWSPlugin({
            "access_key_id": os.getenv("AWS_ACCESS_KEY_ID"),
            "secret_access_key": os.getenv("AWS_SECRET_ACCESS_KEY"),
            "region": os.getenv("AWS_REGION", "us-east-1"),
        })
        mcp_registry.register("aws", aws_plugin)
        logger.info("✓ AWS Plugin registered")
    except Exception as e:
        logger.warning("⚠ AWS Plugin failed: %s", e)

    # GCP
    try:
        gcp_plugin = GCPPlugin({
            "service_account_json": os.getenv("GCP_SERVICE_ACCOUNT_JSON"),
            "project_id": os.getenv("GCP_PROJECT_ID"),
        })
        mcp_registry.register("gcp", gcp_plugin)
        logger.info("✓ GCP Plugin registered")
    except Exception as e:
        logger.warning("⚠ GCP Plugin failed: %s", e)

    # OpenAI
    try:
        openai_plugin = OpenAIPlugin({
            "api_key": os.getenv("OPENAI_API_KEY"),
            "org_id": os.getenv("OPENAI_ORG_ID"),
        })
        mcp_registry.register("openai", openai_plugin)
        logger.info("✓ OpenAI Plugin registered")
    except Exception as e:
        logger.warning("⚠ OpenAI Plugin failed: %s", e)


initialize_plugins()

# ============================================================
# REQUEST MODELS
# ============================================================

class ScanRequest(BaseModel):
    message: str


class MultiCloudScanRequest(BaseModel):
    providers: list[str]
    account_ids: dict[str, str] = {}


class AgentChatRequest(BaseModel):
    message: str


class AgentChatResponse(BaseModel):
    reply: str


class AgentExplainScanRequest(BaseModel):
    scan_id: int
    question: Optional[str] = None


# ============================================================
# GPT AGENT ENGINE
# ============================================================

async def run_gpt_agent(prompt: str) -> str:
    try:
        response = openai_client.chat.completions.create(
            model=OPENAI_AGENT_MODEL,
            messages=[
                {
                    "role": "system",
                    "content": "You are a cloud security expert and CSPM analyst."
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content.strip()
    except Exception as e:
        logger.error("GPT Agent error: %s", e)
        return f"Agent error: {e}"


# ============================================================
# HELPER FUNCTIONS (REPORT BUILDING)
# ============================================================

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

    # Unique providers
    providers = sorted({(r[2] or "").lower() for r in rows if r[2]})

    # Per-cloud summary
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
        "providers": providers,   # e.g. ["aws"] or ["aws", "openai"]
        "per_cloud": per_cloud,   # e.g. {"aws": {"resources": 3, "findings": 0}, ...}
    }


# ============================================================
# API ROUTES
# ============================================================

@app.get("/")
async def root():
    return {
        "service": "Multi-Cloud MCP Security Scanner",
        "version": "2.2.0",
        "agent_model": OPENAI_AGENT_MODEL,
        "registered_providers": mcp_registry.list_providers(),
        "features": [
            "MCP Plugins",
            "Real Cloud Resource Scanning",
            "AI Recommendations",
            "Security Dashboard",
            "Compliance Mapping",
            "Agent Chat",
            "Agent Scan Explain",
        ],
    }


# ------------------------------------------------------------
# AI-ORCHESTRATED MULTI-CLOUD SCAN (/scan)
# ------------------------------------------------------------
@app.post("/scan")
async def intelligent_scan(request: ScanRequest):
    logger.info("Scan message received: %s", request.message)

    valid_providers = {p.lower() for p in mcp_registry.list_providers()}

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

        # Strip markdown fences if present
        if plan_raw.startswith("```"):
            parts = plan_raw.split("```")
            if len(parts) >= 2:
                plan_raw = parts[1].strip()

        plan = json.loads(plan_raw)
    except Exception as e:
        logger.error("LLM plan extraction error: %s", e)
        plan = {"providers": ["aws"], "account_ids": {"aws": "default"}}

    # Normalize and validate providers
    providers = [p.lower() for p in plan.get("providers", []) if isinstance(p, str)]
    providers = [p for p in providers if p in valid_providers]

    account_ids = plan.get("account_ids", {})
    if not isinstance(account_ids, dict):
        account_ids = {}

    # Heuristic: if user text explicitly mentions a provider, force-add it
    msg_lower = request.message.lower()
    if "aws" in msg_lower and "aws" in valid_providers and "aws" not in providers:
        providers.append("aws")
    if ("gcp" in msg_lower or "google cloud" in msg_lower) and "gcp" in valid_providers and "gcp" not in providers:
        providers.append("gcp")
    if "openai" in msg_lower and "openai" in valid_providers and "openai" not in providers:
        providers.append("openai")

    # Final fallback: if nothing left, default to aws if available, otherwise all providers
    if not providers:
        if "aws" in valid_providers:
            providers = ["aws"]
        else:
            providers = list(valid_providers)

    logger.info("Final providers to scan: %s", providers)

    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    # Step 2: Run provider scans
    for provider in providers:
        try:
            account_id = account_ids.get(provider, "default")
            result = await mcp_registry.scan(provider, account_id)
            scan_results.append(result)

            scan_id = await store_scan_result(result)
            stored_ids.append(scan_id)

            logger.info("✓ %s scan finished", provider.upper())
        except Exception as e:
            logger.error("Scan failed for %s: %s", provider, e)

    # Step 3: AI risk analysis
    try:
        ai_analysis = await ai_engine.analyze_scan_results(scan_results)
    except Exception as e:
        logger.error("AI analysis failed: %s", e)
        ai_analysis = {"error": "AI unavailable"}

    return {
        "status": "completed",
        "scan_ids": stored_ids,
        "providers_scanned": providers,
        "total_resources": sum(len(r.resources) for r in scan_results),
        "total_findings": sum(len(r.findings) for r in scan_results),
        "ai_analysis": ai_analysis.get("ai_analysis", ""),
        "remediation_plan": ai_analysis.get("remediation_plan", {}),
        "executive_summary": ai_analysis.get("executive_summary", {}),
    }


# ------------------------------------------------------------
# DIRECT MULTI-CLOUD SCAN (/scan/multi-cloud)
# ------------------------------------------------------------
@app.post("/scan/multi-cloud")
async def multi_cloud_scan(request: MultiCloudScanRequest):
    scan_results: list[ScanResult] = []
    stored_ids: list[int] = []

    for provider in request.providers:
        try:
            account_id = request.account_ids.get(provider, "default")
            result = await mcp_registry.scan(provider, account_id)
            scan_results.append(result)

            scan_id = await store_scan_result(result)
            stored_ids.append(scan_id)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"{provider} scan failed: {e}")

    ai_analysis = await ai_engine.analyze_scan_results(scan_results)

    return {
        "status": "completed",
        "scan_ids": stored_ids,
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


# ------------------------------------------------------------
# AGENT CHAT
# ------------------------------------------------------------
@app.post("/agent/chat", response_model=AgentChatResponse)
async def agent_chat(request: AgentChatRequest):
    reply = await run_gpt_agent(request.message)
    return AgentChatResponse(reply=reply)


# ------------------------------------------------------------
# AGENT SCAN EXPLAIN
# ------------------------------------------------------------
@app.post("/agent/scan/explain", response_model=AgentChatResponse)
async def agent_explain_scan(request: AgentExplainScanRequest):
    # Use the structured report for better context
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

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    """Serve the dashboard UI"""
    with open("dashboard.html", "r") as f:
        return f.read()

# Optional: Make dashboard the default route
@app.get("/", response_class=HTMLResponse)
async def root_redirect():
    """Redirect root to dashboard"""
    with open("dashboard.html", "r") as f:
        return f.read()

# ------------------------------------------------------------
# REPORTS
# ------------------------------------------------------------
@app.get("/report/{scan_id}")
async def get_report(scan_id: int):
    return build_scan_report(scan_id)


@app.get("/report/{scan_id}/pdf")
async def get_report_pdf(scan_id: int):
    data = build_scan_report(scan_id)

    providers = data.get("providers", [])
    per_cloud = data.get("per_cloud", {})

    # Provider line
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

    # =========================================================
    # COVER TITLE
    # =========================================================
    p.setFont("Helvetica-Bold", 20)
    p.drawCentredString(width / 2, y, "Multi-Cloud Security Assessment Report")
    y -= 40

    p.setFont("Helvetica", 12)
    p.drawCentredString(width / 2, y, f"Scan ID: {scan_id}")
    y -= 18
    p.drawCentredString(width / 2, y, provider_line)
    y -= 18
    p.drawCentredString(width / 2, y, "Generated by MCP Security Scanner")
    y -= 40

    # =========================================================
    # 1. EXECUTIVE SUMMARY
    # =========================================================
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

    # =========================================================
    # 2. RISK SUMMARY
    # =========================================================
    y -= 20
    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "2. Risk Summary")
    y -= 20

    p.setFont("Helvetica", 11)
    p.drawString(60, y, f"Total Resources Scanned: {data['total_resources']}")
    y -= 14
    p.drawString(60, y, f"Total Security Findings: {data['total_findings']}")
    y -= 18

    if per_cloud:
        p.drawString(60, y, "Per-Cloud Breakdown:")
        y -= 14
        for cloud, stats in per_cloud.items():
            line = f"- {cloud.upper()}: {stats['resources']} resources, {stats['findings']} findings"
            for part in _wrap_text(line, width=95):
                p.drawString(70, y, part)
                y -= 14
            y -= 4

    # =========================================================
    # 3. DETAILED FINDINGS
    # =========================================================
    if y < 160:
        p.showPage()
        y = height - 60

    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "3. Detailed Findings")
    y -= 20

    p.setFont("Helvetica", 10)

    findings = data.get("findings", [])

    if not findings:
        p.drawString(60, y, "No findings detected in this scan.")
        y -= 14
    else:
        for idx, f in enumerate(findings, start=1):
            block = (
                f"Finding #{idx}\n"
                f"Severity: {f.get('severity')}\n"
                f"Cloud: {f.get('cloud', '').upper()}\n"
                f"Resource: {f.get('resource_name')} ({f.get('type')})\n"
                f"Issue Description: {f.get('description')}"
            )

            for line in _wrap_text(block, width=95):
                if y < 80:
                    p.showPage()
                    p.setFont("Helvetica", 10)
                    y = height - 60
                p.drawString(60, y, line)
                y -= 14

            y -= 12  # gap between findings

    # =========================================================
    # 4. RECOMMENDED REMEDIATION PLAN
    # =========================================================
    if y < 200:
        p.showPage()
        y = height - 60

    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "4. Recommended Remediation Plan")
    y -= 20

    p.setFont("Helvetica", 11)

    lines = []

    # High priority generic
    lines.append("High Priority (Immediate Actions):")
    lines.append("- Review and fix high-severity issues identified in this scan.")
    if "openai" in providers:
        lines.append("- Rotate OpenAI API keys and move them to a secure secrets manager.")
    if "aws" in providers:
        lines.append("- Review AWS IAM roles and S3/public access settings.")
    if "gcp" in providers:
        lines.append("- Review GCP IAM bindings and firewall rules.")
    lines.append("")

    # Medium priority
    lines.append("Medium Priority (Next 7 Days):")
    lines.append("- Enable monitoring and usage alerts for suspicious activity.")
    lines.append("- Implement least-privilege access for identities and API keys.")
    lines.append("- Document governance for how cloud resources and models may be used.")
    lines.append("")

    # Long term
    lines.append("Long-Term Improvements:")
    lines.append("- Integrate logs with a central SIEM or monitoring platform.")
    lines.append("- Schedule periodic security scans and posture reviews.")

    remediation_text = "\n".join(lines)

    for line in _wrap_text(remediation_text):
        if y < 80:
            p.showPage()
            p.setFont("Helvetica", 11)
            y = height - 60
        p.drawString(60, y, line)
        y -= 14

    # =========================================================
    # 5. CONCLUSION
    # =========================================================
    if y < 150:
        p.showPage()
        y = height - 60

    p.setFont("Helvetica-Bold", 14)
    p.drawString(50, y, "5. Conclusion")
    y -= 20

    p.setFont("Helvetica", 11)
    conclusion_text = (
        "This assessment provides a snapshot of the current security posture of the scanned cloud "
        "environment(s). Addressing the identified findings and following the remediation plan will "
        "significantly reduce risk and improve the overall security posture across AWS, GCP, OpenAI, "
        "and other integrated platforms as applicable."
    )

    for line in _wrap_text(conclusion_text):
        if y < 80:
            p.showPage()
            p.setFont("Helvetica", 11)
            y = height - 60
        p.drawString(60, y, line)
        y -= 14

    p.showPage()
    p.save()
    buffer.seek(0)

    return StreamingResponse(
        buffer,
        media_type="application/pdf",
        headers={
            "Content-Disposition": f'attachment; filename="security_scan_report_{scan_id}.pdf"'
        },
    )


# ------------------------------------------------------------
# DASHBOARD
# ------------------------------------------------------------
@app.get("/posture/dashboard")
async def posture_dashboard():
    summary = get_multi_cloud_summary()

    dashboard = {
        "clouds": [],
        "total_resources": 0,
        "total_findings": 0,
        "public_resources": 0,
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


# ------------------------------------------------------------
# PROVIDERS LIST
# ------------------------------------------------------------
@app.get("/providers")
async def list_providers():
    providers = mcp_registry.list_providers()
    return {
        "registered_providers": providers,
        "total": len(providers),
    }


# ============================================================
# DATABASE STORAGE
# ============================================================

async def store_scan_result(result: ScanResult) -> int:
    scan_id = create_scan_record(result.account_id, result.provider)

    # Store resources
    for r in result.resources:
        store_resource(
            scan_id,
            result.provider,
            r.resource_type,
            r.name,
            r.config,
            r.is_public,
        )

    # Store findings
    for f in result.findings:
        cur = DB_CONN.cursor()
        cur.execute(
            "SELECT id FROM resources WHERE scan_id=%s AND name=%s LIMIT 1",
            (scan_id, f.resource.name),
        )
        row = cur.fetchone()
        cur.close()

        if row:
            resource_id = row[0]
            store_finding(
                scan_id,
                resource_id,
                f.severity.value,
                f"{f.issue}: {f.description}",
                result.provider,
            )

    logger.info("Stored scan %s", scan_id)
    return scan_id


# ============================================================
# UVICORN ENTRYPOINT
# ============================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)

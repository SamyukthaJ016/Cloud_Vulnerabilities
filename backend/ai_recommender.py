"""
AI Recommendation Engine
Analyzes security findings and generates intelligent remediation plans
"""

import json
import logging
from typing import List, Dict, Any
from dataclasses import asdict
from openai import OpenAI
from mcp_base import ScanResult, SecurityFinding, Severity

logger = logging.getLogger("ai_recommender")


class AIRecommendationEngine:
    """
    AI-powered security posture analysis and recommendation system
    Uses OpenAI to:
    1. Summarize risks across cloud providers
    2. Prioritize remediation actions
    3. Generate 7-day remediation plans
    4. Predict exploitability
    5. Provide compliance guidance
    """

    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)
        self.model = "gpt-4o-mini"

    async def analyze_scan_results(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """
        Comprehensive AI analysis of multi-cloud scan results
        """
        logger.info(f"AI analyzing {len(scan_results)} cloud scan results")

        # Prepare findings summary for AI
        findings_summary = self._prepare_findings_summary(scan_results)
        
        # Generate AI analysis
        analysis = await self._generate_ai_analysis(findings_summary)
        
        # Create remediation plan
        remediation_plan = await self._create_remediation_plan(findings_summary)
        
        # Risk prioritization
        risk_priority = self._prioritize_risks(scan_results)
        
        return {
            "ai_analysis": analysis,
            "remediation_plan": remediation_plan,
            "risk_priority": risk_priority,
            "executive_summary": self._create_executive_summary(scan_results)
        }

    def _prepare_findings_summary(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Prepare findings in a format suitable for AI analysis"""
        summary = {
            "total_resources": 0,
            "total_findings": 0,
            "by_severity": {
                "CRITICAL": [],
                "HIGH": [],
                "MEDIUM": [],
                "LOW": [],
                "INFO": []
            },
            "by_provider": {},
            "compliance_gaps": []
        }

        for result in scan_results:
            summary["total_resources"] += len(result.resources)
            summary["total_findings"] += len(result.findings)
            
            if result.provider not in summary["by_provider"]:
                summary["by_provider"][result.provider] = {
                    "resources": 0,
                    "findings": 0,
                    "critical": 0
                }
            
            summary["by_provider"][result.provider]["resources"] += len(result.resources)
            summary["by_provider"][result.provider]["findings"] += len(result.findings)
            
            for finding in result.findings:
                severity = finding.severity.value
                summary["by_severity"][severity].append({
                    "provider": result.provider,
                    "resource": finding.resource.name,
                    "issue": finding.issue,
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "compliance": finding.compliance
                })
                
                if severity == "CRITICAL":
                    summary["by_provider"][result.provider]["critical"] += 1
                
                # Track unique compliance gaps
                for comp in finding.compliance:
                    if comp not in summary["compliance_gaps"]:
                        summary["compliance_gaps"].append(comp)

        return summary

    async def _generate_ai_analysis(self, findings_summary: Dict[str, Any]) -> str:
        """Generate AI-powered security analysis"""
        
        prompt = f"""
You are a cloud security expert analyzing multi-cloud security posture.

SCAN RESULTS:
- Total Resources Scanned: {findings_summary['total_resources']}
- Total Security Findings: {findings_summary['total_findings']}
- Critical Issues: {len(findings_summary['by_severity']['CRITICAL'])}
- High Issues: {len(findings_summary['by_severity']['HIGH'])}
- Medium Issues: {len(findings_summary['by_severity']['MEDIUM'])}

CRITICAL FINDINGS:
{json.dumps(findings_summary['by_severity']['CRITICAL'][:10], indent=2)}

HIGH FINDINGS:
{json.dumps(findings_summary['by_severity']['HIGH'][:10], indent=2)}

CLOUD PROVIDERS:
{json.dumps(findings_summary['by_provider'], indent=2)}

COMPLIANCE GAPS:
{', '.join(findings_summary['compliance_gaps'])}

Provide a comprehensive security analysis including:
1. Overall security posture rating (Critical/Poor/Fair/Good/Excellent)
2. Top 3 most critical risks and their business impact
3. Attack vectors that could be exploited
4. Compliance concerns
5. Recommended immediate actions (next 24 hours)
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an expert cloud security analyst providing actionable insights."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=1500
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return "AI analysis unavailable - please review findings manually"

    async def _create_remediation_plan(self, findings_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Create a 7-day remediation plan"""
        
        prompt = f"""
You are a cloud security remediation specialist.

FINDINGS TO REMEDIATE:
Critical: {len(findings_summary['by_severity']['CRITICAL'])} issues
High: {len(findings_summary['by_severity']['HIGH'])} issues
Medium: {len(findings_summary['by_severity']['MEDIUM'])} issues

TOP CRITICAL ISSUES:
{json.dumps(findings_summary['by_severity']['CRITICAL'][:5], indent=2)}

Create a realistic 7-day remediation plan in JSON format:
{{
  "day_1": {{
    "focus": "Emergency critical issues",
    "tasks": ["task 1", "task 2"],
    "priority": "CRITICAL"
  }},
  "day_2": {{ ... }},
  ...
  "day_7": {{ ... }}
}}

Prioritize by:
1. Exploitability (publicly exposed resources first)
2. Data sensitivity (IAM, encryption issues)
3. Compliance requirements
4. Ease of remediation
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You create practical, prioritized remediation plans. Output only valid JSON."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                max_tokens=1000
            )
            
            plan_text = response.choices[0].message.content.strip()
            
            # Try to parse JSON, fallback to text if fails
            try:
                # Remove markdown code blocks if present
                if plan_text.startswith("```json"):
                    plan_text = plan_text.split("```json")[1].split("```")[0].strip()
                elif plan_text.startswith("```"):
                    plan_text = plan_text.split("```")[1].split("```")[0].strip()
                
                return json.loads(plan_text)
            except:
                return {"plan_text": plan_text}
        
        except Exception as e:
            logger.error(f"Remediation plan generation failed: {e}")
            return {"error": "Unable to generate remediation plan"}

    def _prioritize_risks(self, scan_results: List[ScanResult]) -> List[Dict[str, Any]]:
        """Prioritize risks by severity and exploitability"""
        all_findings = []
        
        for result in scan_results:
            for finding in result.findings:
                # Calculate risk score
                severity_score = {
                    Severity.CRITICAL: 10,
                    Severity.HIGH: 7,
                    Severity.MEDIUM: 4,
                    Severity.LOW: 2,
                    Severity.INFO: 1
                }.get(finding.severity, 0)
                
                # Boost score for public exposure
                if finding.resource.is_public:
                    severity_score += 3
                
                # Boost score for IAM/access issues
                if "iam" in finding.resource.resource_type.lower() or "key" in finding.issue.lower():
                    severity_score += 2
                
                all_findings.append({
                    "risk_score": severity_score,
                    "provider": result.provider,
                    "resource": finding.resource.name,
                    "resource_type": finding.resource.resource_type,
                    "severity": finding.severity.value,
                    "issue": finding.issue,
                    "description": finding.description,
                    "recommendation": finding.recommendation,
                    "is_public": finding.resource.is_public,
                    "compliance": finding.compliance
                })
        
        # Sort by risk score
        all_findings.sort(key=lambda x: x["risk_score"], reverse=True)
        
        return all_findings[:20]  # Top 20 risks

    def _create_executive_summary(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """Create executive summary for dashboard"""
        total_resources = sum(len(r.resources) for r in scan_results)
        total_findings = sum(len(r.findings) for r in scan_results)
        
        severity_counts = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0,
            "INFO": 0
        }
        
        public_resources = 0
        
        for result in scan_results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
                if finding.resource.is_public:
                    public_resources += 1
        
        # Calculate security score (0-100)
        security_score = 100
        security_score -= severity_counts["CRITICAL"] * 15
        security_score -= severity_counts["HIGH"] * 8
        security_score -= severity_counts["MEDIUM"] * 3
        security_score -= severity_counts["LOW"] * 1
        security_score = max(0, security_score)
        
        # Determine posture
        if security_score >= 90:
            posture = "EXCELLENT"
        elif security_score >= 75:
            posture = "GOOD"
        elif security_score >= 50:
            posture = "FAIR"
        elif security_score >= 25:
            posture = "POOR"
        else:
            posture = "CRITICAL"
        
        return {
            "security_score": security_score,
            "security_posture": posture,
            "total_resources": total_resources,
            "total_findings": total_findings,
            "severity_breakdown": severity_counts,
            "public_resources": public_resources,
            "clouds_scanned": len(scan_results),
            "providers": [r.provider for r in scan_results]
        }

    async def generate_compliance_report(
        self, 
        scan_results: List[ScanResult], 
        framework: str = "CIS"
    ) -> Dict[str, Any]:
        """Generate compliance report for specific framework"""
        
        findings_by_control = {}
        
        for result in scan_results:
            for finding in result.findings:
                for control in finding.compliance:
                    if control.startswith(framework):
                        if control not in findings_by_control:
                            findings_by_control[control] = []
                        findings_by_control[control].append({
                            "provider": result.provider,
                            "resource": finding.resource.name,
                            "issue": finding.issue,
                            "severity": finding.severity.value
                        })
        
        total_controls = len(findings_by_control)
        failed_controls = sum(1 for findings in findings_by_control.values() if findings)
        
        compliance_percentage = ((total_controls - failed_controls) / total_controls * 100) if total_controls > 0 else 100
        
        return {
            "framework": framework,
            "compliance_percentage": round(compliance_percentage, 2),
            "total_controls_checked": total_controls,
            "failed_controls": failed_controls,
            "findings_by_control": findings_by_control
        }

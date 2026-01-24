# backend/ai/multi_agent_analyzer.py

"""
Multi-Agent Security Analysis System
Parallel specialist agents for each cloud provider with supervisor coordination
"""

import asyncio
import json
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from openai import OpenAI

from backend.mcp.mcp_base import ScanResult, SecurityFinding, Severity

logger = logging.getLogger("multi_agent_analyzer")


@dataclass
class AgentResponse:
    """Response from a specialist agent"""
    agent_name: str
    provider: str
    analysis: str
    top_risks: List[Dict[str, Any]]
    remediation_steps: List[str]
    confidence_score: float
    execution_time: float


class SpecialistAgent:
    """Base class for cloud provider specialist agents"""
    
    def __init__(self, client: OpenAI, provider: str, model: str = "gpt-4o-mini"):
        self.client = client
        self.provider = provider
        self.model = model
        self.agent_name = f"{provider.upper()}_Specialist"
    
    async def analyze(self, scan_result: ScanResult) -> AgentResponse:
        """Analyze scan results for specific provider"""
        start_time = datetime.now()
        
        # Prepare provider-specific context
        context = self._build_context(scan_result)
        
        # Generate analysis
        analysis = await self._generate_analysis(context)
        
        # Extract structured insights
        top_risks = self._extract_top_risks(scan_result)
        remediation_steps = self._generate_remediation_steps(scan_result)
        confidence = self._calculate_confidence(scan_result)
        
        execution_time = (datetime.now() - start_time).total_seconds()
        
        return AgentResponse(
            agent_name=self.agent_name,
            provider=self.provider,
            analysis=analysis,
            top_risks=top_risks,
            remediation_steps=remediation_steps,
            confidence_score=confidence,
            execution_time=execution_time
        )
    
    def _build_context(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Build provider-specific context"""
        return {
            "provider": self.provider,
            "resources_count": len(scan_result.resources),
            "findings_count": len(scan_result.findings),
            "critical_findings": [
                f for f in scan_result.findings 
                if f.severity == Severity.CRITICAL
            ],
            "high_findings": [
                f for f in scan_result.findings 
                if f.severity == Severity.HIGH
            ],
            "public_resources": [
                r for r in scan_result.resources 
                if r.is_public
            ]
        }
    
    async def _generate_analysis(self, context: Dict[str, Any]) -> str:
        """Generate provider-specific analysis using AI"""
        raise NotImplementedError("Subclasses must implement _generate_analysis")
    
    def _extract_top_risks(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Extract and rank top security risks"""
        risks = []
        
        for finding in scan_result.findings:
            risk_score = self._calculate_risk_score(finding)
            
            risks.append({
                "score": risk_score,
                "severity": finding.severity.value,
                "resource": finding.resource.name,
                "resource_type": finding.resource.resource_type,
                "issue": finding.issue,
                "description": finding.description,
                "is_public": finding.resource.is_public,
                "compliance": finding.compliance
            })
        
        risks.sort(key=lambda x: x["score"], reverse=True)
        return risks[:10]
    
    def _calculate_risk_score(self, finding: SecurityFinding) -> float:
        """Calculate risk score for a finding"""
        severity_weights = {
            Severity.CRITICAL: 10.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 4.0,
            Severity.LOW: 2.0,
            Severity.INFO: 1.0
        }
        
        base_score = severity_weights.get(finding.severity, 1.0)
        
        # Boost for public exposure
        if finding.resource.is_public:
            base_score *= 1.5
        
        # Boost for IAM/access issues
        if any(keyword in finding.issue.lower() 
               for keyword in ["iam", "key", "secret", "credential"]):
            base_score *= 1.3
        
        return base_score
    
    def _generate_remediation_steps(self, scan_result: ScanResult) -> List[str]:
        """Generate prioritized remediation steps"""
        steps = []
        critical_findings = [
            f for f in scan_result.findings 
            if f.severity == Severity.CRITICAL
        ]
        
        for finding in critical_findings[:5]:
            steps.append(f"{finding.issue}: {finding.recommendation}")
        
        return steps
    
    def _calculate_confidence(self, scan_result: ScanResult) -> float:
        """Calculate confidence score based on data completeness"""
        if not scan_result.resources:
            return 0.0
        
        # Higher confidence with more data
        resource_score = min(len(scan_result.resources) / 50, 1.0)
        finding_score = min(len(scan_result.findings) / 20, 1.0)
        
        return (resource_score + finding_score) / 2


class AWSSpecialistAgent(SpecialistAgent):
    """AWS Security Specialist Agent"""
    
    def __init__(self, client: OpenAI, model: str = "gpt-4o-mini"):
        super().__init__(client, "aws", model)
    
    async def _generate_analysis(self, context: Dict[str, Any]) -> str:
        """AWS-specific security analysis"""
        
        prompt = f"""
You are an AWS security specialist with deep expertise in:
- IAM policies and privilege escalation
- S3 bucket security and data exposure
- EC2 security groups and network access
- CloudTrail and GuardDuty monitoring
- AWS compliance frameworks (CIS, NIST)

SCAN RESULTS:
- Resources Scanned: {context['resources_count']}
- Security Findings: {context['findings_count']}
- Critical Issues: {len(context['critical_findings'])}
- High Risk Issues: {len(context['high_findings'])}
- Public Resources: {len(context['public_resources'])}

CRITICAL FINDINGS:
{json.dumps([{
    'resource': f.resource.name,
    'issue': f.issue,
    'description': f.description
} for f in context['critical_findings'][:5]], indent=2)}

Provide AWS-specific analysis:
1. AWS Security Posture Rating (Critical/Poor/Fair/Good/Excellent)
2. Top 3 AWS-specific attack vectors (e.g., IAM privilege escalation, S3 data exfiltration)
3. AWS service misconfigurations requiring immediate attention
4. AWS-native security controls to implement (GuardDuty, Security Hub, etc.)
5. Prioritized AWS remediation actions (next 24-48 hours)

Focus on AWS-specific threats and AWS-native solutions.
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an AWS security expert. Provide specific, actionable AWS security guidance."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                max_tokens=1500
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"AWS specialist analysis failed: {e}")
            return f"AWS analysis error: {e}"


class GCPSpecialistAgent(SpecialistAgent):
    """GCP Security Specialist Agent"""
    
    def __init__(self, client: OpenAI, model: str = "gpt-4o-mini"):
        super().__init__(client, "gcp", model)
    
    async def _generate_analysis(self, context: Dict[str, Any]) -> str:
        """GCP-specific security analysis"""
        
        prompt = f"""
You are a Google Cloud Platform security specialist with expertise in:
- IAM and service account security
- Cloud Storage bucket permissions
- VPC network security and firewall rules
- Security Command Center and Cloud Armor
- GCP compliance (CIS GCP Benchmark)

SCAN RESULTS:
- Resources Scanned: {context['resources_count']}
- Security Findings: {context['findings_count']}
- Critical Issues: {len(context['critical_findings'])}
- High Risk Issues: {len(context['high_findings'])}
- Public Resources: {len(context['public_resources'])}

CRITICAL FINDINGS:
{json.dumps([{
    'resource': f.resource.name,
    'issue': f.issue,
    'description': f.description
} for f in context['critical_findings'][:5]], indent=2)}

Provide GCP-specific analysis:
1. GCP Security Posture Rating
2. Top 3 GCP-specific risks (e.g., overprivileged service accounts, public GCS buckets)
3. GCP Organization Policy violations
4. GCP-native security tools to enable (Security Command Center, VPC Service Controls)
5. Prioritized GCP remediation steps

Focus on GCP-specific threats and GCP-native security controls.
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a GCP security expert. Provide GCP-specific security guidance."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                max_tokens=1500
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"GCP specialist analysis failed: {e}")
            return f"GCP analysis error: {e}"


class OpenAISpecialistAgent(SpecialistAgent):
    """OpenAI API Security Specialist Agent"""
    
    def __init__(self, client: OpenAI, model: str = "gpt-4o-mini"):
        super().__init__(client, "openai", model)
    
    async def _generate_analysis(self, context: Dict[str, Any]) -> str:
        """OpenAI-specific security analysis"""
        
        prompt = f"""
You are an AI/ML API security specialist focusing on:
- API key management and rotation
- Rate limiting and abuse prevention
- Prompt injection and jailbreaking risks
- Data privacy and PII exposure
- Model access governance

SCAN RESULTS:
- Resources Scanned: {context['resources_count']}
- Security Findings: {context['findings_count']}
- Critical Issues: {len(context['critical_findings'])}

CRITICAL FINDINGS:
{json.dumps([{
    'resource': f.resource.name,
    'issue': f.issue,
    'description': f.description
} for f in context['critical_findings'][:5]], indent=2)}

Provide OpenAI API-specific analysis:
1. API Security Posture Rating
2. API key exposure risks and mitigation
3. Rate limiting and quota management recommendations
4. Prompt security concerns (injection, PII leakage)
5. Monitoring and anomaly detection setup

Focus on AI/ML API-specific security concerns.
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are an AI/ML API security expert. Focus on API security best practices."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.2,
                max_tokens=1500
            )
            
            return response.choices[0].message.content.strip()
        
        except Exception as e:
            logger.error(f"OpenAI specialist analysis failed: {e}")
            return f"OpenAI analysis error: {e}"


class SupervisorAgent:
    """Supervisor agent that coordinates specialists and synthesizes results"""
    
    def __init__(self, client: OpenAI, model: str = "gpt-4o-mini"):
        self.client = client
        self.model = model
    
    async def synthesize(self, agent_responses: List[AgentResponse]) -> Dict[str, Any]:
        """Synthesize specialist analyses into unified report"""
        
        logger.info(f"Supervisor synthesizing {len(agent_responses)} specialist reports")
        
        # Build synthesis prompt
        specialist_analyses = {}
        for response in agent_responses:
            specialist_analyses[response.provider] = {
                "analysis": response.analysis,
                "top_risks": response.top_risks[:3],
                "remediation_steps": response.remediation_steps[:3],
                "confidence": response.confidence_score
            }
        
        prompt = f"""
You are a Chief Security Officer synthesizing reports from cloud security specialists.

SPECIALIST REPORTS:
{json.dumps(specialist_analyses, indent=2)}

Provide a unified executive security assessment:

1. OVERALL SECURITY POSTURE
   - Cross-cloud security rating (Critical/Poor/Fair/Good/Excellent)
   - Most critical risks across all environments
   - Common security patterns/weaknesses

2. STRATEGIC PRIORITIES
   - Top 5 actions for maximum risk reduction
   - Quick wins (easy fixes with high impact)
   - Long-term security improvements

3. CROSS-CLOUD CONCERNS
   - Shared vulnerabilities across providers
   - Identity and access management gaps
   - Monitoring and detection blind spots

4. RESOURCE ALLOCATION
   - Where to focus security team effort first
   - Tools and automation to prioritize
   - Training needs

Keep it executive-friendly: clear, actionable, business-focused.
"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a CISO providing strategic security guidance. Be concise and actionable."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                temperature=0.3,
                max_tokens=2000
            )
            
            synthesis = response.choices[0].message.content.strip()
            
            return {
                "unified_analysis": synthesis,
                "specialist_reports": [
                    {
                        "provider": r.provider,
                        "agent": r.agent_name,
                        "confidence": r.confidence_score,
                        "execution_time": r.execution_time,
                        "top_risks_count": len(r.top_risks)
                    }
                    for r in agent_responses
                ],
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Supervisor synthesis failed: {e}")
            return {
                "error": str(e),
                "specialist_reports": specialist_analyses
            }


class MultiAgentSecurityAnalyzer:
    """
    Main orchestrator for multi-agent security analysis
    Runs specialist agents in parallel and synthesizes results
    """
    
    def __init__(self, api_key: str):
        self.client = OpenAI(api_key=api_key)
        
        # Initialize specialist agents
        self.agents = {
            "aws": AWSSpecialistAgent(self.client),
            "gcp": GCPSpecialistAgent(self.client),
            "openai": OpenAISpecialistAgent(self.client)
        }
        
        # Initialize supervisor
        self.supervisor = SupervisorAgent(self.client)
    
    async def analyze(self, scan_results: List[ScanResult]) -> Dict[str, Any]:
        """
        Run parallel multi-agent analysis
        
        Returns:
            Comprehensive analysis with specialist insights and unified synthesis
        """
        logger.info(f"🤖 Starting multi-agent analysis for {len(scan_results)} providers")
        start_time = datetime.now()
        
        # Create analysis tasks for each provider
        tasks = []
        for scan_result in scan_results:
            provider = scan_result.provider.lower()
            if provider in self.agents:
                agent = self.agents[provider]
                task = agent.analyze(scan_result)
                tasks.append(task)
            else:
                logger.warning(f"No specialist agent for provider: {provider}")
        
        # Run agents in parallel
        agent_responses = await asyncio.gather(*tasks, return_exceptions=True)
        
        # Filter out exceptions
        valid_responses = [
            r for r in agent_responses 
            if isinstance(r, AgentResponse)
        ]
        
        if not valid_responses:
            return {
                "error": "All specialist agents failed",
                "scan_results": scan_results
            }
        
        # Supervisor synthesizes specialist reports
        synthesis = await self.supervisor.synthesize(valid_responses)
        
        total_time = (datetime.now() - start_time).total_seconds()
        
        return {
            "architecture": "multi-agent",
            "total_execution_time": total_time,
            "agents_run": len(valid_responses),
            "specialist_analyses": {
                r.provider: {
                    "agent": r.agent_name,
                    "analysis": r.analysis,
                    "top_risks": r.top_risks,
                    "remediation_steps": r.remediation_steps,
                    "confidence": r.confidence_score,
                    "execution_time": r.execution_time
                }
                for r in valid_responses
            },
            "unified_synthesis": synthesis,
            "performance_metrics": {
                "total_time": total_time,
                "parallel_speedup": f"{len(valid_responses)}x",
                "avg_agent_time": sum(r.execution_time for r in valid_responses) / len(valid_responses)
            }
        }
    
    def get_agent_status(self) -> Dict[str, Any]:
        """Get status of all agents"""
        return {
            "available_agents": list(self.agents.keys()),
            "agent_details": {
                provider: {
                    "name": agent.agent_name,
                    "provider": agent.provider,
                    "model": agent.model
                }
                for provider, agent in self.agents.items()
            }
        }


# Global singleton
multi_agent_analyzer = None


def get_multi_agent_analyzer(api_key: str) -> MultiAgentSecurityAnalyzer:
    """Get or create singleton analyzer instance"""
    global multi_agent_analyzer
    if multi_agent_analyzer is None:
        multi_agent_analyzer = MultiAgentSecurityAnalyzer(api_key)
    return multi_agent_analyzer


# Example usage
if __name__ == "__main__":
    import os
    
    async def test_multi_agent():
        analyzer = MultiAgentSecurityAnalyzer(api_key=os.getenv("OPENAI_API_KEY"))
        
        # Mock scan results
        from backend.mcp.mcp_base import CloudResource
        
        mock_scan = ScanResult(
            provider="aws",
            account_id="123456789",
            resources=[
                CloudResource(
                    provider="aws",
                    resource_type="s3_bucket",
                    name="my-public-bucket",
                    region="us-east-1",
                    config={},
                    is_public=True
                )
            ],
            findings=[
                SecurityFinding(
                    resource=CloudResource(
                        provider="aws",
                        resource_type="s3_bucket",
                        name="my-public-bucket",
                        region="us-east-1",
                        config={},
                        is_public=True
                    ),
                    severity=Severity.CRITICAL,
                    issue="Public S3 Bucket",
                    description="Bucket is publicly accessible",
                    recommendation="Enable Block Public Access"
                )
            ]
        )
        
        result = await analyzer.analyze([mock_scan])
        print(json.dumps(result, indent=2, default=str))
    
    # asyncio.run(test_multi_agent())
    print("✅ Multi-Agent Security Analyzer loaded")
"""
OpenAI MCP Plugin - API Security Scanner
Implements: discover_resources, check_config, assess_vulnerabilities
"""

import logging
from typing import Dict, List, Any
from openai import OpenAI
from mcp_base import MCPPlugin, CloudResource, SecurityFinding, Severity

logger = logging.getLogger("openai_mcp_plugin")


class OpenAIPlugin(MCPPlugin):
    """OpenAI Security Scanner - API security checks"""

    def __init__(self, credentials: Dict[str, str]):
        super().__init__(credentials)
        self.client = OpenAI(api_key=credentials.get('api_key'))
        self.org_id = credentials.get('org_id')

    def _get_provider_name(self) -> str:
        return "openai"

    async def discover_resources(self, account_id: str) -> List[CloudResource]:
        """Tool 1: Discover OpenAI API resources"""
        logger.info(f"OpenAI: Discovering resources for account {account_id}")
        resources = []

        # Discover available models
        resources.extend(await self._discover_models())
        
        # Discover API keys (metadata only - actual keys not accessible)
        resources.extend(await self._discover_api_keys())
        
        # Discover usage patterns
        resources.extend(await self._discover_usage())

        logger.info(f"OpenAI: Discovered {len(resources)} resources")
        return resources

    async def _discover_models(self) -> List[CloudResource]:
        """Discover available OpenAI models"""
        resources = []
        try:
            models_response = self.client.models.list()
            models = [model.id for model in models_response.data]
            
            # Group models by capability
            gpt4_models = [m for m in models if 'gpt-4' in m]
            gpt3_models = [m for m in models if 'gpt-3' in m]
            embedding_models = [m for m in models if 'embedding' in m]
            
            resources.append(CloudResource(
                provider="openai",
                resource_type="model_access",
                name="available_models",
                config={
                    "gpt4_models": gpt4_models,
                    "gpt3_models": gpt3_models,
                    "embedding_models": embedding_models,
                    "total_models": len(models)
                }
            ))
        except Exception as e:
            logger.error(f"Model discovery failed: {e}")
        
        return resources

    async def _discover_api_keys(self) -> List[CloudResource]:
        """Discover API key metadata (not actual keys)"""
        resources = []
        
        # Note: OpenAI API doesn't provide key enumeration
        # This would require organization-level access
        # For now, we track the current key being used
        
        resources.append(CloudResource(
            provider="openai",
            resource_type="api_key",
            name="current_api_key",
            config={
                "key_prefix": "sk-...",  # Never log full keys
                "organization": self.org_id,
                "last_rotation": None,  # Would need to track externally
                "permissions": "full_access"  # OpenAI keys have full access by default
            }
        ))
        
        return resources

    async def _discover_usage(self) -> List[CloudResource]:
        """Discover API usage patterns"""
        resources = []
        
        # In production, you would fetch usage data from OpenAI dashboard or usage API
        # For now, we create a placeholder resource
        
        resources.append(CloudResource(
            provider="openai",
            resource_type="api_usage",
            name="usage_metrics",
            config={
                "tracking": "enabled",
                "rate_limits": "default",
                "usage_alerts": False
            }
        ))
        
        return resources

    async def check_config(self, resources: List[CloudResource]) -> List[Dict[str, Any]]:
        """Tool 2: Check resource configurations"""
        config_issues = []
        
        for resource in resources:
            if resource.resource_type == "api_key":
                if not resource.config.get("last_rotation"):
                    config_issues.append({
                        "resource": resource.name,
                        "issue": "API key rotation not tracked",
                        "type": "openai_key_rotation"
                    })
            
            if resource.resource_type == "api_usage":
                if not resource.config.get("usage_alerts"):
                    config_issues.append({
                        "resource": resource.name,
                        "issue": "No usage alerts configured",
                        "type": "openai_monitoring"
                    })
        
        return config_issues

    async def assess_vulnerabilities(self, resources: List[CloudResource]) -> List[SecurityFinding]:
        """Tool 3: Assess security vulnerabilities"""
        findings = []
        
        for resource in resources:
            # API Key Security Checks
            if resource.resource_type == "api_key":
                findings.extend(self._check_api_key_vulnerabilities(resource))
            
            # Model Access Checks
            elif resource.resource_type == "model_access":
                findings.extend(self._check_model_vulnerabilities(resource))
            
            # Usage Monitoring Checks
            elif resource.resource_type == "api_usage":
                findings.extend(self._check_usage_vulnerabilities(resource))
        
        logger.info(f"OpenAI: Found {len(findings)} security findings")
        return findings

    def _check_api_key_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """API key security checks"""
        findings = []
        
        # Key rotation
        last_rotation = resource.config.get("last_rotation")
        if not last_rotation:
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.HIGH,
                issue="OpenAI API Key Not Rotated",
                description="API key rotation schedule not established",
                recommendation="Rotate API keys every 90 days and track rotation dates",
                compliance=["OWASP-API-2"]
            ))
        
        # Full access permissions
        if resource.config.get("permissions") == "full_access":
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.MEDIUM,
                issue="OpenAI API Key Full Access",
                description="API key has unrestricted access to all OpenAI endpoints",
                recommendation="Consider using project-scoped keys when available, implement application-level controls",
                compliance=["OWASP-API-1"]
            ))
        
        # Potential exposure check (this would need code scanning)
        findings.append(SecurityFinding(
            resource=resource,
            severity=Severity.HIGH,
            issue="Potential API Key Exposure Risk",
            description="API keys may be stored in code repositories or environment files",
            recommendation="Use secrets management (AWS Secrets Manager, HashiCorp Vault), scan repos with tools like TruffleHog",
            compliance=["OWASP-API-2", "CWE-798"]
        ))
        
        return findings

    def _check_model_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """Model access security checks"""
        findings = []
        
        gpt4_models = resource.config.get("gpt4_models", [])
        
        # GPT-4 access without governance
        if gpt4_models:
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.MEDIUM,
                issue="GPT-4 Access Without Guardrails",
                description=f"Organization has access to {len(gpt4_models)} GPT-4 models without documented governance",
                recommendation="Implement content filtering, prompt injection protection, and usage policies for powerful models",
                compliance=["OWASP-LLM-01", "OWASP-LLM-02"]
            ))
        
        # Model enumeration exposure
        findings.append(SecurityFinding(
            resource=resource,
            severity=Severity.LOW,
            issue="Model Capabilities Disclosure",
            description="API exposes available models which could aid attackers in crafting attacks",
            recommendation="Document which models are used in production, implement rate limiting",
            compliance=["OWASP-API-8"]
        ))
        
        return findings

    def _check_usage_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """Usage monitoring security checks"""
        findings = []
        
        # No usage alerts
        if not resource.config.get("usage_alerts"):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.MEDIUM,
                issue="OpenAI Usage Alerts Disabled",
                description="No monitoring or alerting configured for unusual API usage patterns",
                recommendation="Set up usage alerts for cost anomalies and potential API abuse",
                compliance=["NIST-800-53-SI-4"]
            ))
        
        # No rate limiting beyond defaults
        if resource.config.get("rate_limits") == "default":
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.LOW,
                issue="Default Rate Limits",
                description="Using OpenAI default rate limits without custom throttling",
                recommendation="Implement application-level rate limiting to prevent abuse and control costs",
                compliance=["OWASP-API-4"]
            ))
        
        # Logging concerns
        findings.append(SecurityFinding(
            resource=resource,
            severity=Severity.MEDIUM,
            issue="API Request Logging Not Configured",
            description="No evidence of comprehensive API request/response logging",
            recommendation="Log all API calls (without logging sensitive data) for audit and security analysis",
            compliance=["NIST-800-53-AU-2"]
        ))
        
        return findings


# Additional helper function for code scanning (would integrate with repo scanner)
def scan_code_for_api_keys(repo_path: str) -> List[Dict[str, Any]]:
    """
    Scan code repositories for exposed API keys
    In production, integrate with tools like:
    - TruffleHog
    - git-secrets
    - GitHub Secret Scanning
    """
    findings = []
    
    # Patterns to look for
    patterns = [
        r'sk-[a-zA-Z0-9]{48}',  # OpenAI API key pattern
        r'OPENAI_API_KEY\s*=\s*["\']sk-',
        r'openai\.api_key\s*=\s*["\']sk-'
    ]
    
    # This would scan files in repo_path
    # For now, return structure
    logger.info(f"Would scan {repo_path} for API key exposure")
    
    return findings

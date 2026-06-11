"""
MCP Base Interface - Universal Cloud Security Scanner Protocol
Every cloud provider plugin implements these 3 tools:
1. discover_resources - Find all cloud assets
2. check_config - Analyze configurations
3. assess_vulnerabilities - Security risk assessment
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any
from dataclasses import dataclass
from enum import Enum
from backend.mcp_servers.base_server import MCPMessage,mcp_server_manager
import logging

logger = logging.getLogger("mcp_base")

class Severity(Enum):
    """Risk severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class CloudResource:
    """Unified cloud resource representation"""
    provider: str  # aws, gcp, azure, openai
    resource_type: str  # s3_bucket, iam_user, gcs_bucket, etc.
    name: str
    region: str = "global"
    config: Dict[str, Any] = None
    is_public: bool = False
    tags: Dict[str, str] = None

    def __post_init__(self):
        if self.config is None:
            self.config = {}
        if self.tags is None:
            self.tags = {}


@dataclass
class SecurityFinding:
    """Unified security finding"""
    resource: CloudResource
    severity: Severity
    issue: str
    description: str
    recommendation: str
    cve_id: str = None
    compliance: List[str] = None
    detection_tool: str = None  # NEW: Track which tool detected this
    tool_category: str = None   # NEW: 'config_scan', 'vuln_scan', 'secret_scan', etc.

    def __post_init__(self):
        if self.compliance is None:
            self.compliance = []
        # Auto-detect tool from issue if not explicitly set
        if not self.detection_tool:
            self.detection_tool = self._extract_tool_from_issue()
    
    def _extract_tool_from_issue(self) -> str:
        """Extract tool name from issue string like [TRIVY] or [AWS-PLUGIN]"""
        import re
        match = re.search(r'\[([A-Z0-9_\-]+)\]', self.issue)
        if match:
            return match.group(1)
        return "UNKNOWN"

@dataclass
class ScanResult:
    """Complete scan result from a provider"""
    provider: str
    account_id: str
    resources: List[CloudResource]
    findings: List[SecurityFinding]
    scan_duration: float = 0.0
    errors: List[str] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []


class MCPPlugin(ABC):
    """
    Abstract base class for all MCP cloud provider plugins.
    Every plugin (AWS, GCP, Azure, OpenAI) must implement these 3 tools.
    """

    def __init__(self, credentials: Dict[str, str]):
        """
        Initialize plugin with provider credentials
        Args:
            credentials: Dict containing API keys, tokens, etc.
        """
        self.credentials = credentials
        self.provider_name = self._get_provider_name()

    @abstractmethod
    def _get_provider_name(self) -> str:
        """Return provider name (aws, gcp, azure, openai)"""
        pass

    @abstractmethod
    async def discover_resources(self, account_id: str) -> List[CloudResource]:
        """
        Tool 1: Discover all cloud resources
        
        Returns:
            List of CloudResource objects representing all assets
        """
        pass

    @abstractmethod
    async def check_config(self, resources: List[CloudResource]) -> List[Dict[str, Any]]:
        """
        Tool 2: Check resource configurations
        
        Args:
            resources: List of discovered resources
            
        Returns:
            List of configuration issues found
        """
        pass

    @abstractmethod
    async def assess_vulnerabilities(self, resources: List[CloudResource]) -> List[SecurityFinding]:
        """
        Tool 3: Assess security vulnerabilities
        
        Args:
            resources: List of discovered resources
            
        Returns:
            List of SecurityFinding objects with risks and recommendations
        """
        pass

    async def full_scan(self, account_id: str) -> ScanResult:
        """
        Execute complete security scan (all 3 tools)
        This is the main entry point used by FastAPI
        """
        import time
        start_time = time.time()
        errors = []
    
    # FIX: Ensure account_id is never None
        if not account_id or account_id == "None":
            account_id = "default"
            logger.warning(f"No account_id provided for {self.provider_name}, using 'default'")

        try:
        # Tool 1: Discover
            resources = await self.discover_resources(account_id)
        
        # Tool 2: Check Config (optional, can be used for detailed analysis)
            config_issues = await self.check_config(resources)
        
        # Tool 3: Assess Vulnerabilities
            findings = await self.assess_vulnerabilities(resources)
        
            scan_duration = time.time() - start_time
        
            return ScanResult(
                provider=self.provider_name,
                account_id=account_id,  # Now guaranteed to be non-None
                resources=resources,
                findings=findings,
                scan_duration=scan_duration,
                errors=errors
            )
        
        except Exception as e:
            errors.append(f"Scan failed: {str(e)}")
            return ScanResult(
                provider=self.provider_name,
                account_id=account_id,  # Now guaranteed to be non-None
                resources=[],
                findings=[],
                scan_duration=time.time() - start_time,
                errors=errors
            )


class MCPRegistry:
    """
    Registry for all MCP plugins
    FastAPI uses this to route scan requests to the correct plugin
    """
    
    def __init__(self):
        self._plugins: Dict[str, Any] = {}
    
    def register(self, provider: str, plugin: MCPPlugin):
        """Register a cloud provider plugin"""
        self._plugins[provider.lower()] = plugin

    def unregister(self, provider: str) -> None:
        """Remove a provider from the registry if present."""
        self._plugins.pop(provider.lower(), None)
    
    def get_plugin(self, provider: str) -> MCPPlugin:
        """Get plugin for a specific provider"""
        plugin = self._plugins.get(provider.lower())
        if not plugin:
            raise ValueError(f"No plugin registered for provider: {provider}")
        return plugin
    
    def list_providers(self) -> List[str]:
        """List all registered providers"""
        return list(self._plugins.keys())
    
    

    async def scan(
        self,
        provider: str,
        account_id: str,
        options: dict | None = None,
    ):
        """
        Dispatch scan to MCP server via MCPServerManager
        """
        options = options or {}

        tool_name = f"{provider}/full_scan"

        message = MCPMessage(
            method="tools/call",
            params={
                "name": tool_name,
                "arguments": {
                    "account_id": account_id,
                    **options,
                },
            },
        )

    
        response = await mcp_server_manager.send_request(provider, message)

        if response.error:
            raise RuntimeError(response.error)

        return response.result



# Global registry instance
mcp_registry = MCPRegistry()

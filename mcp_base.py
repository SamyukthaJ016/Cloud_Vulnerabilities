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
    compliance: List[str] = None  # ["CIS-1.2", "NIST-800-53"]

    def __post_init__(self):
        if self.compliance is None:
            self.compliance = []


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
                account_id=account_id,
                resources=resources,
                findings=findings,
                scan_duration=scan_duration,
                errors=errors
            )
            
        except Exception as e:
            errors.append(f"Scan failed: {str(e)}")
            return ScanResult(
                provider=self.provider_name,
                account_id=account_id,
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
        self._plugins: Dict[str, MCPPlugin] = {}
    
    def register(self, provider: str, plugin: MCPPlugin):
        """Register a cloud provider plugin"""
        self._plugins[provider.lower()] = plugin
    
    def get_plugin(self, provider: str) -> MCPPlugin:
        """Get plugin for a specific provider"""
        plugin = self._plugins.get(provider.lower())
        if not plugin:
            raise ValueError(f"No plugin registered for provider: {provider}")
        return plugin
    
    def list_providers(self) -> List[str]:
        """List all registered providers"""
        return list(self._plugins.keys())
    
    async def scan(self, provider: str, account_id: str) -> ScanResult:
        """Execute scan using the appropriate plugin"""
        plugin = self.get_plugin(provider)
        return await plugin.full_scan(account_id)


# Global registry instance
mcp_registry = MCPRegistry()

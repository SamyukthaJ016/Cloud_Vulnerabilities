# backend/mcp_scanner.py - UPDATED VERSION
"""
MCP Server-Based Security Scanner
Replaces old plugin system with full MCP protocol implementation
Now includes CloudFox offensive scan integration
"""

import os
import logging
from typing import Dict, List, Any, Optional
from datetime import datetime

from backend.mcp_servers.base_server import (
    mcp_server_manager,
    MCPMessage,
    MCPResponse
)
from backend.mcp_servers.aws_server import create_aws_server
from backend.mcp_servers.gcp_server import create_gcp_server
from backend.mcp_servers.kubernetes_server import create_kubernetes_server
from backend.cloudfox.cloudfox_server import create_cloudfox_server
from backend.credentials.manager import credential_manager

logger = logging.getLogger("mcp_scanner")


class MCPSecurityScanner:
    """
    Unified security scanner using MCP server architecture
    Orchestrates scanning across multiple cloud providers
    """
    
    def __init__(self):
        self.server_manager = mcp_server_manager
        self.initialized_servers = set()
    
    async def initialize_provider_servers(self, user_id: str, providers: List[str]) -> Dict[str, Any]:
        """
        Initialize MCP servers for requested providers with user credentials
        
        Returns:
            Dict with initialized servers and credential mapping
        """
        logger.info(f"🔧 Initializing MCP servers for user={user_id}, providers={providers}")
        
        results = {
            "initialized": [],
            "failed": [],
            "credential_mapping": {}
        }
        
        for provider in providers:
            try:
                # Get user's default credential for this provider
                credential = credential_manager.get_default_credential(user_id, provider)
                
                if not credential:
                    logger.warning(f"⚠️ No credential found for {provider}")
                    results["failed"].append({
                        "provider": provider,
                        "reason": "No credentials available"
                    })
                    continue
                
                # Check if server already exists
                existing_server = self.server_manager.get_server(provider)
                if existing_server and existing_server.running:
                    logger.info(f"♻️ Reusing existing {provider} server")
                    results["initialized"].append(provider)
                    results["credential_mapping"][provider] = credential.id
                    continue
                
                # Initialize new server based on provider
                server = None
                
                if provider == "aws":
                    server = create_aws_server({
                        "access_key_id": credential.aws_access_key_id,
                        "secret_access_key": credential.aws_secret_access_key,
                        "session_token": credential.aws_session_token,
                        "region": credential.aws_region or "us-east-1"
                    })
                    results["credential_mapping"]["aws"] = credential.id
                
                elif provider == "gcp":
                    server = create_gcp_server({
                        "service_account_json": credential.gcp_service_account_json,
                        "project_id": credential.gcp_project_id
                    })
                    results["credential_mapping"]["gcp"] = credential.id

                elif provider == "kubernetes":
                    server = create_kubernetes_server({
                        "kubeconfig": credential.kubernetes_kubeconfig,
                        "context": credential.kubernetes_context,
                        "cluster_name": credential.kubernetes_cluster_name,
                    })
                    results["credential_mapping"]["kubernetes"] = credential.id
                
                elif provider == "cloudfox":
                    # CloudFox uses AWS credentials
                    aws_cred = credential_manager.get_default_credential(user_id, "aws")
                    if aws_cred:
                        server = create_cloudfox_server({
                            "profile": os.getenv("AWS_PROFILE", "default"),
                            "access_key_id": aws_cred.aws_access_key_id,
                            "secret_access_key": aws_cred.aws_secret_access_key,
                            "session_token": aws_cred.aws_session_token,
                            "region": aws_cred.aws_region or "us-east-1"
                        })
                        results["credential_mapping"]["cloudfox"] = "aws-credential"
                    else:
                        results["failed"].append({
                            "provider": "cloudfox",
                            "reason": "CloudFox requires AWS credentials"
                        })
                        continue
                
                if server:
                    # Register and start server
                    self.server_manager.register_server(server)
                    await server.start()
                    
                    self.initialized_servers.add(provider)
                    results["initialized"].append(provider)
                    logger.info(f"✅ {provider.upper()} MCP server initialized")
                else:
                    results["failed"].append({
                        "provider": provider,
                        "reason": "Provider not supported"
                    })
            
            except Exception as e:
                logger.error(f"❌ Failed to initialize {provider} server: {e}")
                results["failed"].append({
                    "provider": provider,
                    "reason": str(e)
                })
        
        return results
    
    async def scan_provider(
        self,
        provider: str,
        account_id: str = "default",
        deep_scan: bool = False,
        offensive_scan: bool = True  # NEW: Enable CloudFox by default
    ) -> Dict[str, Any]:
        """
        Scan a single provider using its MCP server
        
        Args:
            provider: Cloud provider name (aws, gcp, etc.)
            account_id: Account/project identifier
            deep_scan: Enable deep vulnerability scanning
            offensive_scan: Enable CloudFox offensive scanning (AWS only)
        
        Returns:
            Scan results including resources, findings, and metadata
        """
        logger.info(f"🔍 Scanning {provider} (account={account_id}, deep={deep_scan}, offensive={offensive_scan})")
        
        # Check if server is initialized
        server = self.server_manager.get_server(provider)
        if not server:
            raise RuntimeError(f"MCP server not initialized for {provider}")
        
        # Prepare arguments for the scan
        arguments = {
            "account_id": account_id,
            "deep_scan": deep_scan
        }
        
        # Add offensive_scan parameter for AWS
        if provider == "aws":
            arguments["offensive_scan"] = offensive_scan
        
        # Call full_scan tool via MCP protocol
        message = MCPMessage(
            method="tools/call",
            params={
                "name": f"{provider}/full_scan",
                "arguments": arguments
            }
        )
        
        response = await self.server_manager.send_request(provider, message)
        
        if response.error:
            raise RuntimeError(f"Scan failed: {response.error}")
        
        scan_result = response.result
        
        # Add metadata
        scan_result["provider"] = provider
        scan_result["scan_timestamp"] = datetime.utcnow().isoformat()
        scan_result["deep_scan_enabled"] = deep_scan
        scan_result["offensive_scan_enabled"] = offensive_scan if provider == "aws" else False
        
        return scan_result
    
    async def scan_multi_cloud(
        self,
        user_id: str,
        providers: List[str],
        account_ids: Dict[str, str] = None,
        deep_scan: bool = False,
        offensive_scan: bool = True  # NEW PARAMETER
    ) -> Dict[str, Any]:
        """
        Orchestrate multi-cloud security scan using MCP servers
        
        Args:
            user_id: User identifier
            providers: List of cloud providers to scan
            account_ids: Optional account IDs per provider
            deep_scan: Enable deep vulnerability scanning
            offensive_scan: Enable CloudFox offensive scanning for AWS
        
        Returns:
            Aggregated scan results across all providers
        """
        logger.info(f"🌐 Multi-cloud scan: user={user_id}, providers={providers}, offensive={offensive_scan}")
        
        # Initialize MCP servers with user credentials
        init_results = await self.initialize_provider_servers(user_id, providers)
        
        if not init_results["initialized"]:
            raise RuntimeError("No providers could be initialized")
        
        # Scan each provider
        scan_results = {
            "scan_id": f"multicloud-{datetime.utcnow().timestamp()}",
            "timestamp": datetime.utcnow().isoformat(),
            "user_id": user_id,
            "providers_scanned": [],
            "providers_failed": init_results["failed"],
            "credential_mapping": init_results["credential_mapping"],
            "results": {},
            "summary": {
                "total_resources": 0,
                "total_findings": 0,
                "aws_findings": 0,
                "cloudfox_findings": 0,
                "by_severity": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0
                }
            }
        }
        
        for provider in init_results["initialized"]:
            try:
                account_id = (account_ids or {}).get(provider, "default")
                
                # For AWS, pass offensive_scan parameter
                if provider == "aws":
                    result = await self.scan_provider(
                        provider=provider,
                        account_id=account_id,
                        deep_scan=deep_scan,
                        offensive_scan=offensive_scan
                    )
                else:
                    # For other providers, just pass deep_scan
                    result = await self.scan_provider(
                        provider=provider,
                        account_id=account_id,
                        deep_scan=deep_scan,
                        offensive_scan=False  # CloudFox only works with AWS
                    )
                
                scan_results["results"][provider] = result
                scan_results["providers_scanned"].append(provider)
                
                # Aggregate summary
                if "summary" in result:
                    summary = result["summary"]
                    scan_results["summary"]["total_resources"] += summary.get("total_resources", 0)
                    scan_results["summary"]["total_findings"] += summary.get("total_findings", 0)
                    
                    # Track CloudFox findings separately
                    if provider == "aws":
                        scan_results["summary"]["aws_findings"] += summary.get("aws_findings", 0)
                        scan_results["summary"]["cloudfox_findings"] += summary.get("cloudfox_findings", 0)
                    
                    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
                        scan_results["summary"]["by_severity"][severity] += summary.get(severity, 0)
            
            except Exception as e:
                logger.error(f"❌ Failed to scan {provider}: {e}")
                scan_results["providers_failed"].append({
                    "provider": provider,
                    "reason": str(e)
                })
        
        return scan_results
    
    async def run_offensive_scan(
        self,
        user_id: str,
        profile: Optional[str] = None,
        region: str = "us-east-1"
    ) -> Dict[str, Any]:
        """
        Run CloudFox offensive security scan via MCP server
        
        Args:
            user_id: User identifier
            profile: AWS CLI profile name
            region: AWS region
        
        Returns:
            CloudFox scan results with attack paths and vulnerabilities
        """
        profile = profile or os.getenv("AWS_PROFILE", "default")
        logger.info(f"⚔️ Offensive scan: user={user_id}, profile={profile}")
        
        # Initialize CloudFox server
        init_results = await self.initialize_provider_servers(user_id, ["cloudfox"])
        
        if "cloudfox" not in init_results["initialized"]:
            raise RuntimeError("CloudFox server initialization failed")
        
        # Run offensive scan
        message = MCPMessage(
            method="tools/call",
            params={
                "name": "cloudfox/offensive_scan",
                "arguments": {
                    "profile": profile,
                    "region": region
                }
            }
        )
        
        response = await self.server_manager.send_request("cloudfox", message)
        
        if response.error:
            raise RuntimeError(f"Offensive scan failed: {response.error}")
        
        return response.result
    
    async def discover_resources(
        self,
        provider: str,
        resource_type: str = None
    ) -> Dict[str, Any]:
        """
        Discover resources using MCP server
        
        Args:
            provider: Cloud provider
            resource_type: Optional specific resource type to discover
        
        Returns:
            Discovered resources
        """
        server = self.server_manager.get_server(provider)
        if not server:
            raise RuntimeError(f"MCP server not initialized for {provider}")
        
        # List available discovery tools
        tools_message = MCPMessage(method="tools/list")
        tools_response = await self.server_manager.send_request(provider, tools_message)
        
        if tools_response.error:
            raise RuntimeError(f"Failed to list tools: {tools_response.error}")
        
        # Find appropriate discovery tool
        tools = tools_response.result.get("tools", [])
        discovery_tools = [
            t for t in tools 
            if "discover" in t.get("name", "").lower()
        ]
        
        if not discovery_tools:
            raise RuntimeError(f"No discovery tools available for {provider}")
        
        # Use first discovery tool
        tool_name = discovery_tools[0]["name"]
        
        message = MCPMessage(
            method="tools/call",
            params={
                "name": tool_name,
                "arguments": {}
            }
        )
        
        response = await self.server_manager.send_request(provider, message)
        
        if response.error:
            raise RuntimeError(f"Discovery failed: {response.error}")
        
        return response.result
    
    async def cleanup(self):
        """Stop all MCP servers"""
        logger.info("🧹 Cleaning up MCP servers")
        await self.server_manager.stop_all()
        self.initialized_servers.clear()


# Singleton instance
mcp_scanner = MCPSecurityScanner()

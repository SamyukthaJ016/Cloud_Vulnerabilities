# backend/mcp_servers/cloudfox_server.py

"""
CloudFox MCP Server - Offensive Security Scanner
Implements MCP protocol for AWS penetration testing using CloudFox
"""

import json
import logging
import asyncio
import subprocess
import tempfile
from typing import Dict, List, Any, Optional
from datetime import datetime
from pathlib import Path

from backend.mcp_servers.base_server import (
    BaseMCPServer,
    MCPTool,
    MCPResource,
    ToolCategory
)

logger = logging.getLogger("cloudfox_mcp_server")


class CloudFoxMCPServer(BaseMCPServer):
    """CloudFox MCP Server - provides offensive security scanning tools for AWS"""
    
    def __init__(self, config: Dict[str, Any]):
        self.cloudfox_path = None
        self.aws_profile = config.get('profile', 'default')
        self.aws_region = config.get('region', 'us-east-1')
        
        super().__init__("cloudfox", config)
        
        # Find CloudFox executable
        self._find_cloudfox()
    
    def _find_cloudfox(self) -> None:
        """Find CloudFox executable"""
        locations = [
            "cloudfox",  # In PATH
            "/usr/local/bin/cloudfox",
            "/root/go/bin/cloudfox",
            str(Path.home() / "go/bin/cloudfox"),
        ]
        
        for location in locations:
            try:
                result = subprocess.run(
                    [location, "--version"],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                if result.returncode == 0:
                    self.cloudfox_path = location
                    logger.info(f"✅ CloudFox found at: {location}")
                    logger.info(f"   Version: {result.stdout.strip()}")
                    return
            except (FileNotFoundError, subprocess.TimeoutExpired, Exception) as e:
                continue
        
        logger.warning("⚠️ CloudFox not found. Install: go install github.com/BishopFox/cloudfox@latest")
    
    def _setup_tools(self) -> None:
        """Setup CloudFox security scanning tools"""
        
        # Tool 1: Secrets Discovery
        self.register_tool(MCPTool(
            name="cloudfox/discover_secrets",
            description="Discover exposed secrets in EC2 userdata, Lambda env vars, and Task definitions",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "profile": {
                        "type": "string",
                        "description": "AWS profile name",
                        "default": "default"
                    },
                    "region": {
                        "type": "string",
                        "description": "AWS region",
                        "default": "us-east-1"
                    }
                }
            },
            handler=self._discover_secrets
        ))
        
        # Tool 2: Attack Path Enumeration
        self.register_tool(MCPTool(
            name="cloudfox/enumerate_attack_paths",
            description="Enumerate privilege escalation paths and attack vectors",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "profile": {"type": "string", "default": "default"},
                    "region": {"type": "string", "default": "us-east-1"}
                }
            },
            handler=self._enumerate_attack_paths
        ))
        
        # Tool 3: IAM Principals Analysis
        self.register_tool(MCPTool(
            name="cloudfox/analyze_iam_principals",
            description="Find principals with admin or overprivileged permissions",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {
                    "profile": {"type": "string", "default": "default"}
                }
            },
            handler=self._analyze_iam_principals
        ))
        
        # Tool 4: Endpoint Exposure Check
        self.register_tool(MCPTool(
            name="cloudfox/check_endpoints",
            description="Discover publicly exposed endpoints and services",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "profile": {"type": "string", "default": "default"}
                }
            },
            handler=self._check_endpoints
        ))
        
        # Tool 5: Role Trust Analysis
        self.register_tool(MCPTool(
            name="cloudfox/analyze_role_trusts",
            description="Analyze IAM role trust relationships for privilege escalation",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "profile": {"type": "string", "default": "default"}
                }
            },
            handler=self._analyze_role_trusts
        ))
        
        # Tool 6: Full Offensive Scan
        self.register_tool(MCPTool(
            name="cloudfox/offensive_scan",
            description="Run comprehensive offensive security assessment",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "profile": {"type": "string", "default": "default"},
                    "region": {"type": "string", "default": "us-east-1"},
                    "modules": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "Specific modules to run (empty = all)"
                    }
                }
            },
            handler=self._offensive_scan
        ))
    
    def _setup_resources(self) -> None:
        """Setup CloudFox resources"""
        
        self.register_resource(MCPResource(
            uri="cloudfox://status",
            name="CloudFox Status",
            description="CloudFox availability and version information",
            mime_type="application/json"
        ))
        
        self.register_resource(MCPResource(
            uri="cloudfox://capabilities",
            name="CloudFox Capabilities",
            description="Available CloudFox scanning modules",
            mime_type="application/json"
        ))
    
    async def _fetch_resource_content(self, uri: str) -> str:
        """Fetch content for CloudFox resources"""
        
        if uri == "cloudfox://status":
            return json.dumps({
                "available": self.cloudfox_path is not None,
                "path": self.cloudfox_path,
                "profile": self.aws_profile,
                "region": self.aws_region
            }, indent=2)
        
        elif uri == "cloudfox://capabilities":
            return json.dumps({
                "modules": [
                    "secrets",
                    "principals",
                    "endpoints",
                    "role-trusts",
                    "env-vars",
                    "access-keys",
                    "inventory",
                    "workloads",
                    "permissions",
                    "buckets"
                ]
            }, indent=2)
        
        else:
            raise ValueError(f"Unknown resource URI: {uri}")
    
    # Tool Handlers
    
    async def _run_cloudfox_command(
        self,
        command: str,
        profile: str = "default",
        region: str = "us-east-1",
        extra_args: List[str] = None
    ) -> Dict[str, Any]:
        """Run a CloudFox command and return parsed results"""
        
        if not self.cloudfox_path:
            return {
                "error": "CloudFox not available",
                "install_guide": "Install: go install github.com/BishopFox/cloudfox@latest"
            }
        
        # Create temporary output directory
        with tempfile.TemporaryDirectory() as temp_dir:
            cmd = [
                self.cloudfox_path,
                "aws",
                "--profile", profile,
                "--region", region,
                "--output", "json",
                "--output-dir", temp_dir,
                command
            ]
            
            if extra_args:
                cmd.extend(extra_args)
            
            logger.info(f"[CloudFox] Running: {' '.join(cmd)}")
            
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                stdout, stderr = await asyncio.wait_for(
                    process.communicate(),
                    timeout=300  # 5 minutes
                )
                
                if process.returncode != 0:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    logger.error(f"[CloudFox] Command failed: {error_msg}")
                    return {
                        "error": f"CloudFox command failed: {error_msg}",
                        "command": command
                    }
                
                # Parse output
                output = stdout.decode()
                
                # Try to find JSON output file
                output_files = list(Path(temp_dir).glob("*.json"))
                if output_files:
                    with open(output_files[0]) as f:
                        return json.load(f)
                
                # Try to parse stdout as JSON
                try:
                    return json.loads(output)
                except json.JSONDecodeError:
                    # Return raw output
                    return {
                        "raw_output": output,
                        "command": command
                    }
            
            except asyncio.TimeoutError:
                logger.error(f"[CloudFox] Command timed out: {command}")
                return {"error": f"CloudFox command timed out: {command}"}
            
            except Exception as e:
                logger.error(f"[CloudFox] Execution failed: {e}")
                return {"error": str(e)}
    
    async def _discover_secrets(self, profile: str = "default", region: str = "us-east-1") -> Dict[str, Any]:
        """Discover exposed secrets"""
        logger.info(f"[CloudFox] Discovering secrets in AWS account...")
        
        result = await self._run_cloudfox_command("secrets", profile, region)
        
        if "error" not in result:
            findings = self._parse_secrets(result)
            return {
                "command": "secrets",
                "findings_count": len(findings),
                "findings": findings,
                "raw_data": result
            }
        
        return result
    
    async def _enumerate_attack_paths(self, profile: str = "default", region: str = "us-east-1") -> Dict[str, Any]:
        """Enumerate attack paths"""
        logger.info(f"[CloudFox] Enumerating attack paths...")
        
        # Run multiple modules that identify attack paths
        results = {}
        
        for module in ["permissions", "role-trusts", "principals"]:
            result = await self._run_cloudfox_command(module, profile, region)
            results[module] = result
        
        # Combine findings
        all_findings = []
        for module, result in results.items():
            if "error" not in result:
                all_findings.extend(self._parse_generic_findings(module, result))
        
        return {
            "command": "attack_paths",
            "findings_count": len(all_findings),
            "findings": all_findings,
            "modules_run": list(results.keys())
        }
    
    async def _analyze_iam_principals(self, profile: str = "default") -> Dict[str, Any]:
        """Analyze IAM principals"""
        logger.info(f"[CloudFox] Analyzing IAM principals...")
        
        result = await self._run_cloudfox_command("principals", profile)
        
        if "error" not in result:
            findings = self._parse_principals(result)
            return {
                "command": "principals",
                "findings_count": len(findings),
                "findings": findings,
                "raw_data": result
            }
        
        return result
    
    async def _check_endpoints(self, profile: str = "default") -> Dict[str, Any]:
        """Check exposed endpoints"""
        logger.info(f"[CloudFox] Checking exposed endpoints...")
        
        result = await self._run_cloudfox_command("endpoints", profile)
        
        if "error" not in result:
            findings = self._parse_endpoints(result)
            return {
                "command": "endpoints",
                "findings_count": len(findings),
                "findings": findings,
                "raw_data": result
            }
        
        return result
    
    async def _analyze_role_trusts(self, profile: str = "default") -> Dict[str, Any]:
        """Analyze role trust relationships"""
        logger.info(f"[CloudFox] Analyzing role trusts...")
        
        result = await self._run_cloudfox_command("role-trusts", profile)
        
        if "error" not in result:
            findings = self._parse_role_trusts(result)
            return {
                "command": "role-trusts",
                "findings_count": len(findings),
                "findings": findings,
                "raw_data": result
            }
        
        return result
    
    async def _offensive_scan(
        self,
        profile: str = "default",
        region: str = "us-east-1",
        modules: List[str] = None
    ) -> Dict[str, Any]:
        """Run full offensive security scan"""
        logger.info(f"[CloudFox] Running offensive security scan...")
        
        if not modules:
            modules = [
                "secrets",
                "principals", 
                "endpoints",
                "role-trusts",
                "permissions",
                "env-vars",
                "access-keys",
                "buckets"
            ]
        
        results = {}
        all_findings = []
        
        for module in modules:
            logger.info(f"[CloudFox] Running module: {module}")
            result = await self._run_cloudfox_command(module, profile, region)
            results[module] = result
            
            if "error" not in result:
                findings = self._parse_generic_findings(module, result)
                all_findings.extend(findings)
        
        return {
            "scan_id": f"cloudfox-{datetime.utcnow().timestamp()}",
            "timestamp": datetime.utcnow().isoformat(),
            "profile": profile,
            "region": region,
            "modules_run": modules,
            "total_findings": len(all_findings),
            "findings": all_findings,
            "severity_breakdown": self._get_severity_breakdown(all_findings),
            "raw_results": results
        }
    
    # Parsing helpers
    
    def _parse_secrets(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse secrets findings"""
        findings = []
        
        # CloudFox secrets output format varies, handle different structures
        data = result.get("secrets", result.get("data", []))
        
        for item in data:
            if isinstance(item, dict):
                findings.append({
                    "severity": "CRITICAL",
                    "title": f"Secret Exposed: {item.get('type', 'Unknown')}",
                    "description": f"Secret found in {item.get('location', 'unknown')}",
                    "resource": item.get("resource_arn", item.get("resource")),
                    "recommendation": "Remove hardcoded secrets, use AWS Secrets Manager",
                    "module": "secrets",
                    "raw_data": item
                })
        
        return findings
    
    def _parse_principals(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse principals findings"""
        findings = []
        
        data = result.get("principals", result.get("data", []))
        
        for item in data:
            if isinstance(item, dict):
                is_admin = item.get("is_admin", False)
                if is_admin:
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Admin Principal: {item.get('name', 'Unknown')}",
                        "description": f"Principal has administrator-level permissions",
                        "resource": item.get("arn"),
                        "recommendation": "Apply least privilege, use custom policies",
                        "module": "principals",
                        "raw_data": item
                    })
        
        return findings
    
    def _parse_endpoints(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse endpoints findings"""
        findings = []
        
        data = result.get("endpoints", result.get("data", []))
        
        for item in data:
            if isinstance(item, dict):
                if item.get("public"):
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Public Endpoint: {item.get('name', 'Unknown')}",
                        "description": f"Endpoint is publicly accessible",
                        "resource": item.get("arn"),
                        "recommendation": "Review exposure, implement network restrictions",
                        "module": "endpoints",
                        "raw_data": item
                    })
        
        return findings
    
    def _parse_role_trusts(self, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Parse role trust findings"""
        findings = []
        
        data = result.get("role_trusts", result.get("trusts", result.get("data", [])))
        
        for item in data:
            if isinstance(item, dict):
                principal = item.get("trusted_principal", "")
                if "*" in principal or "root" in principal.lower():
                    findings.append({
                        "severity": "HIGH",
                        "title": f"Permissive Trust: {item.get('role_name', 'Unknown')}",
                        "description": f"Role trusts {principal}",
                        "resource": item.get("role_arn"),
                        "recommendation": "Restrict trust to specific principals",
                        "module": "role-trusts",
                        "raw_data": item
                    })
        
        return findings
    
    def _parse_generic_findings(self, module: str, result: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generic parser for CloudFox results"""
        findings = []
        
        # Try common data structures
        data = result.get("data", result.get(module, []))
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    findings.append({
                        "severity": "MEDIUM",
                        "title": f"{module.title()}: {item.get('name', 'Finding')}",
                        "description": str(item),
                        "module": module,
                        "raw_data": item
                    })
        
        return findings
    
    def _get_severity_breakdown(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        """Get severity breakdown"""
        breakdown = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }
        
        for finding in findings:
            severity = finding.get("severity", "MEDIUM")
            if severity in breakdown:
                breakdown[severity] += 1
        
        return breakdown


def create_cloudfox_server(config: Dict[str, Any] = None) -> CloudFoxMCPServer:
    """Factory function to create CloudFox MCP server"""
    if config is None:
        config = {}
    return CloudFoxMCPServer(config)
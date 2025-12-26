# backend/mcp_servers/gcp_server.py

"""
GCP MCP Server - Dedicated server for GCP security scanning
Implements MCP protocol for Google Cloud Platform resources
"""

import json
import logging
from typing import Dict, List, Any
from google.cloud import storage
from google.oauth2 import service_account
from datetime import datetime

from backend.mcp_servers.base_server import (
    BaseMCPServer,
    MCPTool,
    MCPResource,
    ToolCategory
)
from backend.mcp.mcp_base import CloudResource, SecurityFinding, Severity

logger = logging.getLogger("gcp_mcp_server")


class GCPMCPServer(BaseMCPServer):
    """GCP MCP Server - provides tools and resources for GCP security scanning"""
    
    def __init__(self, config: Dict[str, Any]):
        self.storage_client = None
        self.credentials = None
        self.project_id = None
        
        super().__init__("gcp", config)
        
        # Initialize GCP session
        self._initialize_gcp_session()
    
    def _initialize_gcp_session(self) -> None:
        """Initialize GCP clients"""
        try:
            # Extract project_id
            self.project_id = self.config.get('project_id')
            
            service_account_json = self.config.get('service_account_json')
            
            if service_account_json:
                # Handle both JSON string and dict
                if isinstance(service_account_json, str):
                    try:
                        sa_info = json.loads(service_account_json)
                    except json.JSONDecodeError:
                        import os
                        if os.path.exists(service_account_json):
                            with open(service_account_json) as f:
                                sa_info = json.load(f)
                        else:
                            raise ValueError("Invalid service account JSON")
                else:
                    sa_info = service_account_json
                
                # Set project_id from service account if not provided
                if not self.project_id and 'project_id' in sa_info:
                    self.project_id = sa_info['project_id']
                
                # Create credentials
                self.credentials = service_account.Credentials.from_service_account_info(
                    sa_info,
                    scopes=["https://www.googleapis.com/auth/cloud-platform"]
                )
                
                # Initialize storage client
                self.storage_client = storage.Client(
                    project=self.project_id,
                    credentials=self.credentials
                )
                
                logger.info(f"[GCP] Authenticated for project: {self.project_id}")
                
            else:
                # Use default credentials
                self.storage_client = storage.Client(project=self.project_id)
                logger.info(f"[GCP] Using default credentials for project: {self.project_id}")
            
        except Exception as e:
            logger.error(f"[GCP] Failed to initialize session: {e}")
            raise
    
    def _setup_tools(self) -> None:
        """Setup GCP security scanning tools"""
        
        # Tool 1: Discover GCS Buckets
        self.register_tool(MCPTool(
            name="gcp/discover_gcs_buckets",
            description="Discover all Cloud Storage buckets",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {
                    "include_iam": {
                        "type": "boolean",
                        "description": "Include IAM policies",
                        "default": True
                    }
                }
            },
            handler=self._discover_gcs_buckets
        ))
        
        # Tool 2: Check GCS Security
        self.register_tool(MCPTool(
            name="gcp/check_gcs_security",
            description="Check Cloud Storage bucket security",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "bucket_name": {
                        "type": "string",
                        "description": "Bucket name to check"
                    }
                },
                "required": ["bucket_name"]
            },
            handler=self._check_gcs_security
        ))
        
        # Tool 3: Discover IAM Policies
        self.register_tool(MCPTool(
            name="gcp/discover_iam_policies",
            description="Discover project IAM policies",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {}
            },
            handler=self._discover_iam_policies
        ))
        
        # Tool 4: Full GCP Scan
        self.register_tool(MCPTool(
            name="gcp/full_scan",
            description="Perform complete GCP security scan",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID"
                    },
                    "deep_scan": {
                        "type": "boolean",
                        "description": "Perform deep vulnerability scanning",
                        "default": False
                    }
                }
            },
            handler=self._full_scan
        ))
    
    def _setup_resources(self) -> None:
        """Setup GCP resources"""
        
        self.register_resource(MCPResource(
            uri="gcp://project/info",
            name="GCP Project Information",
            description="Current GCP project details",
            mime_type="application/json"
        ))
        
        self.register_resource(MCPResource(
            uri="gcp://storage/buckets",
            name="GCS Buckets List",
            description="List of all Cloud Storage buckets",
            mime_type="application/json"
        ))
    
    async def _fetch_resource_content(self, uri: str) -> str:
        """Fetch content for GCP resources"""
        
        if uri == "gcp://project/info":
            return json.dumps({
                "project_id": self.project_id,
                "authenticated": self.credentials is not None
            }, indent=2)
        
        elif uri == "gcp://storage/buckets":
            buckets = list(self.storage_client.list_buckets())
            bucket_list = [bucket.name for bucket in buckets]
            return json.dumps({
                "buckets": bucket_list,
                "count": len(bucket_list)
            }, indent=2)
        
        else:
            raise ValueError(f"Unknown resource URI: {uri}")
    
    # Tool Handlers
    
    async def _discover_gcs_buckets(self, include_iam: bool = True) -> Dict[str, Any]:
        """Discover GCS buckets"""
        logger.info("[GCP] Discovering GCS buckets...")
        
        try:
            buckets = list(self.storage_client.list_buckets())
            
            resources = []
            for bucket in buckets:
                bucket_data = {
                    "name": bucket.name,
                    "location": bucket.location,
                    "storage_class": bucket.storage_class,
                    "versioning_enabled": bucket.versioning_enabled,
                    "created": bucket.time_created.isoformat() if bucket.time_created else None
                }
                
                if include_iam:
                    try:
                        policy = bucket.get_iam_policy(requested_policy_version=3)
                        policy_dict = {}
                        for binding in policy.bindings:
                            role = binding.get('role', '')
                            members = binding.get('members', [])
                            policy_dict[role] = list(members)
                        bucket_data["iam_policy"] = policy_dict
                    except:
                        bucket_data["iam_policy"] = {}
                
                resources.append(bucket_data)
            
            return {
                "resources": resources,
                "count": len(resources),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"[GCP] GCS discovery failed: {e}")
            return {"error": str(e), "resources": [], "count": 0}
    
    async def _check_gcs_security(self, bucket_name: str) -> Dict[str, Any]:
        """Check GCS bucket security"""
        logger.info(f"[GCP] Checking GCS security for {bucket_name}...")
        
        findings = []
        
        try:
            bucket = self.storage_client.bucket(bucket_name)
            
            # Check public access
            is_public = False
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    members = binding.get('members', [])
                    if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                        is_public = True
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": "Public GCS Bucket",
                            "description": f"Bucket {bucket_name} is publicly accessible"
                        })
            except:
                pass
            
            # Check encryption
            if not bucket.default_kms_key_name:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "GCS Bucket Not Using CMEK",
                    "description": f"Bucket {bucket_name} not using customer-managed encryption"
                })
            
            # Check versioning
            if not bucket.versioning_enabled:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "GCS Versioning Disabled",
                    "description": f"Bucket {bucket_name} does not have versioning enabled"
                })
            
            # Check logging
            if not bucket.logging:
                findings.append({
                    "severity": "LOW",
                    "issue": "GCS Logging Disabled",
                    "description": f"Bucket {bucket_name} does not have access logging"
                })
            
            return {
                "bucket": bucket_name,
                "is_public": is_public,
                "findings": findings,
                "severity_count": {
                    "CRITICAL": len([f for f in findings if f["severity"] == "CRITICAL"]),
                    "HIGH": len([f for f in findings if f["severity"] == "HIGH"]),
                    "MEDIUM": len([f for f in findings if f["severity"] == "MEDIUM"])
                }
            }
        
        except Exception as e:
            return {"error": str(e), "bucket": bucket_name, "findings": []}
    
    async def _discover_iam_policies(self) -> Dict[str, Any]:
        """Discover IAM policies (basic implementation)"""
        logger.info("[GCP] Discovering IAM policies...")
        
        # Note: Full implementation requires Resource Manager API
        return {
            "message": "IAM policy discovery requires Resource Manager API",
            "project_id": self.project_id,
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _full_scan(self, project_id: str = None, deep_scan: bool = False) -> Dict[str, Any]:
        """Perform full GCP security scan"""
        logger.info(f"[GCP] Starting full scan (deep={deep_scan})...")
        
        project_id = project_id or self.project_id
        
        results = {
            "scan_id": f"gcp-{datetime.utcnow().timestamp()}",
            "project_id": project_id,
            "timestamp": datetime.utcnow().isoformat(),
            "deep_scan": deep_scan,
            "resources": {},
            "findings": [],
            "summary": {}
        }
        
        try:
            # Discover GCS buckets
            gcs_result = await self._discover_gcs_buckets()
            results["resources"]["gcs_buckets"] = gcs_result["count"]
            
            # Check GCS security for each bucket
            for bucket in gcs_result.get("resources", []):
                security_check = await self._check_gcs_security(bucket["name"])
                results["findings"].extend(security_check.get("findings", []))
            
            # Summary
            results["summary"] = {
                "total_resources": sum(results["resources"].values()),
                "total_findings": len(results["findings"]),
                "critical": len([f for f in results["findings"] if f["severity"] == "CRITICAL"]),
                "high": len([f for f in results["findings"] if f["severity"] == "HIGH"]),
                "medium": len([f for f in results["findings"] if f["severity"] == "MEDIUM"])
            }
            
            return results
        
        except Exception as e:
            logger.error(f"[GCP] Full scan failed: {e}")
            results["error"] = str(e)
            return results


def create_gcp_server(config: Dict[str, Any]) -> GCPMCPServer:
    """Factory function to create GCP MCP server"""
    return GCPMCPServer(config)
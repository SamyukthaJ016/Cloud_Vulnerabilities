# backend/mcp_servers/gcp_server.py

"""
GCP MCP Server - Dedicated server for GCP security scanning
Implements MCP protocol for Google Cloud Platform resources
"""

import json
import logging
from typing import Dict, List, Any
from google.cloud import storage
from google.cloud import compute_v1
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
        self.compute_client = None
        self.firewall_client = None
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

                # Initialize compute clients
                self.compute_client = compute_v1.InstancesClient(credentials=self.credentials)
                self.firewall_client = compute_v1.FirewallsClient(credentials=self.credentials)
                
                logger.info(f"[GCP] Authenticated for project: {self.project_id}")
                
            else:
                # Use default credentials
                self.storage_client = storage.Client(project=self.project_id)
                self.compute_client = compute_v1.InstancesClient()
                self.firewall_client = compute_v1.FirewallsClient()
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
        
        # Tool 3: Check IAM Security
        self.register_tool(MCPTool(
            name="gcp/check_iam_security",
            description="Check project IAM security policies",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {}
            },
            handler=self._check_iam_security
        ))
        
        # Tool 4: Discover Compute Instances
        self.register_tool(MCPTool(
            name="gcp/discover_compute_instances",
            description="Discover Compute Engine instances",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {}
            },
            handler=self._discover_compute_instances
        ))
        
        # Tool 5: Check Firewall Security
        self.register_tool(MCPTool(
            name="gcp/check_firewall_security",
            description="Check VPC firewall rule security",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {}
            },
            handler=self._check_firewall_security
        ))
        
        # Tool 6: Full GCP Scan
        self.register_tool(MCPTool(
            name="gcp/full_scan",
            description="Perform complete GCP security scan",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "string",
                        "description": "GCP account/project ID"
                    },
                    "project_id": {
                        "type": "string",
                        "description": "GCP project ID (legacy)"
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
            
    async def _discover_compute_instances(self) -> Dict[str, Any]:
        """Discover Compute Engine instances"""
        logger.info("[GCP] Discovering compute instances...")
        try:
            # We need to list all instances across all zones
            request = compute_v1.AggregatedListInstancesRequest(
                project=self.project_id,
            )
            
            agg_list = self.compute_client.aggregated_list(request=request)
            
            resources = []
            for zone, response in agg_list:
                if response.instances:
                    for instance in response.instances:
                        instance_dict = {
                            "name": instance.name,
                            "zone": zone.split('/')[-1],
                            "machine_type": instance.machine_type.split('/')[-1],
                            "status": instance.status,
                            "network_interfaces": [
                                {
                                    "network_ip": ni.network_i_p,
                                    "access_configs": [
                                        {"nat_ip": ac.nat_i_p} for ac in ni.access_configs
                                    ]
                                } for ni in instance.network_interfaces
                            ],
                            "config_raw": {
                                "shielded_instance_config": {
                                    "enable_secure_boot": instance.shielded_instance_config.enable_secure_boot,
                                    "enable_vtpm": instance.shielded_instance_config.enable_vtpm,
                                    "enable_integrity_monitoring": instance.shielded_instance_config.enable_integrity_monitoring
                                } if instance.shielded_instance_config else {},
                                "can_ip_forward": instance.can_ip_forward
                            }
                        }
                        resources.append(instance_dict)
            
            return {
                "resources": resources,
                "count": len(resources),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"[GCP] Compute discovery failed: {e}")
            return {"error": str(e), "resources": [], "count": 0}

    async def _check_firewall_security(self) -> Dict[str, Any]:
        """Check VPC firewall rule security"""
        logger.info("[GCP] Checking firewall security...")
        findings = []
        try:
            request = compute_v1.ListFirewallsRequest(project=self.project_id)
            firewalls = self.firewall_client.list(request=request)
            
            for fw in firewalls:
                # Check for overly permissive rules (0.0.0.0/0)
                if '0.0.0.0/0' in fw.source_ranges and fw.direction == 'INGRESS' and fw.allowed:
                    for allowed in fw.allowed:
                        protocol = str(
                            getattr(allowed, "I_p_protocol", None)
                            or getattr(allowed, "i_p_protocol", "")
                        ).lower()
                        # Check for risky ports (SSH 22, RDP 3389, DBs, etc.)
                        risky_ports = ['22', '3389', '3306', '5432', '27017']
                        if protocol == 'all':
                            findings.append({
                                "severity": "CRITICAL",
                                "issue": "Full Ingress Access",
                                "description": f"Firewall rule {fw.name} allows ALL traffic from 0.0.0.0/0",
                                "resource": fw.name
                            })
                        elif not allowed.ports or any(port in allowed.ports for port in risky_ports):
                            findings.append({
                                "severity": "HIGH",
                                "issue": "Overly Permissive Firewall Rule",
                                "description": f"Firewall rule {fw.name} allows traffic from 0.0.0.0/0 on sensitive ports",
                                "resource": fw.name
                            })

            return {
                "findings": findings,
                "count": len(findings),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"[GCP] Firewall check failed: {e}")
            return {"error": str(e), "findings": []}

    async def _check_iam_security(self) -> Dict[str, Any]:
        """Check project-level IAM security"""
        logger.info("[GCP] Checking project IAM security...")
        findings = []
        try:
            from google.cloud import resourcemanager_v3
            client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
            # Use flattened argument for robustness
            policy = client.get_iam_policy(resource=f"projects/{self.project_id}")
            
            for binding in policy.bindings:
                role = binding.role
                members = binding.members
                
                # Check for primitive roles
                if role in ["roles/owner", "roles/editor"]:
                    findings.append({
                        "severity": "HIGH",
                        "issue": "Primitive Role Usage",
                        "description": f"Role {role} is assigned to {len(members)} members. Use predefined or custom roles instead.",
                        "recommendation": "Replace basic/primitive roles (Owner, Editor, Viewer) with fine-grained IAM roles."
                    })
                
                # Check for external members
                for member in members:
                    if "@gmail.com" in member or "@googlemail.com" in member:
                        findings.append({
                            "severity": "MEDIUM",
                            "issue": "External Member in IAM",
                            "description": f"External user {member} has role {role}",
                            "recommendation": "Remove external personal accounts from project IAM policies."
                        })
            
            return {
                "findings": findings,
                "count": len(findings),
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            logger.error(f"[GCP] IAM security check failed: {e}")
            return {"error": str(e), "findings": []}

    async def _check_compute_security(self, instance: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Check specific security posture of a compute instance"""
        findings = []
        instance_name = instance.get("name", "unknown")
        
        # 1. Check Shielded VM
        # Note: instance here is the dict from _discover_compute_instances, 
        # but aggregated_list returns Instance objects which we converted to dict.
        # We need to ensure we have the right fields.
        config = instance.get("config_raw", {}) # We'll populate this in discovery
        
        shielded_config = config.get("shielded_instance_config", {})
        if not shielded_config.get("enable_secure_boot"):
            findings.append({
                "severity": "MEDIUM",
                "issue": "Shielded VM Secure Boot Disabled",
                "description": f"Instance {instance_name} does not have Secure Boot enabled",
                "recommendation": "Enable Shielded VM Secure Boot to protect against rootkits and bootkits."
            })
            
        # 2. Check for Public IP
        has_public_ip = False
        for ni in instance.get("network_interfaces", []):
            if ni.get("access_configs"):
                has_public_ip = True
                break
        
        if has_public_ip:
             findings.append({
                "severity": "MEDIUM",
                "issue": "Public IP Address Assigned",
                "description": f"Instance {instance_name} has a public IP address",
                "recommendation": "Remove public IPs unless absolutely necessary. Use Identity-Aware Proxy (IAP) for access."
            })
             
        # 3. Check IP Forwarding
        if config.get("can_ip_forward"):
            findings.append({
                "severity": "HIGH",
                "issue": "IP Forwarding Enabled",
                "description": f"Instance {instance_name} has IP forwarding enabled",
                "recommendation": "Disable IP forwarding unless the instance is specifically used as a gateway or NAT."
            })

        return findings
    
    async def _full_scan(self, account_id: str = None, project_id: str = None, deep_scan: bool = False, **kwargs) -> Dict[str, Any]:
        """Perform complete GCP security scan"""
        # Ignore "default" account_id
        effective_account_id = account_id if account_id != "default" else None
        active_project = project_id or effective_account_id or self.project_id
        
        logger.info(f"[GCP] Starting full scan for project: {active_project} (deep={deep_scan})...")
        
        results = {
            "scan_id": f"gcp-{datetime.utcnow().timestamp()}",
            "project_id": active_project,
            "timestamp": datetime.utcnow().isoformat(),
            "deep_scan": deep_scan,
            "resources": [], 
            "findings": [],
            "errors": [],
            "summary": {}
        }
        
        try:
            # 1. Discover GCS buckets
            gcs_discovery = await self._discover_gcs_buckets()
            if "error" in gcs_discovery:
                results["errors"].append(f"GCS Discovery error: {gcs_discovery['error']}")
            
            bucket_resources = gcs_discovery.get("resources", [])
            for r in bucket_resources:
                res_obj = {
                    "provider": "gcp",
                    "resource_type": "gcs_bucket",
                    "name": r["name"],
                    "region": r.get("location", "global"),
                    "config": r,
                    "is_public": False 
                }
                
                security_check = await self._check_gcs_security(r["name"])
                if "error" in security_check:
                    results["errors"].append(f"GCS Security check for {r['name']} failed: {security_check['error']}")
                else:
                    res_obj["is_public"] = security_check.get("is_public", False)
                    for f in security_check.get("findings", []):
                        results["findings"].append({
                            "resource": res_obj,
                            "severity": f["severity"],
                            "issue": f["issue"],
                            "description": f["description"],
                            "recommendation": "Follow GCP security hardening guidelines for Cloud Storage.",
                            "detection_tool": "gcp-config-scanner"
                        })
                results["resources"].append(res_obj)
            
            # 2. Discover Compute Instances & Check Security
            compute_discovery = await self._discover_compute_instances()
            if "error" in compute_discovery:
                results["errors"].append(f"Compute Discovery error: {compute_discovery['error']}")
            
            for r in compute_discovery.get("resources", []):
                res_obj = {
                    "provider": "gcp",
                    "resource_type": "compute_instance",
                    "name": r["name"],
                    "region": r.get("zone", "global"),
                    "config": r,
                    "is_public": any(ni.get("access_configs") for ni in r.get("network_interfaces", []))
                }
                results["resources"].append(res_obj)
                
                # Check security for this instance
                instance_findings = await self._check_compute_security(r)
                for f in instance_findings:
                    results["findings"].append({
                        "resource": res_obj,
                        "severity": f["severity"],
                        "issue": f["issue"],
                        "description": f["description"],
                        "recommendation": f["recommendation"],
                        "detection_tool": "gcp-compute-scanner"
                    })
            
            # 3. Check Project IAM Security
            iam_check = await self._check_iam_security()
            if "error" in iam_check:
                results["errors"].append(f"IAM Check error: {iam_check['error']}")
            
            # Create a pseudo-resource for Project IAM
            project_res = {
                "provider": "gcp",
                "resource_type": "project_iam",
                "name": f"project-{active_project}-iam",
                "region": "global",
                "config": {"project_id": active_project},
                "is_public": False
            }
            results["resources"].append(project_res)
            
            for f in iam_check.get("findings", []):
                results["findings"].append({
                    "resource": project_res,
                    "severity": f["severity"],
                    "issue": f["issue"],
                    "description": f["description"],
                    "recommendation": f["recommendation"],
                    "detection_tool": "gcp-iam-scanner"
                })
            
            # 4. Check Firewalls
            firewall_check = await self._check_firewall_security()
            if "error" in firewall_check:
                results["errors"].append(f"Firewall Check error: {firewall_check['error']}")
            
            for f in firewall_check.get("findings", []):
                fw_name = f.get("resource", "unknown-firewall")
                res_obj = {
                    "provider": "gcp",
                    "resource_type": "firewall_rule",
                    "name": fw_name,
                    "region": "global",
                    "config": {"firewall_name": fw_name},
                    "is_public": True 
                }
                results["resources"].append(res_obj)
                
                results["findings"].append({
                    "resource": res_obj,
                    "severity": f["severity"],
                    "issue": f["issue"],
                    "description": f["description"],
                    "recommendation": "Restrict firewall ingress to known IP ranges and specific ports.",
                    "detection_tool": "gcp-firewall-checker"
                })
            
            # Final summary
            results["summary"] = {
                "total_resources": len(results["resources"]),
                "total_findings": len(results["findings"]),
                "critical": len([f for f in results["findings"] if f["severity"] == "CRITICAL"]),
                "high": len([f for f in results["findings"] if f["severity"] == "HIGH"]),
                "medium": len([f for f in results["findings"] if f["severity"] == "MEDIUM"]),
                "low": len([f for f in results["findings"] if f.get("severity") == "LOW"]),
                "errors_count": len(results["errors"])
            }
            
            return results
        
        except Exception as e:
            logger.error(f"[GCP] Full scan failed: {e}")
            results["error"] = str(e)
            return results


def create_gcp_server(config: Dict[str, Any]) -> GCPMCPServer:
    """Factory function to create GCP MCP server"""
    return GCPMCPServer(config)

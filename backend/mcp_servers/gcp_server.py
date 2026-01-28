# backend/mcp_servers/gcp_server.py

"""
GCP MCP Server - Dedicated server for GCP security scanning
Implements MCP protocol for Google Cloud Platform resources
"""

import json
import logging
import asyncio
from datetime import datetime
from typing import Dict, List, Any, Optional
from google.cloud import storage
from google.cloud import compute_v1
from google.cloud import resourcemanager_v3
try:
    from google.cloud import iam_admin_v1
except ImportError:
    try:
        from google.iam import admin_v1 as iam_admin_v1
    except ImportError:
        logger.warning("[GCP] google-cloud-iam (iam_admin_v1) not found, will use discovery fallback")
        iam_admin_v1 = None
# from google.cloud.sql.connector import Connector  # Not compatible with Python 3.11 yet
from google.cloud import functions_v1
from google.cloud import container_v1
from google.cloud import bigquery
from googleapiclient import discovery
from google.oauth2 import service_account
from datetime import datetime, timezone, timedelta

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
        self.instances_client = None
        self.firewalls_client = None
        self.networks_client = None
        self.iam_client = None
        self.resource_manager_client = None
        self.functions_client = None
        self.container_client = None
        self.bigquery_client = None
        self.sql_client = None
        self.artifact_client = None
        self.run_client = None
        self.secret_client = None
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
                
                # Initialize Compute Engine clients
                self.instances_client = compute_v1.InstancesClient(credentials=self.credentials)
                self.firewalls_client = compute_v1.FirewallsClient(credentials=self.credentials)
                self.networks_client = compute_v1.NetworksClient(credentials=self.credentials)
                
                # Initialize IAM clients
                if iam_admin_v1:
                    try:
                        self.iam_client = iam_admin_v1.IAMClient(credentials=self.credentials)
                    except Exception as e:
                        logger.warning(f"[GCP] Failed to initialize IAMClient: {e}. Falling back to discovery.")
                        self.iam_client = discovery.build('iam', 'v1', credentials=self.credentials, cache_discovery=False)
                else:
                    self.iam_client = discovery.build('iam', 'v1', credentials=self.credentials, cache_discovery=False)
                
                self.resource_manager_client = resourcemanager_v3.ProjectsClient(credentials=self.credentials)
                
                # Initialize Cloud Functions client
                self.functions_client = functions_v1.CloudFunctionsServiceClient(credentials=self.credentials)
                
                # Initialize GKE client
                self.container_client = container_v1.ClusterManagerClient(credentials=self.credentials)
                
                # Initialize BigQuery client
                self.bigquery_client = bigquery.Client(
                    project=self.project_id,
                    credentials=self.credentials
                )
                
                # Initialize SQL Admin client (Discovery-based)
                self.sql_client = discovery.build('sqladmin', 'v1beta4', credentials=self.credentials, cache_discovery=False)
                
                # Initialize Cloud Run client
                try:
                    from google.cloud import run_v2
                    self.run_client = run_v2.ServicesClient(credentials=self.credentials)
                except ImportError:
                    logger.warning("[GCP] google-cloud-run not installed, skipping Cloud Run discovery")
                
                # Initialize Secret Manager client
                try:
                    from google.cloud import secretmanager_v1
                    self.secret_client = secretmanager_v1.SecretManagerServiceClient(credentials=self.credentials)
                except ImportError:
                    logger.warning("[GCP] google-cloud-secret-manager not installed, skipping Secret Manager discovery")
                
                # Initialize Asset Inventory client (Discovery-based fallback)
                try:
                    self.asset_client = discovery.build('cloudasset', 'v1', credentials=self.credentials, cache_discovery=False)
                except:
                    self.asset_client = None
                
                logger.info(f"[GCP] Session initialized for project: {self.project_id}")
                
            else:
                # Use default credentials
                self.storage_client = storage.Client(project=self.project_id)
                self.instances_client = compute_v1.InstancesClient()
                self.firewalls_client = compute_v1.FirewallsClient()
                self.networks_client = compute_v1.NetworksClient()
                self.iam_client = iam_admin_v1.IAMClient()
                self.resource_manager_client = resourcemanager_v3.ProjectsClient()
                self.functions_client = functions_v1.CloudFunctionsServiceClient()
                self.container_client = container_v1.ClusterManagerClient()
                self.bigquery_client = bigquery.Client(project=self.project_id)
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
                    "account_id": {
                        "type": "string",
                        "description": "Account ID (alias for project_id)"
                    },
                    "deep_scan": {
                        "type": "boolean",
                        "description": "Perform deep vulnerability scanning",
                        "default": False
                    },
                    "offensive_scan": {
                        "type": "boolean",
                        "description": "Perform offensive scanning (not supported for GCP)",
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
        """Discover GCS buckets with enhanced error handling"""
        logger.info("[GCP] Discovering GCS buckets...")
        resources = []
        findings = []
        
        try:
            # Try listing via the standard client
            buckets_it = self.storage_client.list_buckets()
            buckets = list(buckets_it)
            logger.info(f"[GCP] Found {len(buckets)} buckets via storage client")
            
            for bucket in buckets:
                bucket_data = {
                    "name": bucket.name,
                    "location": bucket.location,
                    "storage_class": bucket.storage_class,
                    "versioning_enabled": bucket.versioning_enabled,
                    "created": bucket.time_created.isoformat() if bucket.time_created else None,
                    "type": "gcs_bucket"
                }
                
                if include_iam:
                    try:
                        # Attempt to get IAM policy
                        policy = bucket.get_iam_policy(requested_policy_version=3)
                        policy_dict = {}
                        for binding in policy.bindings:
                            role = binding.get('role', '')
                            members = binding.get('members', [])
                            policy_dict[role] = list(members)
                        bucket_data["iam_policy"] = policy_dict
                    except Exception as e:
                        logger.debug(f"[GCP] Could not get IAM for bucket {bucket.name}: {e}")
                
                # Check security and add findings
                if include_iam:
                    security_result = await self._check_gcs_security(bucket.name)
                    findings.extend(security_result.get("findings", []))
                    bucket_data["security_status"] = security_result
                
                resources.append(bucket_data)
        
        except Exception as e:
            logger.warning(f"[GCP] Standard GCS discovery failed ({e}). Trying Asset Inventory fallback...")
            try:
                # Use Cloud Asset Inventory to find buckets if standard listing fails
                if self.asset_client:
                    logger.info(f"[GCP] Attempting Asset Search in projects/{self.project_id}")
                    # Asset Inventory Search: No query string, filter by type
                    request = self.asset_client.assets().searchAllResources(
                        scope=f"projects/{self.project_id}", 
                        assetTypes=["storage.googleapis.com/Bucket"]
                    )
                    response = request.execute()
                    results = response.get('results', [])
                    logger.info(f"[GCP] Asset Search returned {len(results)} items")
                    
                    found_via_asset = False
                    for asset in results:
                        found_via_asset = True
                        bucket_name = asset.get('displayName') or asset.get('name', '').split('/')[-1]
                        resources.append({
                            "name": bucket_name,
                            "location": asset.get('location'),
                            "type": "gcs_bucket"
                        })
                        # Try security check for discovered asset
                        try:
                            sec = await self._check_gcs_security(bucket_name)
                            findings.extend(sec.get("findings", []))
                        except Exception as e:
                            logger.debug(f"[GCP] Sec check failed for {bucket_name}: {e}")
                    
                    if not found_via_asset:
                        logger.info("[GCP] No buckets found via Asset Inventory search")
            except Exception as e2:
                logger.error(f"[GCP] GCS fallback discovery also failed: {e2}")

        if not resources:
            findings.append({
                "severity": "INFO",
                "issue": "No GCS Buckets Discovered",
                "description": "The scanner found zero GCS buckets. If you have GCPGoat deployed, ensure the Storage API is enabled and permissions are granted.",
                "detection_tool": "discovery_engine"
            })

        return {
            "resources": resources,
            "findings": findings,
            "count": len(resources),
            "timestamp": datetime.utcnow().isoformat()
        }
    
    async def _check_gcs_security(self, bucket_name: str) -> Dict[str, Any]:
        """Check GCS bucket security"""
        logger.info(f"[GCP] Checking GCS security for {bucket_name}...")
        
        findings = []
        
        try:
            bucket = self.storage_client.bucket(bucket_name)
            
            # Check public access via IAM
            is_public_iam = False
            try:
                policy = bucket.get_iam_policy(requested_policy_version=3)
                for binding in policy.bindings:
                    members = binding.get('members', [])
                    if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                        is_public_iam = True
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": "Public GCS Bucket (IAM)",
                            "description": f"Bucket {bucket_name} is publicly accessible via IAM policies",
                            "resource_name": bucket_name,
                            "recommendation": f"Remove 'allUsers' and 'allAuthenticatedUsers' from the IAM policy of bucket {bucket_name}. Enable Uniform Bucket-level Access to prevent accidental public exposure."
                        })
            except Exception as e:
                logger.debug(f"Failed to check GCS IAM: {e}")
            
            # Check public access via ACLs
            is_public_acl = False
            try:
                # If Uniform Bucket Level Access is disabled, ACLs might be used
                if not bucket.iam_configuration.get('uniformBucketLevelAccess', {}).get('enabled'):
                    acl = bucket.acl
                    for entity in acl.get_entities():
                        if entity == 'allUsers' or entity == 'allAuthenticatedUsers':
                            is_public_acl = True
                            findings.append({
                                "severity": "CRITICAL",
                                "issue": "Public GCS Bucket (ACL)",
                                "description": f"Bucket {bucket_name} is publicly accessible via ACLs",
                                "resource_name": bucket_name,
                                "recommendation": f"Update the bucket ACLs to remove public permissions for 'allUsers' or 'allAuthenticatedUsers'. It is highly recommended to enable Uniform Bucket-level Access to disable ACLs entirely."
                            })
            except Exception as e:
                logger.debug(f"Failed to check GCS ACL: {e}")
            
            is_public = is_public_iam or is_public_acl

            # Check for Uniform Bucket Level Access (Best practice)
            try:
                iam_config = getattr(bucket, 'iam_configuration', {})
                ubla = iam_config.get('uniformBucketLevelAccess', {}) if isinstance(iam_config, dict) else getattr(iam_config, 'uniform_bucket_level_access', None)
                
                enabled = False
                if isinstance(ubla, dict):
                    enabled = ubla.get('enabled', False)
                elif ubla:
                    enabled = getattr(ubla, 'enabled', False)

                if not enabled:
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "Uniform Bucket Level Access Disabled",
                        "description": f"Bucket {bucket_name} does not have Uniform Bucket Level Access enabled. This makes ACL management complex and riskier.",
                        "resource_name": bucket_name,
                        "recommendation": f"Enable Uniform Bucket-level Access on bucket {bucket_name}. This ensures that IAM policies are the only way to manage access, simplifying security audits."
                    })
                
                # Check for public objects if UBLA is disabled (ACLs still apply)
                if not enabled:
                    findings.append({
                        "severity": "LOW",
                        "issue": "Fine-grained Access Control Enabled",
                        "description": f"Bucket {bucket_name} supports object-level ACLs, which can lead to accidental public exposure of individual files.",
                        "resource_name": bucket_name,
                        "recommendation": "Switch to Uniform Bucket-level Access for more predictable security."
                    })
            except Exception as e:
                logger.debug(f"Failed to check UBLA for {bucket_name}: {e}")

            # NEW: Check for Public Access Prevention (Best practice)
            try:
                # Need to use the resource directly as python client support varies
                iam_config = getattr(bucket, 'iam_configuration', {})
                pap = iam_config.get('publicAccessPrevention', '') if isinstance(iam_config, dict) else getattr(iam_config, 'public_access_prevention', '')
                
                if pap != 'enforced':
                    findings.append({
                        "severity": "HIGH",
                        "issue": "Public Access Prevention Disabled",
                        "description": f"Bucket {bucket_name} does not have Public Access Prevention enforced. This setting explicitly prevents public access.",
                        "resource_name": bucket_name,
                        "recommendation": f"Enforce Public Access Prevention on bucket {bucket_name} to guarantee that objects cannot be made public."
                    })
            except Exception as e:
                logger.debug(f"Failed to check PAP for {bucket_name}: {e}")
            
            # Check encryption
            if not bucket.default_kms_key_name:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "GCS Bucket Not Using CMEK",
                    "description": f"Bucket {bucket_name} not using customer-managed encryption",
                    "resource_name": bucket_name,
                    "recommendation": f"Enable Customer-Managed Encryption Keys (CMEK) for bucket {bucket_name} using Cloud KMS to have full control over the encryption process."
                })
            
            # Check versioning
            if not bucket.versioning_enabled:
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "GCS Versioning Disabled",
                    "description": f"Bucket {bucket_name} does not have versioning enabled",
                    "resource_name": bucket_name,
                    "recommendation": f"Enable Object Versioning on bucket {bucket_name} to protect against accidental deletion or overwriting of data."
                })
            
            # Check logging
            if not bucket.logging:
                findings.append({
                    "severity": "LOW",
                    "issue": "GCS Logging Disabled",
                    "description": f"Bucket {bucket_name} does not have access logging",
                    "resource_name": bucket_name
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
        """Discover IAM policies and service accounts"""
        logger.info("[GCP] Discovering IAM resources...")
        
        resources = []
        findings = []
        
        try:
            # Get project IAM policy
            project_name = f"projects/{self.project_id}"
            policy = None
            
            try:
                # Use project_id directly as the resource name for the request
                policy = self.resource_manager_client.get_iam_policy(resource=project_name)
                
                # Check for public bindings
                for binding in policy.bindings:
                    if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": "Public IAM Binding",
                            "description": f"Role {binding.role} is granted to public (allUsers or allAuthenticatedUsers)",
                            "recommendation": f"Immediately remove 'allUsers' or 'allAuthenticatedUsers' from the {binding.role} role at the project level. Use specific user or service account bindings instead."
                        })
                    
                    # Check for overly permissive roles
                    if binding.role in ["roles/owner", "roles/editor"] and len(binding.members) > 0:
                        findings.append({
                            "severity": "HIGH",
                            "issue": "Overly Permissive IAM Role",
                            "description": f"Role {binding.role} granted at project level to {len(binding.members)} members",
                            "resource_name": self.project_id,
                            "recommendation": f"Limit the use of powerful roles like 'Owner' or 'Editor'. Replace these with more specific, least-privileged roles (e.g., 'Storage Object Viewer' instead of 'Editor')."
                        })
                    
                    # Check for service account impersonation roles
                    risky_impersonation_roles = [
                        "roles/iam.serviceAccountUser",
                        "roles/iam.serviceAccountTokenCreator",
                        "roles/iam.workloadIdentityUser",
                        "roles/iam.securityAdmin",
                        "roles/resourcemanager.projectIamAdmin"
                    ]
                    if binding.role in risky_impersonation_roles:
                        findings.append({
                            "severity": "HIGH",
                            "issue": "Risky Service Account Impersonation Role",
                            "description": f"Role {binding.role} granted at project level to {len(binding.members)} members. This can lead to privilege escalation.",
                            "resource_name": self.project_id,
                            "recommendation": f"Avoid granting service account impersonation roles (like 'Service Account User') at the project level. Instead, grant them only on the specific service accounts the users need to access."
                        })
                
                resources.append({
                    "name": self.project_id,
                    "type": "iam_policy",
                    "bindings_count": len(policy.bindings)
                })
            except Exception as e:
                logger.warning(f"[GCP] Failed to get IAM policy: {e}")
            
            # List service accounts and their keys
            try:
                import dateutil.parser as date_parser
                sa_parent = f"projects/{self.project_id}"
                service_accounts = []
                
                # Support both GAPIC and Discovery clients
                if hasattr(self.iam_client, 'projects'):
                    # Discovery client logic
                    resp = self.iam_client.projects().serviceAccounts().list(name=sa_parent).execute()
                    sa_list = resp.get('accounts', [])
                    # Normalize to simple objects or dicts
                    for sa_dict in sa_list:
                        email = sa_dict.get('email')
                        unique_id = sa_dict.get('uniqueId')
                        name = sa_dict.get('name')
                        
                        resources.append({
                            "name": email,
                            "type": "service_account",
                            "unique_id": unique_id
                        })
                        
                        # NEW: Check IAM policy on the Service Account itself
                        try:
                            sa_policy = self.iam_client.projects().serviceAccounts().getIamPolicy(resource=name).execute()
                            if sa_policy and 'bindings' in sa_policy:
                                for binding in sa_policy['bindings']:
                                    role = binding.get('role', '')
                                    members = binding.get('members', [])
                                    if any(r in role for r in ["serviceAccountUser", "serviceAccountTokenCreator"]):
                                        findings.append({
                                            "severity": "HIGH",
                                            "issue": "Service Account Impersonation Allowed",
                                            "description": f"Role {role} is granted on service account {email} to {members}. This allows those members to act as this service account.",
                                            "resource_name": email,
                                            "recommendation": f"Review and restrict who can impersonate the service account {email}."
                                        })
                        except Exception as e:
                            logger.debug(f"[GCP] Could not get IAM for SA {email}: {e}")

                        # Check for Default Compute Service Account
                        if "developer.gserviceaccount.com" in email:
                             findings.append({
                                "severity": "MEDIUM",
                                "issue": "Default Compute Service Account in Use",
                                "description": f"Default Service Account {email} is present.",
                                "resource_name": email,
                                "recommendation": "Use custom service accounts instead of the Default Compute SA."
                            })

                        # List keys
                        try:
                            keys_resp = self.iam_client.projects().serviceAccounts().keys().list(name=name).execute()
                            for key in keys_resp.get('keys', []):
                                valid_after = key.get('validAfterTime')
                                if valid_after:
                                    # Handle timestamp string from Discovery API
                                    try:
                                        from dateutil import parser
                                        create_time = parser.parse(valid_after)
                                        age = datetime.now(timezone.utc) - create_time
                                        if age.days > 90:
                                            findings.append({
                                                "severity": "HIGH",
                                                "issue": "Stale Service Account Key",
                                                "description": f"Key for {email} is {age.days} days old.",
                                                "recommendation": f"Rotate the stale key for {email}."
                                            })
                                    except: pass
                        except Exception as e:
                            logger.debug(f"[GCP] Could not list keys for {email}: {e}")
                else:
                    # GAPIC client logic
                    service_accounts = self.iam_client.list_service_accounts(name=sa_parent)
                    for sa in service_accounts:
                        resources.append({
                            "name": sa.email,
                            "type": "service_account",
                            "unique_id": sa.unique_id
                        })
                        
                        try:
                            sa_resource = f"projects/{self.project_id}/serviceAccounts/{sa.email}"
                            target_resource = sa.name if "/" in sa.name else sa_resource
                            sa_policy = self.iam_client.get_iam_policy(request={"resource": target_resource})
                            
                            if sa_policy and hasattr(sa_policy, 'bindings'):
                                for binding in sa_policy.bindings:
                                    if any(role in binding.role for role in ["serviceAccountUser", "serviceAccountTokenCreator"]):
                                        findings.append({
                                            "severity": "HIGH",
                                            "issue": "Service Account Impersonation Allowed",
                                            "description": f"Role {binding.role} is granted on service account {sa.email} to {list(binding.members)}.",
                                            "resource_name": sa.email,
                                            "recommendation": f"Review and restrict who can impersonate the service account {sa.email}."
                                        })
                        except Exception as e:
                            logger.debug(f"[GCP] Could not get IAM policy for service account {sa.email}: {e}")

                        if "developer.gserviceaccount.com" in sa.email:
                             findings.append({
                                "severity": "MEDIUM",
                                "issue": "Default Compute Service Account in Use",
                                "description": f"Default Service Account {sa.email} is present.",
                                "resource_name": sa.email,
                                "recommendation": "Use custom service accounts instead of the Default Compute SA."
                            })
                        
                        try:
                            keys = self.iam_client.list_service_account_keys(name=sa.name)
                            for key in keys:
                                create_time = key.valid_after_time
                                if create_time:
                                    age = datetime.now(timezone.utc) - create_time
                                    if age.days > 90:
                                        findings.append({
                                            "severity": "HIGH",
                                            "issue": "Stale Service Account Key",
                                            "description": f"Key for {sa.email} is {age.days} days old.",
                                            "recommendation": f"Rotate the stale key for {sa.email}."
                                        })
                        except Exception as e:
                            logger.debug(f"[GCP] Could not list keys for {sa.email}: {e}")
                
                # Check for project-level IAM roles that allow escalation (additional check)
                risky_members = {}
                if policy:
                    for binding in policy.bindings:
                        if any(role in binding.role for role in ["owner", "editor", "securityAdmin", "projectIamAdmin"]):
                            for member in binding.members:
                                if member not in risky_members: risky_members[member] = []
                                risky_members[member].append(binding.role)
                
                for member, roles in risky_members.items():
                    if "serviceAccount" not in member: # Focus on users/groups
                        findings.append({
                            "severity": "HIGH",
                            "issue": "Highly Privileged IAM Member",
                            "description": f"Member {member} has powerful roles ({', '.join(roles)}) which can be used for administrative escalation.",
                            "resource_name": member,
                            "recommendation": f"Review and restrict permissions for {member}. Apply the principle of least privilege and remove unnecessary administrative roles."
                        })
                
                # Enhanced: Check for specific privilege escalation paths
                if policy:
                    escalation_paths = await self._detect_privilege_escalation(policy)
                    findings.extend(escalation_paths)
                
            except Exception as e:
                logger.warning(f"[GCP] Failed to list service accounts: {e}")
            
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        
        except Exception as e:
            logger.error(f"[GCP] IAM discovery failed: {e}")
            return {"error": str(e), "resources": [], "findings": []}
    
    async def _detect_privilege_escalation(self, policy) -> List[Dict]:
        """
        Detect IAM privilege escalation paths
        Identifies dangerous permission combinations that allow privilege escalation
        """
        findings = []
        
        # Define dangerous permission combinations for privilege escalation
        escalation_patterns = {
            "Service Account Impersonation": {
                "permissions": ["iam.serviceAccounts.actAs", "iam.serviceAccounts.getAccessToken"],
                "severity": "CRITICAL",
                "description": "Allows impersonating service accounts to gain their permissions"
            },
            "Service Account Key Creation": {
                "permissions": ["iam.serviceAccountKeys.create"],
                "severity": "CRITICAL",
                "description": "Allows creating keys for service accounts to steal their credentials"
            },
            "IAM Policy Modification": {
                "permissions": ["resourcemanager.projects.setIamPolicy", "iam.serviceAccounts.setIamPolicy"],
                "severity": "CRITICAL",
                "description": "Allows modifying IAM policies to grant themselves additional permissions"
            },
            "Cloud Function Deployment": {
                "permissions": ["cloudfunctions.functions.create", "cloudfunctions.functions.update"],
                "severity": "HIGH",
                "description": "Allows deploying malicious Cloud Functions with elevated service accounts"
            },
            "Compute Instance Creation": {
                "permissions": ["compute.instances.create", "compute.instances.setServiceAccount"],
                "severity": "HIGH",
                "description": "Allows creating compute instances with privileged service accounts"
            },
            "Storage Bucket IAM Modification": {
                "permissions": ["storage.buckets.setIamPolicy"],
                "severity": "HIGH",
                "description": "Allows modifying bucket IAM to grant access to sensitive data"
            }
        }
        
        # Check each binding for dangerous permissions
        try:
            for binding in policy.bindings:
                role = binding.role
                members = binding.members
                
                # Check if role contains dangerous permissions
                for pattern_name, pattern_data in escalation_patterns.items():
                    dangerous_perms = pattern_data["permissions"]
                    
                    # Check if the role name suggests it has these permissions
                    role_lower = role.lower()
                    has_dangerous_perm = False
                    
                    # Map role names to likely permissions
                    if any(perm_keyword in role_lower for perm_keyword in [
                        "owner", "editor", "admin", "serviceaccountadmin", 
                        "iamadmin", "securityadmin", "cloudfunctions.admin"
                    ]):
                        has_dangerous_perm = True
                    
                    # Specific checks for each pattern
                    if "serviceaccounts.actas" in dangerous_perms[0].lower() and "serviceaccountuser" in role_lower:
                        has_dangerous_perm = True
                    elif "serviceaccountkeys.create" in dangerous_perms[0].lower() and "serviceaccountkeyadmin" in role_lower:
                        has_dangerous_perm = True
                    elif "setiampolicy" in dangerous_perms[0].lower() and ("iamadmin" in role_lower or "owner" in role_lower):
                        has_dangerous_perm = True
                    elif "cloudfunctions" in dangerous_perms[0].lower() and "cloudfunctions" in role_lower:
                        has_dangerous_perm = True
                    elif "compute.instances" in dangerous_perms[0].lower() and ("compute.admin" in role_lower or "compute.instanceadmin" in role_lower):
                        has_dangerous_perm = True
                    
                    if has_dangerous_perm:
                        for member in members:
                            findings.append({
                                "severity": pattern_data["severity"],
                                "issue": f"IAM Privilege Escalation Path: {pattern_name}",
                                "description": f"Member '{member}' has role '{role}' which grants dangerous permissions. {pattern_data['description']}. This can be exploited for privilege escalation.",
                                "resource_name": member,
                                "role": role,
                                "escalation_type": pattern_name,
                                "recommendation": f"Remove role '{role}' from '{member}' unless absolutely necessary. Implement least privilege by granting only specific required permissions instead of broad administrative roles."
                            })
        
        except Exception as e:
            logger.debug(f"[GCP] Privilege escalation detection failed: {e}")
        
        return findings
    
    async def _discover_compute_instances(self) -> Dict[str, Any]:
        """Discover Compute Engine instances"""
        logger.info("[GCP] Discovering Compute instances...")
        
        resources = []
        findings = []
        
        try:
            # Deep Check: Project-level metadata for OS Login and Serial Port
            try:
                projects_client = compute_v1.ProjectsClient(credentials=self.credentials)
                project_info = projects_client.get(project=self.project_id)
                common_metadata = project_info.common_instance_metadata.items
                
                os_login_enabled = False
                serial_port_enabled = False
                
                for item in common_metadata:
                    if item.key == 'enable-oslogin' and str(item.value).upper() == 'TRUE':
                        os_login_enabled = True
                    if item.key == 'serial-port-enable' and str(item.value).upper() == 'TRUE':
                        serial_port_enabled = True
                
                if not os_login_enabled:
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "OS Login Disabled",
                        "description": "OS Login is not enabled at the project level. Enabling OS Login ensures IAM-based access control for VMs.",
                        "resource_name": f"project/{self.project_id}",
                        "recommendation": "Enable OS Login at the project level by setting 'enable-oslogin' to 'TRUE' in the project-wide metadata. This ensures more secure SSH access management."
                    })
                
                if serial_port_enabled:
                    findings.append({
                        "severity": "HIGH",
                        "issue": "Serial Port Access Enabled",
                        "description": "Serial port access is enabled at the project level. This could allow unauthorized access if not strictly controlled.",
                        "resource_name": f"project/{self.project_id}",
                        "recommendation": "Disable serial port access at the project level unless specifically required for debugging. Set 'serial-port-enable' to 'FALSE' in project metadata."
                    })
            except Exception as e:
                logger.debug(f"[GCP] Project metadata check failed: {e}")
            # OPTIMIZED: Use aggregated_list to find instances in all zones with a single API call
            try:
                request = compute_v1.AggregatedListInstancesRequest(project=self.project_id)
                agg_list = self.instances_client.aggregated_list(request=request)
                
                for zone_name, response in agg_list:
                    if response.instances:
                        zone = zone_name.split('/')[-1]
                        for instance in response.instances:
                            has_public_ip = False
                            
                            # Check for public IP
                            for interface in instance.network_interfaces:
                                if interface.access_configs:
                                    has_public_ip = True
                                    findings.append({
                                        "severity": "HIGH",
                                        "issue": "Compute Instance with Public IP",
                                        "description": f"Instance {instance.name} has a public IP address",
                                        "resource_name": instance.name,
                                        "recommendation": f"Remove the public IP from instance {instance.name} and use a Cloud NAT or a Load Balancer if internet access is needed."
                                    })
                            
                            # Check disk encryption
                            for disk in instance.disks:
                                if not disk.disk_encryption_key:
                                    findings.append({
                                        "severity": "MEDIUM",
                                        "issue": "Unencrypted Disk",
                                        "description": f"Instance {instance.name} has disk without customer-managed encryption",
                                        "resource_name": instance.name,
                                        "recommendation": f"Enable Customer-Managed Encryption Keys (CMEK) for disks on {instance.name}."
                                    })
                            
                            public_ip = next((access.nat_i_p for net in instance.network_interfaces for access in net.access_configs if access.nat_i_p), None)
                            
                            resources.append({
                                "name": instance.name,
                                "zone": zone,
                                "machine_type": instance.machine_type,
                                "has_public_ip": has_public_ip,
                                "public_ip": public_ip,
                                "type": "compute_instance"
                            })
            except Exception as e:
                logger.error(f"[GCP] Aggregated compute discovery failed: {e}")
            
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        
        except Exception as e:
            logger.error(f"[GCP] Compute discovery failed: {e}")
            return {"error": str(e), "resources": [], "findings": []}
            
    async def _discover_sql_instances(self) -> Dict[str, Any]:
        """Discover Cloud SQL instances and check security"""
        logger.info("[GCP] Discovering Cloud SQL instances...")
        resources = []
        findings = []
        
        try:
            if not self.sql_client:
                return {"resources": [], "findings": [], "count": 0}
                
            request = self.sql_client.instances().list(project=self.project_id)
            response = request.execute()
            
            for instance in response.get('items', []):
                name = instance.get('name')
                settings = instance.get('settings', {})
                ip_config = settings.get('ipConfiguration', {})
                
                # Check for public IP
                if ip_config.get('ipv4Enabled', False):
                    findings.append({
                        "severity": "HIGH",
                        "issue": "Cloud SQL Public IP Enabled",
                        "description": f"Instance {name} has a public IP enabled. Use Private IP and Cloud SQL Auth Proxy instead.",
                        "resource_name": name,
                        "recommendation": f"Disable the public IP address on Cloud SQL instance {name}. Configure Private IP access and use the Cloud SQL Auth Proxy for secure connections from outside the VPC."
                    })
                
                # Check SSL enforcement
                if not ip_config.get('requireSsl', False):
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "Cloud SQL SSL Not Enforced",
                        "description": f"Instance {name} does not enforce SSL/TLS for connections.",
                        "resource_name": name,
                        "recommendation": f"Enable 'Require SSL' on Cloud SQL instance {name} to ensure all data in transit is encrypted. Configure your application to use SSL when connecting to the database."
                    })
                
                # Check automated backups
                backup_config = settings.get('backupConfiguration', {})
                if not backup_config.get('enabled', False):
                    findings.append({
                        "severity": "LOW",
                        "issue": "Cloud SQL Backups Disabled",
                        "description": f"Instance {name} has automated backups disabled.",
                        "resource_name": name
                    })
                
                resources.append({
                    "name": name,
                    "database_version": instance.get('databaseVersion'),
                    "state": instance.get('state'),
                    "public_ip": next((addr.get('ipAddress') for addr in instance.get('ipAddresses', []) if addr.get('type') == 'PRIMARY'), None),
                    "type": "cloud_sql"
                })
                
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        except Exception as e:
            logger.warning(f"[GCP] Cloud SQL discovery failed: {e}")
            return {"resources": [], "findings": [], "count": 0}
    
    async def _discover_network_resources(self) -> Dict[str, Any]:
        """Discover VPC networks and firewall rules"""
        logger.info("[GCP] Discovering network resources...")
        
        resources = []
        findings = []
        
        try:
            # List firewall rules
            request = compute_v1.ListFirewallsRequest(project=self.project_id)
            firewalls = self.firewalls_client.list(request=request)
            
            for firewall in firewalls:
                # Check for overly permissive rules (Ingress only)
                if (not firewall.direction or firewall.direction == "INGRESS") and firewall.source_ranges and "0.0.0.0/0" in firewall.source_ranges:
                    for allowed in firewall.allowed:
                        # Safely get protocol
                        # Try IP_protocol first (Discovery API format) then I_P_protocol (Client library format)
                        protocol = str(getattr(allowed, 'I_P_protocol', getattr(allowed, 'IP_protocol', getattr(allowed, 'protocol', 'tcp')))).lower()
                        
                        # Fix for default-allow-icmp being flagged as TCP
                        if "icmp" in protocol or "icmp" in firewall.name.lower():
                            protocol = "icmp"

                        ports = [str(p) for p in getattr(allowed, 'ports', [])]
                        
                        if protocol == "icmp":
                            # ICMP is generally safe/noisy but we flag if specifically requested (not here)
                            continue

                        if not ports:
                            if protocol == "all":
                                findings.append({
                                    "severity": "CRITICAL",
                                    "issue": "Publicly Accessible Firewall (All Ports)",
                                    "description": f"Firewall rule {firewall.name} allows ALL traffic from the internet",
                                    "resource_name": firewall.name,
                                    "recommendation": f"Immediately restrict firewall rule {firewall.name}. Do not allow traffic from '0.0.0.0/0' on all ports. Use specific IP ranges (CIDRs) and specific ports as required by your application."
                                })
                            else:
                                findings.append({
                                    "severity": "HIGH",
                                    "issue": f"Publicly Accessible {protocol.upper()}",
                                    "description": f"Firewall rule {firewall.name} allows public access to all {protocol.upper()} ports",
                                    "resource_name": firewall.name,
                                    "recommendation": f"Restrict firewall rule {firewall.name} to allow only necessary {protocol.upper()} ports and limit the source IP range instead of '0.0.0.0/0'."
                                })
                        else:
                            for port in ports:
                                port_str = str(port)
                                if "22" in port_str:
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "issue": "Publicly Accessible SSH",
                                        "description": f"Firewall rule {firewall.name} allows public access to SSH (Port 22)",
                                        "resource_name": firewall.name,
                                        "recommendation": f"Remove '0.0.0.0/0' from firewall rule {firewall.name}. Restrict SSH access (Port 22) to specific corporate IP addresses or use Google Cloud Identity-Aware Proxy (IAP) for secure access."
                                    })
                                elif "3389" in port_str:
                                    findings.append({
                                        "severity": "CRITICAL",
                                        "issue": "Publicly Accessible RDP",
                                        "description": f"Firewall rule {firewall.name} allows public access to RDP (Port 3389)",
                                        "resource_name": firewall.name,
                                        "recommendation": f"Remove '0.0.0.0/0' from firewall rule {firewall.name}. Restrict RDP access (Port 3389) to specific IP ranges or use Identity-Aware Proxy (IAP)."
                                    })
                                else:
                                    findings.append({
                                        "severity": "MEDIUM",
                                        "issue": "Exposed Port",
                                        "description": f"Firewall rule {firewall.name} allows public access to port {port_str}",
                                        "resource_name": firewall.name
                                    })
                
                resources.append({
                    "name": firewall.name,
                    "type": "firewall_rule",
                    "direction": firewall.direction
                })
            
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        
        except Exception as e:
            logger.warning(f"[GCP] Network discovery failed: {e}")
            return {"resources": [], "findings": [], "count": 0}
    
    async def _discover_cloud_functions(self) -> Dict[str, Any]:
        """Discover Cloud Functions with v1 and v2 support"""
        logger.info("[GCP] Discovering Cloud Functions...")
        resources = []
        findings = []
        
        try:
            # GCP projects can have functions in many locations
            # The '-' wildcard for locations is standard for v1 listing
            parent = f"projects/{self.project_id}/locations/-"
            
            try:
                functions = self.functions_client.list_functions(request={"parent": parent})
                for function in functions:
                    # Check if function allows unauthenticated invocation
                    try:
                        # Get IAM policy for the function to check for allUsers
                        # Resource format: projects/{project}/locations/{location}/functions/{function}
                        func_policy = self.functions_client.get_iam_policy(request={"resource": function.name})
                        is_public = False
                        for binding in func_policy.bindings:
                            if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                                is_public = True
                                break
                        
                        if is_public:
                            findings.append({
                                "severity": "CRITICAL",
                                "issue": "Unauthenticated Cloud Function",
                                "description": f"Function {function.name.split('/')[-1]} allows unauthenticated invocation (public access)",
                                "resource_name": function.name,
                                "recommendation": f"Remove 'allUsers' or 'allAuthenticatedUsers' from the IAM policy of Cloud Function {function.name.split('/')[-1]}. Use IAM-based authentication for secure calls."
                            })
                    except Exception as e:
                        logger.debug(f"Could not get IAM for Cloud Function {function.name}: {e}")
                    
                    res_data = {
                        "name": function.name,
                        "runtime": function.runtime,
                        "trigger_type": "https" if function.https_trigger else "event",
                        "type": "cloud_function"
                    }
                    
                    if function.https_trigger and function.https_trigger.url:
                        res_data["https_trigger_url"] = function.https_trigger.url
                    
                    resources.append(res_data)
            except Exception as e:
                logger.warning(f"[GCP] Cloud Functions v1 list failed: {e}. Trying Cloud Functions v2 fallback...")
                # Fallback to Asset Inventory for Functions
                try:
                    if self.asset_client:
                        request = self.asset_client.assets().searchAllResources(
                            scope=f"projects/{self.project_id}", 
                            assetTypes=["cloudfunctions.googleapis.com/Function"]
                        )
                        response = request.execute()
                        for asset in response.get('results', []):
                            func_name = asset.get('name')
                            resources.append({
                                "name": func_name,
                                "type": "cloud_function"
                            })
                except Exception as asset_err:
                    logger.debug(f"[GCP] Function asset fallback failed: {asset_err}")
            
            if not resources:
                findings.append({
                    "severity": "INFO",
                    "issue": "No Cloud Functions Discovered",
                    "description": "Zero Cloud Functions found. Module 1 of GCPGoat requires the Cloud Functions API to be enabled and visible.",
                    "detection_tool": "discovery_engine"
                })

            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        
        except Exception as e:
            logger.warning(f"[GCP] Cloud Functions discovery failed: {e}")
            return {"resources": [], "findings": [], "count": 0}
    
    async def _discover_gke_clusters(self) -> Dict[str, Any]:
        """Discover GKE clusters"""
        logger.info("[GCP] Discovering GKE clusters...")
        
        resources = []
        findings = []
        
        try:
            parent = f"projects/{self.project_id}/locations/-"
            response = self.container_client.list_clusters(parent=parent)
            
            for cluster in response.clusters:
                # Check if cluster has public endpoint
                if cluster.private_cluster_config is None or not cluster.private_cluster_config.enable_private_endpoint:
                    findings.append({
                        "severity": "HIGH",
                        "issue": "GKE Cluster with Public Endpoint",
                        "description": f"Cluster {cluster.name} has a public endpoint",
                        "resource_name": cluster.name,
                        "recommendation": f"Enable Private Endpoint for cluster {cluster.name} and restrict master authorized networks to known, secure IP ranges."
                    })
                
                # Check legacy ABAC
                if cluster.legacy_abac and cluster.legacy_abac.enabled:
                    findings.append({
                        "severity": "HIGH",
                        "issue": "Legacy ABAC Enabled",
                        "description": f"Cluster {cluster.name} has legacy ABAC enabled",
                        "resource_name": cluster.name,
                        "recommendation": f"Disable Legacy Attribute-Based Access Control (ABAC) on GKE cluster {cluster.name} and use Role-Based Access Control (RBAC) instead for more granular security."
                    })
                
                resources.append({
                    "name": cluster.name,
                    "location": cluster.location,
                    "status": cluster.status,
                    "endpoint": cluster.endpoint,
                    "type": "gke_cluster"
                })
            
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        
        except Exception as e:
            logger.warning(f"[GCP] GKE discovery failed: {e}")
            return {"resources": [], "findings": [], "count": 0}
    
    async def _discover_bigquery_datasets(self) -> Dict[str, Any]:
        """Discover BigQuery datasets"""
        logger.info("[GCP] Discovering BigQuery datasets...")
        
        resources = []
        findings = []
        
        try:
            datasets = list(self.bigquery_client.list_datasets())
            
            for dataset in datasets:
                dataset_ref = self.bigquery_client.get_dataset(dataset.reference)
                
                # Check for public access
                for entry in dataset_ref.access_entries:
                    if entry.entity_type == "allAuthenticatedUsers" or entry.entity_type == "allUsers":
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": "Publicly Accessible BigQuery Dataset",
                            "description": f"Dataset {dataset.dataset_id} is publicly accessible"
                        })
                
                resources.append({
                    "name": dataset.dataset_id,
                    "location": dataset.location,
                    "tables_count": len(list(self.bigquery_client.list_tables(dataset.reference)))
                })
            
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        
        except Exception as e:
            logger.warning(f"[GCP] BigQuery discovery failed: {e}")
            return {"resources": [], "findings": [], "count": 0}

    async def _discover_artifact_images(self) -> Dict[str, Any]:
        """Discover Artifact Registry images for vulnerability scanning"""
        logger.info("[GCP] Discovering Artifact Registry images...")
        resources = []
        findings = []
        
        try:
            if not self.artifact_client:
                return {"resources": [], "findings": [], "count": 0}
                
            # List repositories in the project
            parent = f"projects/{self.project_id}/locations/-"
            request = self.artifact_client.projects().locations().repositories().list(parent=parent)
            response = request.execute()
            
            for repo in response.get('repositories', []):
                repo_name = repo.get('name') # format: projects/*/locations/*/repositories/*
                
                # List packages (images) in the repository
                pkg_request = self.artifact_client.projects().locations().repositories().packages().list(parent=repo_name)
                pkg_response = pkg_request.execute()
                
                for pkg in pkg_response.get('packages', []):
                    pkg_id = pkg.get('name').split('/')[-1]
                    
                    # Construct image URI for Trivy
                    # format: location-docker.pkg.dev/project/repo/package
                    parts = repo_name.split('/')
                    location = parts[3]
                    project = parts[1]
                    repository = parts[5]
                    
                    image_uri = f"{location}-docker.pkg.dev/{project}/{repository}/{pkg_id}"
                    
                    resources.append({
                        "name": pkg_id,
                        "type": "gcr_image", # Map to gcr_image for backend compatibility
                        "image_uri": image_uri,
                        "repository": repository,
                        "location": location
                    })
            
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        except Exception as e:
            logger.warning(f"[GCP] Artifact Registry discovery failed: {e}")
            return {"resources": [], "findings": [], "count": 0}
    
    async def _discover_secrets(self) -> Dict[str, Any]:
        """Discover Secret Manager secrets"""
        logger.info("[GCP] Discovering Secrets...")
        resources = []
        findings = []
        
        try:
            if not self.secret_client: return {"resources": [], "findings": []}
            
            parent = f"projects/{self.project_id}"
            request = self.secret_client.projects().secrets().list(parent=parent)
            response = request.execute()
            
            for secret in response.get('secrets', []):
                name = secret.get('name', '').split('/')[-1]
                resources.append({
                    "name": name,
                    "type": "secret",
                    "created": secret.get('createTime')
                })
                
                # Check if secret is exposed via IAM
                try:
                    policy_req = self.secret_client.projects().secrets().getIamPolicy(resource=secret['name'])
                    policy = policy_req.execute()
                    for binding in policy.get('bindings', []):
                        if "allUsers" in binding.get('members', []) or "allAuthenticatedUsers" in binding.get('members', []):
                            findings.append({
                                "severity": "CRITICAL",
                                "issue": "Public Secret Access",
                                "description": f"Secret {name} is publicly accessible via IAM",
                                "resource_name": name
                            })
                except: pass

            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        except Exception as e:
            logger.debug(f"[GCP] Secret discovery failed: {e}")
            return {"resources": [], "findings": []}

    async def _discover_cloud_run_services(self) -> Dict[str, Any]:
        """Discover Cloud Run services"""
        logger.info("[GCP] Discovering Cloud Run services...")
        resources = []
        findings = []
        
        try:
            if not self.run_client:
                return {"resources": [], "findings": [], "count": 0}
            
            parent = f"projects/{self.project_id}/locations/-"
            request = {"parent": parent}
            
            services = self.run_client.list_services(request=request)
            
            for service in services:
                is_public = False
                # Check IAM policy for allUsers/allAuthenticatedUsers
                try:
                    policy = self.run_client.get_iam_policy(request={"resource": service.name})
                    for binding in policy.bindings:
                        if "allUsers" in binding.members or "allAuthenticatedUsers" in binding.members:
                            is_public = True
                            break
                    
                    if is_public:
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": "Unauthenticated Cloud Run Service",
                            "description": f"Service {service.name.split('/')[-1]} allows unauthenticated invocation",
                            "resource_name": service.name,
                            "recommendation": f"Remove 'allUsers' or 'allAuthenticatedUsers' from the IAM policy of Cloud Run service {service.name.split('/')[-1]}. Enable IAM authentication to restrict access to authorized callers."
                        })
                except Exception as e:
                    logger.debug(f"Could not get IAM for Cloud Run {service.name}: {e}")
                
                resources.append({
                    "name": service.name,
                    "uri": service.uri,
                    "ingress": str(service.ingress),
                    "type": "cloud_run"
                })
                
            return {
                "resources": resources,
                "findings": findings,
                "count": len(resources)
            }
        except Exception as e:
            logger.warning(f"[GCP] Cloud Run discovery failed: {e}")
            return {"resources": [], "findings": [], "count": 0}

    async def _scan_web_applications(self, deep_scan: bool = False) -> Dict[str, Any]:
        """
        Scan web applications (Cloud Functions, Cloud Run) for OWASP vulnerabilities
        Detects: XSS, IDOR, SSRF, Sensitive Data Exposure, Password Reset issues
        """
        logger.info("[GCP] Scanning web applications for OWASP vulnerabilities...")
        findings = []
        
        try:
            # Import enhanced GCPGoat scanner
            from backend.mcp_servers.gcpgoat_scanner import GCPGoatScanner
            from backend.vulnerability.vulnerability_scanner import VulnerabilityScanner, ScanTarget
            from google.cloud import functions_v1
            
            gcpgoat_scanner = GCPGoatScanner()
            v_scanner = VulnerabilityScanner()
            
            # Collect all HTTP endpoints from Cloud Functions and Cloud Run
            endpoints = []
            
            # Get Cloud Functions endpoints
            try:
                parent = f"projects/{self.project_id}/locations/-"
                request = functions_v1.ListFunctionsRequest(parent=parent)
                functions = self.functions_client.list_functions(request=request)
                
                for function in functions:
                    if function.https_trigger and function.https_trigger.url:
                        endpoints.append({
                            "url": function.https_trigger.url,
                            "name": function.name.split('/')[-1],
                            "type": "cloud_function"
                        })
            except Exception as e:
                logger.debug(f"[GCP] Could not list Cloud Functions for web scanning: {e}")
            
            # Get Cloud Run endpoints
            try:
                if self.run_client:
                    parent = f"projects/{self.project_id}/locations/-"
                    services = self.run_client.list_services(parent=parent)
                    
                    for service in services:
                        if service.uri:
                            endpoints.append({
                                "url": service.uri,
                                "name": service.name.split('/')[-1],
                                "type": "cloud_run"
                            })
            except Exception as e:
                logger.debug(f"[GCP] Could not list Cloud Run for web scanning: {e}")
            
            if not endpoints:
                logger.info("[GCP] No HTTP endpoints found for web application scanning")
                return {"findings": [], "count": 0}
            
            logger.info(f"[GCP] Found {len(endpoints)} HTTP endpoints to scan")
            
            # OPTIMIZED: Scan all endpoints in parallel
            tasks = []
            for endpoint in endpoints:
                tasks.append(gcpgoat_scanner.scan_endpoint(endpoint["url"], endpoint["name"], endpoint["type"]))
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            total_web_findings = 0
            for i, result in enumerate(results):
                name = endpoints[i]["name"]
                if isinstance(result, list):
                    findings.extend(result)
                    total_web_findings += len(result)
                    logger.info(f"[GCP] Finished scanning {name}. Found {len(result)} findings.")
                else:
                    logger.error(f"[GCP] Failed to scan endpoint {name}: {result}")
            
            logger.info(f"[GCP] Web application scan complete. Total unique web findings found: {total_web_findings}")
            
            return {
                "findings": findings,
                "count": len(findings)
            }
        
        except Exception as e:
            logger.error(f"[GCP] Web application scanning failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            return {"findings": [], "count": 0}
    
    async def _test_ssrf(self, url: str, resource_name: str, resource_type: str) -> List[Dict]:
        """
        Test for Server-Side Request Forgery (SSRF) vulnerabilities
        OPTIMIZED: Reduced timeout, limited params, parallel execution
        """
        findings = []
        
        try:
            import aiohttp
            import asyncio
            
            # GCPGoat specific: These are the exact parameters used in the vulnerable functions
            param_names = ["url", "uri", "redirect", "proxy", "link", "fetch", "u", "path"]
            
            # GCPGoat specific payloads for metadata
            ssrf_payloads = [
                "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token", # Direct token path
                "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
                "http://169.254.169.254/computeMetadata/v1/",
                "http://localhost:8080" # Local service
            ]
            
            # OPTIMIZED: Reduced timeout from 5s to 2s
            timeout = aiohttp.ClientTimeout(total=2)
            
            async def test_single_payload(session, param, payload):
                """Test a single SSRF payload (for parallel execution)"""
                try:
                    test_url = f"{url}?{param}={payload}"
                    async with session.get(test_url, allow_redirects=False) as response:
                        text = await response.text()
                        logger.info(f"[DEBUG-SSRF] Checking {test_url} -> Status: {response.status}, Len: {len(text)}")
                        if len(text) < 500: logger.info(f"[DEBUG-SSRF] Body snippet: {text[:100]}")
                        
                        # Check for metadata service indicators or exact 200 OK on internal services
                        if response.status == 200 and (
                            any(indicator in text.lower() for indicator in ["computemetadata", "service-accounts", "access_token", "google cloud sdk"]) or 
                            ("metadata" in payload and "google" in text.lower())
                        ):
                            return {
                                "severity": "CRITICAL",
                                "issue": "Server-Side Request Forgery (SSRF)",
                                "description": f"SSRF vulnerability detected in {resource_type} '{resource_name}'. The application fetches external URLs without validation, allowing access to internal metadata service.",
                                "resource_name": resource_name,
                                "url": url,
                                "parameter": param,
                                "payload": payload,
                                "recommendation": f"Implement strict URL validation in {resource_name}. Block access to private IP ranges (169.254.0.0/16, 127.0.0.0/8, 10.0.0.0/8) and metadata endpoints. Use allowlists for external URLs.",
                                "detection_tool": "ssrf_scanner"
                            }
                except (asyncio.TimeoutError, Exception) as e:
                    logger.debug(f"[DEBUG-SSRF] Payload check failed for {test_url}: {e}")
                return None
            
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # OPTIMIZED: Run all tests in parallel instead of sequential
                tasks = []
                for param in param_names:
                    for payload in ssrf_payloads:
                        tasks.append(test_single_payload(session, param, payload))
                
                # Execute all tests concurrently
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Collect findings (stop at first finding for speed)
                for result in results:
                    if result and isinstance(result, dict):
                        findings.append(result)
                        break  # OPTIMIZED: Early termination on first finding
        
        except ImportError:
            logger.error(f"[GCP] SSRF scanner failed: 'aiohttp' library is missing. Install it with 'pip install aiohttp'")
        except Exception as e:
            logger.error(f"[GCP] SSRF testing failed for {resource_name}: {e}")
        
        return findings
    
    async def _test_idor(self, url: str, resource_name: str, resource_type: str) -> List[Dict]:
        """
        Test for Insecure Direct Object Reference (IDOR) vulnerabilities
        OPTIMIZED: Reduced timeout, limited patterns, early termination
        """
        findings = []
        
        try:
            import aiohttp
            import re
            
            # OPTIMIZED: Reduced timeout from 5s to 2s
            timeout = aiohttp.ClientTimeout(total=2)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # First, discover API endpoints
                try:
                    async with session.get(url) as response:
                        text = await response.text()
                        
                        # Explicit GCPGoat patterns + dynamic discovery
                        explicit_patterns = ["/api/blog/1", "/api/users/1", "/api/posts/1", "/user/profile/1"]
                        found_patterns = re.findall(r'["\']([/\w-]+/\d+)["\']', text)
                        id_patterns = list(set(explicit_patterns + found_patterns))
                        
                        if id_patterns:
                            # OPTIMIZED: Test only 3 unique patterns (was 5)
                            for endpoint_path in set(id_patterns[:3]):
                                # Extract the numeric ID
                                match = re.search(r'/(\d+)$', endpoint_path)
                                if match:
                                    original_id = int(match.group(1))
                                    # OPTIMIZED: Test only 2 IDs (was 4)
                                    test_ids = [original_id + 1, original_id - 1]
                                    
                                    original_response = None
                                    try:
                                        test_url = url.rstrip('/') + endpoint_path
                                        async with session.get(test_url) as resp:
                                            original_response = await resp.text()
                                            original_status = resp.status
                                    except:
                                        continue
                                    
                                    # Test with different IDs
                                    for test_id in test_ids:
                                        try:
                                            modified_path = re.sub(r'/\d+$', f'/{test_id}', endpoint_path)
                                            test_url = url.rstrip('/') + modified_path
                                            
                                            async with session.get(test_url) as resp:
                                                test_response = await resp.text()
                                                test_status = resp.status
                                                
                                                # If we get a 200 and different content, it's likely IDOR
                                                logger.info(f"[DEBUG-IDOR] Testing {test_url} -> Status: {test_status}")
                                                
                                                if test_status == 200 and test_response != original_response and len(test_response) > 50:
                                                    findings.append({
                                                        "severity": "HIGH",
                                                        "issue": "Insecure Direct Object Reference (IDOR)",
                                                        "description": f"IDOR vulnerability detected in {resource_type} '{resource_name}'. Endpoint '{endpoint_path}' allows unauthorized access to other users' data by manipulating the ID parameter.",
                                                        "resource_name": resource_name,
                                                        "url": url,
                                                        "vulnerable_endpoint": endpoint_path,
                                                        "recommendation": f"Implement proper authorization checks in {resource_name}. Verify that the authenticated user has permission to access the requested resource ID. Use indirect references or session-based access control.",
                                                        "detection_tool": "idor_scanner"
                                                    })
                                                    return findings  # OPTIMIZED: Early termination
                                        except:
                                            pass
                
                except Exception as e:
                    logger.debug(f"[GCP] IDOR endpoint discovery failed: {e}")
        
        except ImportError:
            logger.error(f"[GCP] IDOR scanner failed: 'aiohttp' library is missing. Install it with 'pip install aiohttp'")
        except Exception as e:
            logger.error(f"[GCP] IDOR testing failed for {resource_name}: {e}")
        
        return findings
    
    async def _test_sensitive_data_exposure(self, url: str, resource_name: str, resource_type: str) -> List[Dict]:
        """Test for sensitive data exposure in responses"""
        findings = []
        
        try:
            import aiohttp
            import re
            
            timeout = aiohttp.ClientTimeout(total=5)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                try:
                    async with session.get(url) as response:
                        text = await response.text()
                        headers = response.headers
                        
                        # Check for exposed secrets in response
                        secret_patterns = {
                            "GCP Service Account Key": r'"type":\s*"service_account"',
                            "GCP API Key": r'AIza[0-9A-Za-z\\-_]{35}',
                            "AWS Access Key": r'AKIA[0-9A-Z]{16}',
                            "Private Key": r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
                            "Password in Response": r'(?i)"?(password|passwd|secret|pass)"?\s*[:=]\s*"?[^"]{3,}"?',
                            "API Token": r'"(api[_-]?token|access[_-]?token|auth[_-]?token)"\s*:\s*"[^"]{10,}"',
                            "Database Connection": r'(mongodb|mysql|postgres|postgresql|db_user|db_pass)://[^\s"\']+',
                            "JWT Token": r'eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+',
                            "Password Reset Token": r'(reset_token|password_reset|token)=([a-zA-Z0-9.\-_]{15,})',
                            "GCP SDK Key": r'\"private_key\": \"-----BEGIN PRIVATE KEY'
                        }
                        
                        for secret_type, pattern in secret_patterns.items():
                            matches = re.findall(pattern, text, re.IGNORECASE)
                            if matches:
                                findings.append({
                                    "severity": "CRITICAL",
                                    "issue": f"Sensitive Data Exposure: {secret_type}",
                                    "description": f"Sensitive data ({secret_type}) exposed in {resource_type} '{resource_name}' response. Found {len(matches)} instance(s).",
                                    "resource_name": resource_name,
                                    "url": url,
                                    "recommendation": f"Remove all sensitive data from API responses in {resource_name}. Never expose credentials, private keys, or tokens in HTTP responses. Use environment variables and secret management services.",
                                    "detection_tool": "secret_scanner"
                                })
                        
                        # Check for stack traces or error messages
                        error_indicators = [
                            "Traceback (most recent call last)",
                            "at com.google.cloud",
                            "Exception in thread",
                            "java.lang.Exception",
                            "Error: ENOENT",
                            "SyntaxError:",
                            "TypeError:",
                            "Internal Server Error"
                        ]
                        
                        for indicator in error_indicators:
                            if indicator in text:
                                findings.append({
                                    "severity": "MEDIUM",
                                    "issue": "Verbose Error Messages",
                                    "description": f"Detailed error messages or stack traces exposed in {resource_type} '{resource_name}'. This can reveal internal application structure.",
                                    "resource_name": resource_name,
                                    "url": url,
                                    "recommendation": f"Implement custom error pages in {resource_name}. Log detailed errors server-side but return generic error messages to users.",
                                    "detection_tool": "error_scanner"
                                })
                                break
                        
                        # Check security headers
                        missing_headers = []
                        if 'Content-Security-Policy' not in headers:
                            missing_headers.append('Content-Security-Policy')
                        if 'X-Content-Type-Options' not in headers:
                            missing_headers.append('X-Content-Type-Options')
                        if 'X-Frame-Options' not in headers:
                            missing_headers.append('X-Frame-Options')
                        
                        if missing_headers:
                            findings.append({
                                "severity": "LOW",
                                "issue": "Missing Security Headers",
                                "description": f"{resource_type} '{resource_name}' is missing security headers: {', '.join(missing_headers)}",
                                "resource_name": resource_name,
                                "url": url,
                                "recommendation": f"Add security headers to {resource_name}: Content-Security-Policy, X-Content-Type-Options: nosniff, X-Frame-Options: DENY",
                                "detection_tool": "header_scanner"
                            })
                
                except Exception as e:
                    logger.debug(f"[GCP] Sensitive data check failed: {e}")
        
        except Exception as e:
            logger.debug(f"[GCP] Sensitive data exposure testing failed for {resource_name}: {e}")
        
        return findings
    
    async def _test_password_reset(self, url: str, resource_name: str, resource_type: str) -> List[Dict]:
        """
        Test for password reset vulnerabilities
        OPTIMIZED: Reduced timeout, limited endpoints, early termination
        """
        findings = []
        
        try:
            import aiohttp
            import re
            
            # OPTIMIZED: Reduced timeout from 5s to 2s
            timeout = aiohttp.ClientTimeout(total=2)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                # OPTIMIZED: Test only 3 most common endpoints (was 6)
                reset_endpoints = [
                    '/reset',
                    '/forgot-password',
                    '/api/reset'
                ]
                
                for endpoint in reset_endpoints:
                    try:
                        test_url = url.rstrip('/') + endpoint
                        
                        # Test 1: Check if endpoint exists and accepts requests
                        async with session.get(test_url) as response:
                            if response.status in [200, 201, 302]:
                                text = await response.text()
                                
                                # Test 2: Check for token in URL (insecure)
                                if re.search(r'token=[a-zA-Z0-9]{10,}', test_url):
                                    findings.append({
                                        "severity": "HIGH",
                                        "issue": "Password Reset Token in URL",
                                        "description": f"Password reset functionality in {resource_type} '{resource_name}' exposes reset tokens in URL parameters, which can be leaked via browser history or referrer headers.",
                                        "resource_name": resource_name,
                                        "url": test_url,
                                        "recommendation": f"Send password reset tokens via POST body or email only in {resource_name}. Never include sensitive tokens in URL parameters.",
                                        "detection_tool": "auth_scanner"
                                    })
                                    return findings  # OPTIMIZED: Early termination
                                
                                # Test 3: Try to request reset for multiple users (account enumeration)
                                # OPTIMIZED: Skip this test if we already found a vulnerability
                                test_emails = ["test@example.com", "nonexistent@example.com"]
                                responses = []
                                
                                for email in test_emails:
                                    try:
                                        async with session.post(test_url, json={"email": email}) as resp:
                                            responses.append({
                                                "email": email,
                                                "status": resp.status,
                                                "text": await resp.text()
                                            })
                                    except:
                                        pass
                                
                                # If responses differ, account enumeration is possible
                                if len(responses) == 2 and (
                                    responses[0]["status"] != responses[1]["status"] or
                                    len(responses[0]["text"]) != len(responses[1]["text"])
                                ):
                                    findings.append({
                                        "severity": "MEDIUM",
                                        "issue": "Account Enumeration via Password Reset",
                                        "description": f"Password reset endpoint in {resource_type} '{resource_name}' reveals whether an email exists in the system through different responses.",
                                        "resource_name": resource_name,
                                        "url": test_url,
                                        "recommendation": f"Return the same response for both existing and non-existing accounts in {resource_name}. Use generic messages like 'If the email exists, a reset link has been sent.'",
                                        "detection_tool": "auth_scanner"
                                    })
                                    return findings  # OPTIMIZED: Early termination
                    
                    except Exception as e:
                        logger.debug(f"[GCP] Password reset test failed for {endpoint}: {e}")
        
        except Exception as e:
            logger.debug(f"[GCP] Password reset testing failed for {resource_name}: {e}")
        
        return findings

    async def _full_scan(self, project_id: str = None, account_id: str = None, deep_scan: bool = False, offensive_scan: bool = False) -> Dict[str, Any]:
        """Perform full GCP security scan"""
        logger.info(f"[GCP] Starting full scan (deep={deep_scan})...")
        
        # Support account_id as alias for project_id
        project_id = project_id or account_id or self.project_id
        
        all_resources = [
            {
                "provider": "gcp",
                "resource_type": "project",
                "name": project_id,
                "config": {"project_id": project_id},
                "is_public": False
            }
        ]
        all_findings = []
        tool_logs = []
        
        try:
            # Check if we are scanning the right project (useful for multi-project credentials)
            try:
                projects_request = self.resource_manager_client.search_projects()
                accessible_projects = [p.project_id for p in projects_request]
                if self.project_id not in accessible_projects and accessible_projects:
                    all_findings.append({
                        "resource": {"provider": "gcp", "resource_type": "scanner_alert", "name": "Project Configuration"},
                        "severity": "LOW",
                        "issue": "Scanning Unlisted Project",
                        "description": f"The current project ID ({self.project_id}) was not found in your accessible projects list. Projects found: {', '.join(accessible_projects)}. You may be scanning the wrong project.",
                        "detection_tool": "system_check"
                    })
            except: pass

            # Helper function to process scanner results
            def process_scanner_result(result, resource_type_prefix):
                res_list = result.get("resources", [])
                findings_list = result.get("findings", [])
                logger.info(f"[GCP] Found {len(res_list)} resources and {len(findings_list)} findings for {resource_type_prefix}")
                
                for res_data in res_list:
                    # Create resource object
                    resource = {
                        "provider": "gcp",
                        "resource_type": res_data.get("type", resource_type_prefix),
                        "name": res_data.get("name", "unknown"),
                        "config": res_data,
                        "is_public": res_data.get("has_public_ip", False)
                    }
                    all_resources.append(resource)
                
                # Add findings
                for finding in findings_list:
                    finding_obj = {
                        "resource": {
                            "provider": "gcp",
                            "resource_type": resource_type_prefix if finding.get("resource_name") != project_id else "project",
                            "name": finding.get("resource_name", project_id),
                            "config": {},
                            "is_public": False
                        },
                        "severity": finding.get("severity", "MEDIUM"),
                        "issue": finding.get("issue", "Unknown Issue"),
                        "description": finding.get("description", ""),
                        "recommendation": finding.get("recommendation", "Review GCP security documentation for remediation steps."),
                        "detection_tool": "gcp_scanner"
                    }
                    all_findings.append(finding_obj)

            if deep_scan:
                # Check for local security tool availability and warn if missing
                from backend.vulnerability.vulnerability_scanner import VulnerabilityScanner
                v_scanner = VulnerabilityScanner()
                missing_tools = []
                for tool in ["nuclei", "gitleaks", "trivy"]:
                    if tool not in v_scanner.tools_available:
                        missing_tools.append(tool)
                
                if missing_tools:
                    all_findings.append({
                        "resource": {"provider": "gcp", "resource_type": "scanner_alert", "name": "Local Environment"},
                        "severity": "MEDIUM",
                        "issue": "Deep Scan Tools Missing",
                        "description": f"The following tools are missing from your PATH: {', '.join(missing_tools)}. XSS, SSRF, and Secret scanning will be skipped.",
                        "detection_tool": "system_check"
                    })
            
            # OPTIMIZED: Run major discovery tasks in parallel
            logger.info("[GCP] Starting parallelized discovery tasks...")
            discovery_tasks = {
                "gcs_bucket": self._discover_gcs_buckets(),
                "compute_instance": self._discover_compute_instances(),
                "iam_resource": self._discover_iam_policies(),
                "firewall_rule": self._discover_network_resources(),
                "cloud_function": self._discover_cloud_functions(),
                "gke_cluster": self._discover_gke_clusters(),
                "bigquery_dataset": self._discover_bigquery_datasets(),
                "cloud_sql": self._discover_sql_instances(),
                "gcr_image": self._discover_artifact_images(),
                "secret": self._discover_secrets(),
                "cloud_run": self._discover_cloud_run_services()
            }
            
            # Execute all discovery tasks simultaneously
            discovery_keys = list(discovery_tasks.keys())
            discovery_results = await asyncio.gather(*discovery_tasks.values(), return_exceptions=True)
            
            # Process results
            for i, result in enumerate(discovery_results):
                key = discovery_keys[i]
                status = "SUCCESS"
                message = "Completed successfully"
                count = 0
                
                if isinstance(result, dict):
                    if "error" in result:
                        status = "FAILED"
                        message = result["error"]
                    else:
                        count = result.get("count", len(result.get("resources", [])))
                        if count == 0:
                            status = "EMPTY"
                            message = "No resources found"
                    
                    process_scanner_result(result, key)
                elif isinstance(result, Exception):
                    status = "FAILED"
                    message = str(result)
                    logger.error(f"[GCP] Discovery task {key} failed: {result}")
                else:
                    status = "FAILED"
                    message = "Unknown error"
                    logger.error(f"[GCP] Discovery task {key} returned unexpected type: {type(result)}")

                tool_logs.append({
                    "tool": key,
                    "status": status,
                    "message": message,
                    "resources_found": count
                })
            
            
            # 12. (NEW) Web Application Vulnerability Scanning (ALWAYS RUN - Critical OWASP Vulnerabilities)
            logger.info("[GCP] Running OWASP web application vulnerability scans...")
            web_scan_result = await self._scan_web_applications(deep_scan=deep_scan)
            
            # Process web app findings
            findings_count = len(web_scan_result.get("findings", []))
            for finding in web_scan_result.get("findings", []):
                finding_obj = {
                    "resource": {
                        "provider": "gcp",
                        "resource_type": "web_application",
                        "name": finding.get("resource_name", "unknown"),
                        "config": {"url": finding.get("url", "")},
                        "is_public": True
                    },
                    "severity": finding.get("severity", "MEDIUM"),
                    "issue": finding.get("issue", "Unknown Issue"),
                    "description": finding.get("description", ""),
                    "recommendation": finding.get("recommendation", "Review application security best practices."),
                    "detection_tool": finding.get("detection_tool", "web_scanner")
                }
                all_findings.append(finding_obj)
            
            tool_logs.append({
                "tool": "web_vulnerability_scanner",
                "status": "SUCCESS" if findings_count > 0 else "EMPTY",
                "message": f"Found {findings_count} web vulnerabilities" if findings_count > 0 else "No web vulnerabilities found",
                "resources_found": findings_count
            })
            
            # Report disabled APIs if any
            for api in web_scan_result.get("disabled_apis", []):
                all_findings.append({
                    "severity": "LOW",
                    "issue": f"GCP API Disabled: {api['name']}",
                    "description": f"The {api['name']} ({api['service']}) is disabled. This prevents the scanner from analyzing resources like {api['resource_type']}.",
                    "resource": {"provider": "gcp", "resource_type": "api", "name": api['service']},
                    "recommendation": f"Go to {api['url']} to enable this API for better security coverage."
                })
            
            logger.info(f"[GCP] Web application scan found {findings_count} vulnerabilities")
            
            # 13. (NEW) Asset Inventory Census (Debugging)
            if not all_resources:
                try:
                    if self.asset_client:
                        census_request = self.asset_client.assets().searchAllResources(scope=f"projects/{self.project_id}", pageSize=1)
                        census_response = census_request.execute()
                        total_assets = len(census_response.get('results', []))
                        if total_assets == 0:
                            all_findings.append({
                                "resource": {"provider": "gcp", "resource_type": "scanner_alert", "name": "API Visibility"},
                                "severity": "MEDIUM",
                                "issue": "Zero Assets Visible",
                                "description": f"Asset Inventory reports 0 resources in project {self.project_id}. This usually means either the project is empty, or the Service Account lacks the 'Cloud Asset Viewer' role.",
                                "detection_tool": "asset_search"
                            })
                except:
                    pass
            
            results = {
                "scan_id": f"gcp-{datetime.utcnow().timestamp()}",
                "project_id": project_id,
                "timestamp": datetime.utcnow().isoformat(),
                "deep_scan": deep_scan,
                "resources": all_resources,
                "findings": all_findings,
                "tool_logs": tool_logs,
                "summary": {
                    "total_resources": len(all_resources),
                    "total_findings": len(all_findings),
                    "critical": len([f for f in all_findings if f["severity"] == "CRITICAL"]),
                    "high": len([f for f in all_findings if f["severity"] == "HIGH"]),
                    "medium": len([f for f in all_findings if f["severity"] == "MEDIUM"])
                }
            }
            
            logger.info(f"[GCP] Scan complete: {len(all_resources)} resources, {len(all_findings)} findings")
            return results
        
        except Exception as e:
            logger.error(f"[GCP] Full scan failed: {e}")
            import traceback
            logger.error(f"[GCP] Traceback: {traceback.format_exc()}")
            return {
                "error": str(e),
                "resources": [],
                "findings": []
            }


def create_gcp_server(config: Dict[str, Any]) -> GCPMCPServer:
    """Factory function to create GCP MCP server"""
    return GCPMCPServer(config)
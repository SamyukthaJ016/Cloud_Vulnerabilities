# backend/mcp_servers/aws_server.py

"""
AWS MCP Server - Dedicated server for AWS security scanning
Implements MCP protocol for AWS cloud resources
"""
import os
from backend.credentials.aws_assume_role import get_aws_session
import boto3
import json
import logging
from typing import Dict, List, Any
from botocore.exceptions import ClientError
from datetime import datetime
from backend.mcp_servers.base_server import mcp_server_manager,MCPMessage
from backend.mcp_servers.base_server import (
    BaseMCPServer,
    MCPTool,
    MCPResource,
    ToolCategory
)
from backend.mcp.mcp_base import CloudResource, SecurityFinding, Severity

logger = logging.getLogger("aws_mcp_server")
DEFAULT_AWS_REGION = os.getenv("DEFAULT_AWS_REGION", "ap-south-1")


class AWSMCPServer(BaseMCPServer):
    """AWS MCP Server - provides tools and resources for AWS security scanning"""
    
    def __init__(self, config: Dict[str, Any]):
        self.session = None
        self.s3 = None
        self.iam = None
        self.ec2 = None
        self.cloudtrail = None
        self.kms = None
        
        super().__init__("aws", config)
        
        # Initialize AWS session
        self._initialize_aws_session()
    
    def _initialize_aws_session(self) -> None:
        """Initialize AWS session with credentials from config"""
        try:
            logger.info(f"[AWS] Initializing session with config: {self.config}")
            
            # Pass self.config as the creds parameter
            self.session = get_aws_session(
                region=self.config.get('region', DEFAULT_AWS_REGION),
                creds=self.config  # Pass the entire config as creds
            )

            self.s3 = self.session.client("s3")
            self.iam = self.session.client("iam")
            self.ec2 = self.session.client("ec2")
            self.cloudtrail = self.session.client("cloudtrail")
            self.kms = self.session.client("kms")
            self.guardduty = self.session.client("guardduty")
            
            # Validate credentials
            self.sts_client = self.session.client('sts')
            identity = self.sts_client.get_caller_identity()
            logger.info(f"[AWS] Session initialized. Account: {identity['Account']}")
            
        except Exception as e:
            logger.error(f"[AWS] Failed to initialize session: {e}")
            raise
    
    def _setup_tools(self) -> None:
        """Setup AWS security scanning tools"""
        
        # Tool 1: Discover S3 Buckets
        self.register_tool(MCPTool(
            name="aws/discover_s3_buckets",
            description="Discover all S3 buckets in the AWS account",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {
                    "include_policy": {
                        "type": "boolean",
                        "description": "Include bucket policies in results",
                        "default": True
                    }
                }
            },
            handler=self._discover_s3_buckets
        ))
        
        # Tool 2: Check S3 Security
        self.register_tool(MCPTool(
            name="aws/check_s3_security",
            description="Check S3 bucket security configurations",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "bucket_name": {
                        "type": "string",
                        "description": "Name of the S3 bucket to check"
                    }
                },
                "required": ["bucket_name"]
            },
            handler=self._check_s3_security
        ))
        
        # Tool 3: Discover IAM Users
        self.register_tool(MCPTool(
            name="aws/discover_iam_users",
            description="Discover all IAM users in the AWS account",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {
                    "include_policies": {
                        "type": "boolean",
                        "description": "Include user policies",
                        "default": True
                    }
                }
            },
            handler=self._discover_iam_users
        ))
        
        # Tool 4: Check IAM Security
        self.register_tool(MCPTool(
            name="aws/check_iam_security",
            description="Check IAM user security configurations",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "IAM username to check"
                    }
                },
                "required": ["username"]
            },
            handler=self._check_iam_security
        ))
        
        # Tool 5: Discover Security Groups
        self.register_tool(MCPTool(
            name="aws/discover_security_groups",
            description="Discover all EC2 security groups",
            category=ToolCategory.DISCOVERY,
            input_schema={
                "type": "object",
                "properties": {}
            },
            handler=self._discover_security_groups
        ))
        
        # Tool 6: Full AWS Scan
        self.register_tool(MCPTool(
            name="aws/full_scan",
            description="Perform a complete AWS security scan",
            category=ToolCategory.VULNERABILITY,
            input_schema={
                "type": "object",
                "properties": {
                    "account_id": {
                        "type": "string",
                        "description": "AWS account ID (default uses current account)"
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
        """Setup AWS resources"""
        
        self.register_resource(MCPResource(
            uri="aws://account/identity",
            name="AWS Account Identity",
            description="Current AWS account identity information",
            mime_type="application/json"
        ))
        
        self.register_resource(MCPResource(
            uri="aws://s3/buckets",
            name="S3 Buckets List",
            description="List of all S3 buckets",
            mime_type="application/json"
        ))
        
        self.register_resource(MCPResource(
            uri="aws://iam/users",
            name="IAM Users List",
            description="List of all IAM users",
            mime_type="application/json"
        ))
    
    async def _fetch_resource_content(self, uri: str) -> str:
        """Fetch content for AWS resources"""
        
        if uri == "aws://account/identity":
            sts = self.session.client("sts")
            identity = sts.get_caller_identity()
            return json.dumps(identity, indent=2)
        
        elif uri == "aws://s3/buckets":
            buckets = self.s3.list_buckets().get("Buckets", [])
            bucket_list = [bucket["Name"] for bucket in buckets]
            return json.dumps({"buckets": bucket_list, "count": len(bucket_list)}, indent=2)
        
        elif uri == "aws://iam/users":
            users = self.iam.list_users().get("Users", [])
            user_list = [user["UserName"] for user in users]
            return json.dumps({"users": user_list, "count": len(user_list)}, indent=2)
        
        else:
            raise ValueError(f"Unknown resource URI: {uri}")
    
    # Tool Handlers
    
    async def _discover_s3_buckets(self, include_policy: bool = True) -> Dict[str, Any]:
        """Discover S3 buckets"""
        logger.info("[AWS] Discovering S3 buckets...")
        
        try:
            response = self.s3.list_buckets()
            buckets = response.get("Buckets", [])
            
            resources = []
            for bucket in buckets:
                bucket_name = bucket["Name"]
                
                # Get bucket location
                try:
                    location = self.s3.get_bucket_location(Bucket=bucket_name)
                    region = location.get("LocationConstraint") or "us-east-1"
                except:
                    region = "unknown"
                
                bucket_data = {
                    "name": bucket_name,
                    "creation_date": bucket["CreationDate"].isoformat(),
                    "region": region
                }
                
                if include_policy:
                    try:
                        policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                        bucket_data["policy"] = json.loads(policy["Policy"])
                    except:
                        bucket_data["policy"] = None
                
                resources.append(bucket_data)
            
            return {
                "resources": resources,
                "count": len(resources),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            logger.error(f"[AWS] S3 discovery failed: {e}")
            return {"error": str(e), "resources": [], "count": 0}
    
    async def _check_s3_security(self, bucket_name: str) -> Dict[str, Any]:
        """Check S3 bucket security"""
        logger.info(f"[AWS] Checking S3 security for {bucket_name}...")
        
        findings = []
        
        try:
            # Check public access
            is_public = False
            try:
                acl = self.s3.get_bucket_acl(Bucket=bucket_name)
                for grant in acl.get("Grants", []):
                    uri = grant.get("Grantee", {}).get("URI", "")
                    if "AllUsers" in uri or "AllAuthenticatedUsers" in uri:
                        is_public = True
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": "Public S3 Bucket",
                            "description": f"Bucket {bucket_name} is publicly accessible via ACL"
                        })
            except:
                pass
            
            # Check encryption
            try:
                encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
            except:
                findings.append({
                    "severity": "HIGH",
                    "issue": "S3 Encryption Disabled",
                    "description": f"Bucket {bucket_name} does not have default encryption enabled"
                })
            
            # Check versioning
            try:
                versioning = self.s3.get_bucket_versioning(Bucket=bucket_name)
                if versioning.get("Status") != "Enabled":
                    findings.append({
                        "severity": "MEDIUM",
                        "issue": "S3 Versioning Disabled",
                        "description": f"Bucket {bucket_name} does not have versioning enabled"
                    })
            except:
                pass
            
            # Check Block Public Access
            try:
                bpa = self.s3.get_public_access_block(Bucket=bucket_name)
                conf = bpa.get("PublicAccessBlockConfiguration", {})
                if not (conf.get("BlockPublicAcls") and conf.get("IgnorePublicAcls") and 
                        conf.get("BlockPublicPolicy") and conf.get("RestrictPublicBuckets")):
                    findings.append({
                        "severity": "HIGH",
                        "issue": "S3 Block Public Access Disabled",
                        "description": f"Bucket {bucket_name} does not have Block Public Access enabled for all settings",
                        "recommendation": "Enable 'Block all public access' for this bucket"
                    })
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                     findings.append({
                        "severity": "HIGH",
                        "issue": "S3 Block Public Access Disabled",
                        "description": f"Bucket {bucket_name} does not have Block Public Access configuration",
                        "recommendation": "Enable 'Block all public access' for this bucket"
                    })
            except Exception:
                pass

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
    
    async def _discover_iam_users(self, include_policies: bool = True) -> Dict[str, Any]:
        """Discover IAM users"""
        logger.info("[AWS] Discovering IAM users...")
        
        try:
            response = self.iam.list_users()
            users = response.get("Users", [])
            
            resources = []
            for user in users:
                username = user["UserName"]
                
                user_data = {
                    "username": username,
                    "created": user["CreateDate"].isoformat(),
                    "arn": user["Arn"]
                }
                
                # Check MFA
                try:
                    mfa_devices = self.iam.list_mfa_devices(UserName=username)
                    user_data["mfa_enabled"] = len(mfa_devices.get("MFADevices", [])) > 0
                except:
                    user_data["mfa_enabled"] = False
                
                if include_policies:
                    try:
                        policies = self.iam.list_attached_user_policies(UserName=username)
                        user_data["policies"] = [p["PolicyArn"] for p in policies.get("AttachedPolicies", [])]
                    except:
                        user_data["policies"] = []
                
                resources.append(user_data)
            
            return {
                "resources": resources,
                "count": len(resources),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            return {"error": str(e), "resources": [], "count": 0}
    
    async def _check_iam_security(self, username: str) -> Dict[str, Any]:
        """Check IAM user security"""
        logger.info(f"[AWS] Checking IAM security for {username}...")
        
        findings = []
        
        try:
            # Check MFA
            try:
                mfa_devices = self.iam.list_mfa_devices(UserName=username)
                if len(mfa_devices.get("MFADevices", [])) == 0:
                    findings.append({
                        "severity": "CRITICAL",
                        "issue": "IAM User Without MFA",
                        "description": f"User {username} does not have MFA enabled"
                    })
            except:
                pass
            
            # Check access keys
            try:
                keys = self.iam.list_access_keys(UserName=username)
                for key in keys.get("AccessKeyMetadata", []):
                    if key["Status"] == "Active":
                        age = (datetime.now(key["CreateDate"].tzinfo) - key["CreateDate"]).days
                        if age > 90:
                            findings.append({
                                "severity": "HIGH",
                                "issue": "Old IAM Access Key",
                                "description": f"Access key for {username} is {age} days old"
                            })
            except:
                pass
            
            return {
                "username": username,
                "findings": findings,
                "severity_count": {
                    "CRITICAL": len([f for f in findings if f["severity"] == "CRITICAL"]),
                    "HIGH": len([f for f in findings if f["severity"] == "HIGH"])
                }
            }
        
        except Exception as e:
            return {"error": str(e), "username": username, "findings": []}
    
    async def _discover_security_groups(self) -> Dict[str, Any]:
        """Discover security groups"""
        logger.info("[AWS] Discovering security groups...")
        
        try:
            response = self.ec2.describe_security_groups()
            groups = response.get("SecurityGroups", [])
            
            resources = []
            for sg in groups:
                resources.append({
                    "group_id": sg["GroupId"],
                    "group_name": sg["GroupName"],
                    "vpc_id": sg.get("VpcId"),
                    "ingress_rules": len(sg.get("IpPermissions", [])),
                    "egress_rules": len(sg.get("IpPermissionsEgress", []))
                })
            
            return {
                "resources": resources,
                "count": len(resources),
                "timestamp": datetime.utcnow().isoformat()
            }
        
        except Exception as e:
            return {"error": str(e), "resources": [], "count": 0}

    async def _check_cloudtrail(self) -> List[Dict[str, Any]]:
        """Check CloudTrail configuration"""
        logger.info("[AWS] Checking CloudTrail configuration...")
        findings = []
        try:
            trails_response = self.cloudtrail.describe_trails()
            trails = trails_response.get("trailList", [])
            
            if not trails:
                findings.append({
                    "severity": "CRITICAL",
                    "issue": "No CloudTrail Configured",
                    "description": "No CloudTrail trails found in the region. Auditing is disabled.",
                    "resource_name": "Account Level",
                    "recommendation": "Enable CloudTrail in all regions to track API activity."
                })
                return findings
            
            # Check if logging is enabled for at least one trail
            logging_enabled = False
            for trail in trails:
                try:
                    status = self.cloudtrail.get_trail_status(Name=trail["TrailARN"])
                    if status.get("IsLogging"):
                        logging_enabled = True
                        break
                except Exception:
                    continue
            
            if not logging_enabled:
                findings.append({
                    "severity": "HIGH",
                    "issue": "CloudTrail Logging Disabled",
                    "description": "CloudTrail exists but logging is disabled on all trails.",
                    "resource_name": "Account Level",
                    "recommendation": "Enable logging for your CloudTrail trails."
                })

        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                findings.append({
                    "severity": "MEDIUM",  # Medium because it blocks visibility, not necessarily a vul
                    "issue": "Scan Permission Missing (CloudTrail)",
                    "description": "Scanner does not have permission to list CloudTrails.",
                    "resource_name": "Account Level",
                    "recommendation": "Add `cloudtrail:DescribeTrails` and `cloudtrail:GetTrailStatus` to IAM policy."
                })
            else:
                logger.error(f"CloudTrail check failed: {e}")
        except Exception as e:
            logger.error(f"CloudTrail check failed: {e}")
        return findings

    async def _check_guardduty(self) -> List[Dict[str, Any]]:
        """Check GuardDuty configuration"""
        logger.info("[AWS] Checking GuardDuty configuration...")
        findings = []
        try:
            detectors_response = self.guardduty.list_detectors()
            detectors = detectors_response.get("DetectorIds", [])
            
            if not detectors:
                findings.append({
                    "severity": "HIGH",
                    "issue": "GuardDuty Not Enabled",
                    "description": "Amazon GuardDuty is not enabled in this region.",
                    "resource_name": "Account Level",
                    "recommendation": "Enable GuardDuty to detect potential threats."
                })
            else:
                 # Check if enabled
                 for detector_id in detectors:
                    try:
                        detector = self.guardduty.get_detector(DetectorId=detector_id)
                        if detector.get("Status") != "ENABLED":
                            findings.append({
                                "severity": "HIGH",
                                "issue": "GuardDuty Disabled",
                                "description": f"GuardDuty detector {detector_id} is disabled.",
                                "resource_name": f"GuardDuty-{detector_id}",
                                "recommendation": "Enable the GuardDuty detector."
                            })
                    except Exception:
                        continue
        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDenied':
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Scan Permission Missing (GuardDuty)",
                    "description": "Scanner does not have permission to list GuardDuty detectors.",
                    "resource_name": "Account Level",
                    "recommendation": "Add `guardduty:ListDetectors` to IAM policy."
                })
            # Check for SubscriptionRequiredException (GuardDuty not enabled) caught by generic Exception usually, but ensuring here
            elif "SubscriptionRequiredException" in str(e):
                  findings.append({
                    "severity": "HIGH",
                    "issue": "GuardDuty Not Enabled",
                    "description": "Amazon GuardDuty is not enabled/subscribed in this region.",
                    "resource_name": "Account Level",
                    "recommendation": "Enable GuardDuty to detect potential threats."
                })
            else:
                logger.error(f"GuardDuty check failed: {e}")

        except Exception as e:
             # Check for SubscriptionRequiredException (GuardDuty not enabled)
             error_str = str(e)
             if "SubscriptionRequiredException" in error_str:
                 findings.append({
                    "severity": "HIGH",
                    "issue": "GuardDuty Not Enabled",
                    "description": "Amazon GuardDuty is not enabled/subscribed in this region.",
                    "resource_name": "Account Level",
                    "recommendation": "Enable GuardDuty to detect potential threats."
                })
             else:
                logger.error(f"GuardDuty check failed: {e}")
        return findings

    async def _check_vpc_flow_logs(self) -> List[Dict[str, Any]]:
        """Check VPC Flow Logs configuration"""
        logger.info("[AWS] Checking VPC Flow Logs...")
        findings = []
        try:
            vpcs_response = self.ec2.describe_vpcs()
            vpcs = vpcs_response.get("Vpcs", [])
            
            for vpc in vpcs:
                vpc_id = vpc["VpcId"]
                # Check flow logs for this VPC
                try:
                    flow_logs_response = self.ec2.describe_flow_logs(
                        Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
                    )
                    flow_logs = flow_logs_response.get("FlowLogs", [])
                    
                    if not flow_logs:
                        findings.append({
                            "severity": "MEDIUM",
                            "issue": "VPC Flow Logs Disabled",
                            "description": f"VPC {vpc_id} does not have Flow Logs enabled.",
                            "resource_name": vpc_id,
                            "recommendation": "Enable VPC Flow Logs for network traffic analysis."
                        })
                except Exception as e:
                    logger.error(f"Failed to check flow logs for VPC {vpc_id}: {e}")

        except ClientError as e:
             if e.response['Error']['Code'] == 'AccessDenied':
                findings.append({
                    "severity": "MEDIUM",
                    "issue": "Scan Permission Missing (VPC Flow Logs)",
                    "description": "Scanner does not have permission to describe VPCs or Flow Logs.",
                    "resource_name": "Account Level",
                    "recommendation": "Add `ec2:DescribeVpcs` and `ec2:DescribeFlowLogs` to IAM policy."
                })
             else:
                logger.error(f"VPC Flow Logs check failed: {e}")

        except Exception as e:
             logger.error(f"VPC Flow Logs check failed: {e}")
        return findings

    async def _full_scan(self,account_id: str = "default",deep_scan: bool = False,offensive_scan: bool = False,include_cloudfox: bool | None = None) -> Dict[str, Any]:

        """Perform full AWS security scan with CloudFox integration"""
        if include_cloudfox is None:
            include_cloudfox = offensive_scan

        logger.info(f"[AWS] Starting full scan (deep={deep_scan}, cloudfox={include_cloudfox})...")
        
        results = {
            "scan_id": f"aws-{datetime.utcnow().timestamp()}",
            "account_id": account_id,
            "timestamp": datetime.utcnow().isoformat(),
            "deep_scan": deep_scan,
            "cloudfox_included": include_cloudfox,
            "resources": {},
            "findings": [],
            "cloudfox_findings": [],  # NEW: Separate CloudFox findings
            "summary": {}
        }
    
        try:
            # 1. Discover S3
            s3_result = await self._discover_s3_buckets()
            s3_res_list = []
            for r in s3_result.get("resources", []):
                res = {
                    "provider": "aws",
                    "resource_type": "s3_bucket",
                    "name": r["name"],
                    "region": r.get("region", "us-east-1"),
                    "config": r
                }
                s3_res_list.append(res)
            
            # 2. Check S3 security
            for res_dict in s3_res_list:
                security_check = await self._check_s3_security(res_dict["name"])
                # Attach resource to findings
                for f in security_check.get("findings", []):
                    f["resource"] = res_dict
                results["findings"].extend(security_check.get("findings", []))
            
            # Prepare final resource list for main.py storage
            all_resources = s3_res_list

            # 3. Discover IAM
            iam_result = await self._discover_iam_users()
            iam_res_list = []
            for r in iam_result.get("resources", []):
                res = {
                    "provider": "aws",
                    "resource_type": "iam_user",
                    "name": r["username"],
                    "region": "global",
                    "config": r
                }
                iam_res_list.append(res)
            all_resources.extend(iam_res_list)
        
            # 4. Check IAM security
            for res_dict in iam_res_list:
                security_check = await self._check_iam_security(res_dict["name"])
                for f in security_check.get("findings", []):
                    f["resource"] = res_dict
                results["findings"].extend(security_check.get("findings", []))
        
            # 5. Discover security groups
            sg_result = await self._discover_security_groups()
            for r in sg_result.get("resources", []):
                all_resources.append({
                    "provider": "aws",
                    "resource_type": "security_group",
                    "name": r["group_id"],
                    "region": r.get("region", "us-east-1"),
                    "config": r
                })

            # Create Account Level resource for generic findings
            account_resource = {
                "provider": "aws",
                "resource_type": "account",
                "name": "Account Level",
                "region": "global",
                "config": {"account_id": account_id}
            }
            all_resources.append(account_resource)
            
            # --- NEW: Logging & Monitoring Checks ---
            
            # 6. Check CloudTrail
            cloudtrail_findings = await self._check_cloudtrail()
            for f in cloudtrail_findings:
                f["resource"] = account_resource
                f["issue"] = f"[AWS-LOGGING-SCANNER] {f['issue']}"
            results["findings"].extend(cloudtrail_findings)
            
            # 7. Check GuardDuty
            guardduty_findings = await self._check_guardduty()
            for f in guardduty_findings:
                f["resource"] = account_resource
                f["issue"] = f"[AWS-LOGGING-SCANNER] {f['issue']}"
            results["findings"].extend(guardduty_findings)
            
            # 8. Check VPC Flow Logs
            vpc_findings = await self._check_vpc_flow_logs()
            for f in vpc_findings:
                # If finding specified a resource_name (vpc-id), try to match or use account
                res_name = f.get("resource_name", "Account Level")
                if res_name != "Account Level":
                     # Create a temporary VPC resource for storage if not exists
                     vpc_res = {
                         "provider": "aws",
                         "resource_type": "vpc",
                         "name": res_name,
                         "region": self.config.get("region", "us-east-1"),
                         "config": {"vpc_id": res_name}
                     }
                     all_resources.append(vpc_res)
                     f["resource"] = vpc_res
                else:
                    f["resource"] = account_resource
                f["issue"] = f"[AWS-LOGGING-SCANNER] {f['issue']}"
            results["findings"].extend(vpc_findings)

            results["resources"] = all_resources

        # 9. RUN CLOUDFOX IF ENABLED
            if include_cloudfox:
                try:
                    cloudfox_results = await self._run_cloudfox_scan()
                    results["cloudfox_findings"] = cloudfox_results.get("findings", [])
                    results["cloudfox_summary"] = cloudfox_results.get("summary", {})
                    logger.info(f"[AWS] CloudFox scan completed: {len(results['cloudfox_findings'])} findings")
                except Exception as e:
                    logger.error(f"[AWS] CloudFox scan failed: {e}")
                    results["cloudfox_error"] = str(e)
        
        # 10. Combine all findings
            all_findings = results["findings"] + results.get("cloudfox_findings", [])
        
        # 11. Summary
            results["summary"] = {
                "total_resources": len(results["resources"]),
                "total_findings": len(all_findings),
                "aws_findings": len(results["findings"]),
                "cloudfox_findings": len(results.get("cloudfox_findings", [])),
                "critical": len([f for f in all_findings if f.get("severity") == "CRITICAL"]),
                "high": len([f for f in all_findings if f.get("severity") == "HIGH"]),
                "medium": len([f for f in all_findings if f.get("severity") == "MEDIUM"]),
                "low": len([f for f in all_findings if f.get("severity") == "LOW"])
            }
        
        # Add CloudFox findings to main findings list
            results["findings"].extend(results.get("cloudfox_findings", []))
        
            return results
    
        except Exception as e:
            logger.error(f"[AWS] Full scan failed: {e}")
            results["error"] = str(e)
            return results



    async def _run_cloudfox_scan(self) -> Dict[str, Any]:
        """Run CloudFox offensive scan via MCP server"""
        logger.info("[AWS] Running CloudFox offensive scan...")

        try:
        # ✅ Build MCP message FIRST
            message = MCPMessage(
                method="tools/call",
                params={
                    "name": "cloudfox/offensive_scan",
                    "arguments": {
                        "profile": self.config.get("profile") or os.getenv("AWS_PROFILE", "default"),
                        "region": self.config.get("region", "us-east-1"),
                        "modules": [
                            "secrets",
                            "principals",
                            "endpoints",
                            "role-trusts",
                        ],
                    },
                },
            )

        # ✅ Call CloudFox MCP server
            response = await mcp_server_manager.send_request("cloudfox", message)

            if not response or response.error:
                logger.error(f"[AWS] CloudFox error: {getattr(response, 'error', 'unknown')}")
                return {"findings": [], "summary": {}}

            result = response.result or {}

        # ✅ Normalize CloudFox findings
            formatted_findings = []
            for cf in result.get("findings", []):
                formatted_findings.append({
                    "severity": cf.get("severity", "HIGH"),
                    "issue": f"[CLOUDFOX] {cf.get('title', 'Offensive Finding')}",
                    "description": cf.get("description", ""),
                    "resource": cf.get("resource", {}),
                    "recommendation": cf.get(
                        "recommendation",
                        "Review IAM roles, trust policies, and permissions",
                    ),
                    "source": "cloudfox",
                    "tool": "CLOUDFOX",
                })

            return {
                "findings": formatted_findings,
                "summary": {
                    "total_findings": len(formatted_findings),
                    "by_severity": result.get("severity_breakdown", {}),
                },
                "raw_result": result,
            }

        except Exception as e:
            logger.error(f"[AWS] CloudFox scan failed: {e}")
        return {"findings": [], "summary": {}, "error": str(e)}

# Create AWS MCP server instance
def create_aws_server(config: Dict[str, Any]) -> AWSMCPServer:
    """Factory function to create AWS MCP server"""
    return AWSMCPServer(config)


    

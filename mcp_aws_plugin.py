"""
AWS MCP Plugin - Complete Security Scanner
Implements: discover_resources, check_config, assess_vulnerabilities
"""

import boto3
import logging
from typing import Dict, List, Any
from datetime import datetime, timedelta,timezone
from mcp_base import MCPPlugin, CloudResource, SecurityFinding, Severity

logger = logging.getLogger("aws_mcp_plugin")


class AWSPlugin(MCPPlugin):
    """AWS Security Scanner - Full CSPM capabilities"""

    def __init__(self, credentials: Dict[str, str]):
        super().__init__(credentials)
        self.s3 = boto3.client(
            's3',
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key'),
            region_name=credentials.get('region', 'us-east-1')
        )
        self.iam = boto3.client(
            'iam',
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key')
        )
        self.ec2 = boto3.client(
            'ec2',
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key'),
            region_name=credentials.get('region', 'us-east-1')
        )
        self.cloudtrail = boto3.client(
            'cloudtrail',
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key'),
            region_name=credentials.get('region', 'us-east-1')
        )
        self.kms = boto3.client(
            'kms',
            aws_access_key_id=credentials.get('access_key_id'),
            aws_secret_access_key=credentials.get('secret_access_key'),
            region_name=credentials.get('region', 'us-east-1')
        )

    def _get_provider_name(self) -> str:
        return "aws"

    async def discover_resources(self, account_id: str) -> List[CloudResource]:
        """Tool 1: Discover all AWS resources"""
        logger.info(f"AWS: Discovering resources for account {account_id}")
        resources = []

        # Discover S3 Buckets
        resources.extend(await self._discover_s3_buckets())
        
        # Discover IAM Users
        resources.extend(await self._discover_iam_users())
        
        # Discover EC2 Security Groups
        resources.extend(await self._discover_security_groups())
        
        # Discover CloudTrail
        resources.extend(await self._discover_cloudtrail())
        
        # Discover KMS Keys
        resources.extend(await self._discover_kms_keys())

        logger.info(f"AWS: Discovered {len(resources)} resources")
        return resources
    async def _discover_s3_buckets(self) -> List[CloudResource]:
        """Discover S3 buckets with comprehensive public access detection"""
        resources = []
        try:
            buckets = self.s3.list_buckets().get('Buckets', [])
            for bucket in buckets:
                name = bucket['Name']
            
            # Initialize public detection flags
                is_public = False
                public_reasons = []
            
            # Method 1: Check Public Access Block
                try:
                    pab = self.s3.get_public_access_block(Bucket=name)
                    pab_config = pab.get('PublicAccessBlockConfiguration', {})
                
                # If ANY of these is False, bucket COULD be public
                    block_public_acls = pab_config.get('BlockPublicAcls', False)
                    ignore_public_acls = pab_config.get('IgnorePublicAcls', False)
                    block_public_policy = pab_config.get('BlockPublicPolicy', False)
                    restrict_public_buckets = pab_config.get('RestrictPublicBuckets', False)
                
                    if not (block_public_acls and ignore_public_acls and 
                            block_public_policy and restrict_public_buckets):
                        public_reasons.append("Public Access Block not fully enabled")
                    # Don't set is_public yet, need to check if actually exposed
                
                    pab_status = {
                        'BlockPublicAcls': block_public_acls,
                        'IgnorePublicAcls': ignore_public_acls,
                        'BlockPublicPolicy': block_public_policy,
                        'RestrictPublicBuckets': restrict_public_buckets
                    }
                except self.s3.exceptions.NoSuchPublicAccessBlockConfiguration:
                    # No public access block = potentially public
                    public_reasons.append("No Public Access Block configured")
                    pab_status = None
                except Exception as e:
                    logger.warning(f"Could not check Public Access Block for {name}: {e}")
                    pab_status = None
            
            # Method 2: Check ACL for AllUsers or AllAuthenticatedUsers
                try:
                    acl = self.s3.get_bucket_acl(Bucket=name)
                    for grant in acl.get('Grants', []):
                        grantee = grant.get('Grantee', {})
                        uri = grantee.get('URI', '')
                    
                    # Check for public grants
                        if 'AllUsers' in uri:
                            is_public = True
                            public_reasons.append("ACL grants to AllUsers (anonymous public)")
                        elif 'AllAuthenticatedUsers' in uri:
                            is_public = True
                            public_reasons.append("ACL grants to AllAuthenticatedUsers")
                
                    acl_info = acl.get('Grants', [])
                except Exception as e:
                    logger.warning(f"Could not check ACL for {name}: {e}")
                    acl_info = None
            
            # Method 3: Check Bucket Policy for public statements
                policy = {}
                try:
                    policy_response = self.s3.get_bucket_policy(Bucket=name)
                    import json
                    policy = json.loads(policy_response['Policy'])
                
                # Check if policy has public statements
                    for statement in policy.get('Statement', []):
                        principal = statement.get('Principal', {})
                    
                    # Check for wildcard principal
                        if principal == '*' or principal == {'AWS': '*'}:
                            effect = statement.get('Effect', '')
                            if effect == 'Allow':
                                is_public = True
                                public_reasons.append("Bucket policy allows public access (Principal: *)")
                    
                    # Check for public principal in various formats
                        if isinstance(principal, dict):
                            aws_principal = principal.get('AWS', [])
                            if aws_principal == '*' or (isinstance(aws_principal, list) and '*' in aws_principal):
                                if statement.get('Effect') == 'Allow':
                                    is_public = True
                                    public_reasons.append("Bucket policy allows public AWS access")
                except self.s3.exceptions.NoSuchBucketPolicy:
                    pass  # No policy is fine
                except Exception as e:
                    logger.warning(f"Could not check policy for {name}: {e}")
            
            # Get encryption
                encryption = None
                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=name)
                except self.s3.exceptions.ServerSideEncryptionConfigurationNotFoundError:
                    pass  # No encryption
                except Exception as e:
                    logger.warning(f"Could not check encryption for {name}: {e}")
            
            # Get versioning
                versioning = None
                try:
                    versioning = self.s3.get_bucket_versioning(Bucket=name)
                except Exception as e:
                    logger.warning(f"Could not check versioning for {name}: {e}")
            
            # Get logging
                logging_enabled = False
                try:
                    logging_config = self.s3.get_bucket_logging(Bucket=name)
                    logging_enabled = 'LoggingEnabled' in logging_config
                except Exception as e:
                    logger.warning(f"Could not check logging for {name}: {e}")
            
            # Log public detection
                if is_public:
                    logger.warning(f"🚨 PUBLIC BUCKET DETECTED: {name}")
                    logger.warning(f"   Reasons: {', '.join(public_reasons)}")
                elif public_reasons:
                    logger.info(f"⚠️  Bucket {name} has potential public access (but not confirmed): {', '.join(public_reasons)}")

                resources.append(CloudResource(
                    provider="aws",
                    resource_type="s3_bucket",
                    name=name,
                    config={
                        "policy": policy,
                        "encryption": encryption,
                        "versioning": versioning,
                        "logging": logging_enabled,
                        "public_access_block": pab_status,
                        "acl": acl_info,
                        "public_reasons": public_reasons if public_reasons else None
                    },
                    is_public=is_public
                ))
        except Exception as e:
            logger.error(f"S3 discovery failed: {e}")
    
        return resources
    # async def _discover_s3_buckets(self) -> List[CloudResource]:
    #     """Discover S3 buckets"""
    #     resources = []
    #     try:
    #         buckets = self.s3.list_buckets().get('Buckets', [])
    #         for bucket in buckets:
    #             name = bucket['Name']
                
    #             # Get bucket policy
    #             policy = {}
    #             is_public = False
    #             try:
    #                 policy_response = self.s3.get_bucket_policy(Bucket=name)
    #                 import json
    #                 policy = json.loads(policy_response['Policy'])
    #             except:
    #                 pass
                
    #             # Check public access
    #             try:
    #                 acl = self.s3.get_bucket_acl(Bucket=name)
    #                 is_public = any(
    #                     grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers'
    #                     for grant in acl.get('Grants', [])
    #                 )
    #             except:
    #                 pass
                
    #             # Get encryption
    #             encryption = None
    #             try:
    #                 encryption = self.s3.get_bucket_encryption(Bucket=name)
    #             except:
    #                 pass
                
    #             # Get versioning
    #             versioning = None
    #             try:
    #                 versioning = self.s3.get_bucket_versioning(Bucket=name)
    #             except:
    #                 pass
                
    #             # Get logging
    #             logging_enabled = False
    #             try:
    #                 logging_config = self.s3.get_bucket_logging(Bucket=name)
    #                 logging_enabled = 'LoggingEnabled' in logging_config
    #             except:
    #                 pass

    #             resources.append(CloudResource(
    #                 provider="aws",
    #                 resource_type="s3_bucket",
    #                 name=name,
    #                 config={
    #                     "policy": policy,
    #                     "encryption": encryption,
    #                     "versioning": versioning,
    #                     "logging": logging_enabled
    #                 },
    #                 is_public=is_public
    #             ))
    #     except Exception as e:
    #         logger.error(f"S3 discovery failed: {e}")
        
    #     return resources

    async def _discover_iam_users(self) -> List[CloudResource]:
        """Discover IAM users"""
        resources = []
        try:
            users = self.iam.list_users().get('Users', [])
            for user in users:
                username = user['UserName']
                
                # Get MFA devices
                mfa_devices = self.iam.list_mfa_devices(UserName=username).get('MFADevices', [])
                
                # Get access keys
                access_keys = self.iam.list_access_keys(UserName=username).get('AccessKeyMetadata', [])
                
                # Get user policies
                policies = []
                try:
                    attached_policies = self.iam.list_attached_user_policies(UserName=username)
                    policies = [p['PolicyArn'] for p in attached_policies.get('AttachedPolicies', [])]
                except:
                    pass

                resources.append(CloudResource(
                    provider="aws",
                    resource_type="iam_user",
                    name=username,
                    config={
                        "mfa_enabled": len(mfa_devices) > 0,
                        "access_keys": access_keys,
                        "policies": policies,
                        "created": user.get('CreateDate')
                    }
                ))
        except Exception as e:
            logger.error(f"IAM discovery failed: {e}")
        
        return resources

    async def _discover_security_groups(self) -> List[CloudResource]:
        """Discover EC2 Security Groups"""
        resources = []
        try:
            sgs = self.ec2.describe_security_groups().get('SecurityGroups', [])
            for sg in sgs:
                resources.append(CloudResource(
                    provider="aws",
                    resource_type="security_group",
                    name=sg['GroupName'],
                    config={
                        "group_id": sg['GroupId'],
                        "ingress_rules": sg.get('IpPermissions', []),
                        "egress_rules": sg.get('IpPermissionsEgress', []),
                        "vpc_id": sg.get('VpcId')
                    }
                ))
        except Exception as e:
            logger.error(f"Security group discovery failed: {e}")
        
        return resources

    async def _discover_cloudtrail(self) -> List[CloudResource]:
        """Discover CloudTrail trails"""
        resources = []
        try:
            trails = self.cloudtrail.describe_trails().get('trailList', [])
            for trail in trails:
                name = trail['Name']
                
                # Get trail status
                status = self.cloudtrail.get_trail_status(Name=name)
                
                resources.append(CloudResource(
                    provider="aws",
                    resource_type="cloudtrail",
                    name=name,
                    config={
                        "is_logging": status.get('IsLogging', False),
                        "log_file_validation": trail.get('LogFileValidationEnabled', False),
                        "s3_bucket": trail.get('S3BucketName'),
                        "is_multi_region": trail.get('IsMultiRegionTrail', False)
                    }
                ))
        except Exception as e:
            logger.error(f"CloudTrail discovery failed: {e}")
        
        return resources

    async def _discover_kms_keys(self) -> List[CloudResource]:
        """Discover KMS keys"""
        resources = []
        try:
            keys = self.kms.list_keys().get('Keys', [])[:10]  # Limit for demo
            for key in keys:
                key_id = key['KeyId']
                
                try:
                    key_metadata = self.kms.describe_key(KeyId=key_id)['KeyMetadata']
                    rotation = self.kms.get_key_rotation_status(KeyId=key_id)
                    
                    resources.append(CloudResource(
                        provider="aws",
                        resource_type="kms_key",
                        name=key_metadata.get('KeyId'),
                        config={
                            "key_state": key_metadata.get('KeyState'),
                            "rotation_enabled": rotation.get('KeyRotationEnabled', False),
                            "description": key_metadata.get('Description')
                        }
                    ))
                except:
                    pass
        except Exception as e:
            logger.error(f"KMS discovery failed: {e}")
        
        return resources

    async def check_config(self, resources: List[CloudResource]) -> List[Dict[str, Any]]:
        """Tool 2: Check resource configurations"""
        config_issues = []
        
        for resource in resources:
            if resource.resource_type == "s3_bucket":
                if not resource.config.get("encryption"):
                    config_issues.append({
                        "resource": resource.name,
                        "issue": "No encryption enabled",
                        "type": "s3_encryption"
                    })
                
                if not resource.config.get("versioning", {}).get('Status') == 'Enabled':
                    config_issues.append({
                        "resource": resource.name,
                        "issue": "Versioning disabled",
                        "type": "s3_versioning"
                    })
        
        return config_issues

    async def assess_vulnerabilities(self, resources: List[CloudResource]) -> List[SecurityFinding]:
        """Tool 3: Assess security vulnerabilities"""
        findings = []
        
        for resource in resources:
            # S3 Security Checks
            if resource.resource_type == "s3_bucket":
                findings.extend(self._check_s3_vulnerabilities(resource))
            
            # IAM Security Checks
            elif resource.resource_type == "iam_user":
                findings.extend(self._check_iam_vulnerabilities(resource))
            
            # Security Group Checks
            elif resource.resource_type == "security_group":
                findings.extend(self._check_sg_vulnerabilities(resource))
            
            # CloudTrail Checks
            elif resource.resource_type == "cloudtrail":
                findings.extend(self._check_cloudtrail_vulnerabilities(resource))
            
            # KMS Checks
            elif resource.resource_type == "kms_key":
                findings.extend(self._check_kms_vulnerabilities(resource))
        
        logger.info(f"AWS: Found {len(findings)} security findings")
        return findings

    def _check_s3_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """S3 bucket security checks"""
        findings = []
        
        # Public access
        if resource.is_public:
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.CRITICAL,
                issue="Public S3 Bucket",
                description=f"Bucket {resource.name} is publicly accessible",
                recommendation="Enable 'Block Public Access' settings and review bucket policy",
                compliance=["CIS-2.1.5", "NIST-800-53-AC-3"]
            ))
        
        # No encryption
        if not resource.config.get("encryption"):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.HIGH,
                issue="S3 Encryption Disabled",
                description=f"Bucket {resource.name} does not have default encryption enabled",
                recommendation="Enable AES-256 or KMS encryption for the bucket",
                compliance=["CIS-2.1.1"]
            ))
        
        # No versioning
        if resource.config.get("versioning", {}).get('Status') != 'Enabled':
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.MEDIUM,
                issue="S3 Versioning Disabled",
                description=f"Bucket {resource.name} does not have versioning enabled",
                recommendation="Enable versioning to protect against accidental deletion",
                compliance=["CIS-2.1.3"]
            ))
        
        # No logging
        if not resource.config.get("logging"):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.LOW,
                issue="S3 Access Logging Disabled",
                description=f"Bucket {resource.name} does not have access logging enabled",
                recommendation="Enable server access logging for audit purposes",
                compliance=["CIS-2.1.4"]
            ))
        
        return findings

    def _check_iam_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """IAM user security checks"""
        findings = []
        
        # No MFA
        if not resource.config.get("mfa_enabled"):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.CRITICAL,
                issue="IAM User Without MFA",
                description=f"User {resource.name} does not have MFA enabled",
                recommendation="Enable MFA for all IAM users, especially those with console access",
                compliance=["CIS-1.2", "NIST-800-53-IA-2"]
            ))
        
        # Old access keys
        access_keys = resource.config.get("access_keys", [])
        for key in access_keys:
            if key.get('Status') == 'Active':
                create_date = key.get('CreateDate')

                if create_date:
            # Convert string → datetime (for tests / mocks)
                    if isinstance(create_date, str):
                        try:
                            create_date = datetime.fromisoformat(create_date.replace("Z", "+00:00"))
                        except Exception:
                            create_date = datetime.now(timezone.utc)

            # Ensure timezone aware
                    if create_date.tzinfo is None:
                        create_date = create_date.replace(tzinfo=timezone.utc)

            # Calculate age
                    age_days = (datetime.now(timezone.utc) - create_date).days

                    if age_days > 90:
                        findings.append(SecurityFinding(
                            resource=resource,
                            severity=Severity.HIGH if age_days > 180 else Severity.MEDIUM,
                            issue="Old IAM Access Key",
                            description=f"User {resource.name} has access key older than {age_days} days",
                            recommendation="Rotate access keys every 90 days",
                            compliance=["CIS-1.3"]
                        ))

        
        # Admin policies
        policies = resource.config.get("policies", [])
        if any("AdministratorAccess" in p for p in policies):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.HIGH,
                issue="IAM User with Admin Access",
                description=f"User {resource.name} has AdministratorAccess policy",
                recommendation="Follow principle of least privilege, use roles instead",
                compliance=["CIS-1.16"]
            ))
        
        return findings

    def _check_sg_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """Security group checks"""
        findings = []
        
        ingress_rules = resource.config.get("ingress_rules", [])
        
        for rule in ingress_rules:
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                
                if cidr == '0.0.0.0/0':
                    from_port = rule.get('FromPort')
                    to_port = rule.get('ToPort')
                    
                    # SSH open to world
                    if from_port == 22:
                        findings.append(SecurityFinding(
                            resource=resource,
                            severity=Severity.CRITICAL,
                            issue="SSH Open to World",
                            description=f"Security group {resource.name} allows SSH (port 22) from 0.0.0.0/0",
                            recommendation="Restrict SSH access to specific IP ranges or use bastion hosts",
                            compliance=["CIS-4.1"]
                        ))
                    
                    # RDP open to world
                    if from_port == 3389:
                        findings.append(SecurityFinding(
                            resource=resource,
                            severity=Severity.CRITICAL,
                            issue="RDP Open to World",
                            description=f"Security group {resource.name} allows RDP (port 3389) from 0.0.0.0/0",
                            recommendation="Restrict RDP access to specific IP ranges",
                            compliance=["CIS-4.2"]
                        ))
                    
                    # Database ports
                    if from_port in [3306, 5432, 1433, 27017]:
                        findings.append(SecurityFinding(
                            resource=resource,
                            severity=Severity.HIGH,
                            issue="Database Port Open to World",
                            description=f"Security group {resource.name} allows database port {from_port} from 0.0.0.0/0",
                            recommendation="Restrict database access to application security groups only",
                            compliance=["CIS-4.3"]
                        ))
        
        return findings

    def _check_cloudtrail_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """CloudTrail checks"""
        findings = []
        
        if not resource.config.get("is_logging"):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.CRITICAL,
                issue="CloudTrail Logging Disabled",
                description=f"CloudTrail {resource.name} is not logging",
                recommendation="Enable CloudTrail logging for all regions",
                compliance=["CIS-2.1"]
            ))
        
        if not resource.config.get("log_file_validation"):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.MEDIUM,
                issue="CloudTrail Log Validation Disabled",
                description=f"CloudTrail {resource.name} does not have log file validation enabled",
                recommendation="Enable log file validation to detect tampering",
                compliance=["CIS-2.2"]
            ))
        
        return findings

    def _check_kms_vulnerabilities(self, resource: CloudResource) -> List[SecurityFinding]:
        """KMS key checks"""
        findings = []
        
        if not resource.config.get("rotation_enabled"):
            findings.append(SecurityFinding(
                resource=resource,
                severity=Severity.MEDIUM,
                issue="KMS Key Rotation Disabled",
                description=f"KMS key {resource.name} does not have automatic rotation enabled",
                recommendation="Enable automatic key rotation for customer-managed keys",
                compliance=["CIS-2.8"]
            ))
        
        return findings

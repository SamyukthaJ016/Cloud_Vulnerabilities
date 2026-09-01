"""
Auto-Permission API for AWS IAM Policy Management

This module provides endpoints for automatically granting IAM permissions
to users when they need to assume CloudFormation-created roles.
"""

import logging
from typing import Optional
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel
import boto3
from botocore.exceptions import ClientError

from backend.credentials.manager import CredentialManager
from backend.tenant_security import request_identity

logger = logging.getLogger("auto_permission")
router = APIRouter()
credential_manager = CredentialManager()


class AutoPermissionRequest(BaseModel):
    """Request to auto-grant IAM permission"""
    credential_id: int
    iam_user_name: str
    policy_arn: str
    role_arn: Optional[str] = None
    admin_credential_id: Optional[int] = None


class AutoPermissionResponse(BaseModel):
    """Response from auto-permission grant"""
    success: bool
    message: str
    attached_policy: Optional[str] = None
    error_details: Optional[str] = None
    recommended_cli_command: Optional[str] = None
    trust_relationship_cli_command: Optional[str] = None
    identity_policy_json: Optional[str] = None
    trust_policy_json: Optional[str] = None


@router.post("/auto-grant-permission", response_model=AutoPermissionResponse)
async def auto_grant_permission(request: AutoPermissionRequest, http_request: Request):
    """
    Automatically attach IAM policy to user to grant assume role permission.
    
    This endpoint:
    1. Retrieves user's AWS credentials
    2. Creates IAM client with those credentials
    3. Attaches the CloudFormation scanner policy to the IAM user
    4. Logs the action for audit
    
    Security:
    - Only attaches pre-defined CloudFormation policies
    - Requires explicit user consent (frontend confirmation)
    - Uses user's own credentials (no privilege escalation)
    - Full audit trail
    """
    try:
        identity = request_identity(http_request)
        if not identity:
            raise HTTPException(status_code=401, detail="Authentication required")
        user_id = identity.user_id

        logger.info(f"[AutoPermission] Request to grant permission for user {user_id}")
        logger.info(f"[AutoPermission] IAM User: {request.iam_user_name}, Policy: {request.policy_arn}")
        
        # Validate policy ARN format (security check)
        if not request.policy_arn.startswith("arn:aws:iam::"):
            raise HTTPException(
                status_code=400,
                detail="Invalid policy ARN format"
            )
        
        if "CloudGuard-Scanner-Policy" not in request.policy_arn:
            raise HTTPException(
                status_code=400,
                detail="Only CloudGuard scanner policies can be auto-attached"
            )
        
        # Get credentials for the IAM operation
        # Use admin_credential_id if provided, otherwise use the scanner's own credentials
        op_cred_id = request.admin_credential_id or request.credential_id
        credential = credential_manager.get_credentials(
            credential_id=op_cred_id,
            user_id=user_id
        )
        
        if not credential:
            raise HTTPException(
                status_code=404,
                detail=f"AWS credentials (ID: {op_cred_id}) not found"
            )
        
        logger.info(f"[AutoPermission] Using credentials ID: {op_cred_id} for IAM operation")
        
        # Create IAM client with user's credentials
        session = boto3.Session(
            aws_access_key_id=credential.aws_access_key_id,
            aws_secret_access_key=credential.aws_secret_access_key,
            region_name=credential.aws_region or "us-east-1"
        )
        
        iam = session.client('iam')
        sts = session.client('sts')
        
        # Get caller identity to understand the account context
        try:
            current_identity = sts.get_caller_identity()
            current_account_id = current_identity['Account']
            current_user_arn = current_identity['Arn']
            logger.info(f"[AutoPermission] IAM Operation context: Account={current_account_id}, User={current_user_arn}")
        except Exception as e:
            logger.warning(f"[AutoPermission] Could not get caller identity: {e}")
            current_account_id = None

        if request.role_arn:
            # 1. Identity-based fix (Inline Policy on the User)
            logger.info(f"[AutoPermission] Creating inline policy for role {request.role_arn}")
            policy_document = {
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": request.role_arn
                }]
            }
            
            import json
            iam.put_user_policy(
                UserName=request.iam_user_name,
                PolicyName="CloudGuard-AssumeRole-Permission",
                PolicyDocument=json.dumps(policy_document)
            )
            logger.info(f"[AutoPermission] ✅ Successfully put inline policy for {request.iam_user_name}")

            # 2. Trust-based fix (If Admin credentials are used and it's a SAME-ACCOUNT setup)
            if request.admin_credential_id and current_account_id:
                role_account_id = request.role_arn.split(':')[4]
                
                if current_account_id == role_account_id:
                    logger.info(f"[AutoPermission] Local account detected. Ensuring Trust Relationship on {request.role_arn} is correct.")
                    try:
                        trust_policy = {
                            "Version": "2012-10-17",
                            "Statement": [{
                                "Effect": "Allow",
                                "Principal": { "AWS": f"arn:aws:iam::{current_account_id}:root" },
                                "Action": "sts:AssumeRole",
                                "Condition": {
                                    "StringEquals": { "sts:ExternalId": "CloudGuard-Scanner-Validation" }
                                }
                            }]
                        }
                        
                        role_name = request.role_arn.split('/')[-1]
                        iam.update_assume_role_policy(
                            RoleName=role_name,
                            PolicyDocument=json.dumps(trust_policy)
                        )
                        logger.info(f"[AutoPermission] ✅ Successfully updated Trust Relationship for role {role_name}")
                    except Exception as te:
                        logger.warning(f"[AutoPermission] Failed to update trust policy (might be okay if already correct): {te}")
                else:
                    logger.info(f"[AutoPermission] Cross-account role detected ({role_account_id}). Admin must fix trust manually in target account.")

            applied_method = "put_user_policy + trust_check"
        else:
            # Fallback to attaching the managed policy if role_arn not provided
            logger.info(f"[AutoPermission] Attaching managed policy {request.policy_arn} to user {request.iam_user_name}")
            
            iam.attach_user_policy(
                UserName=request.iam_user_name,
                PolicyArn=request.policy_arn
            )
            logger.info(f"[AutoPermission] ✅ Successfully attached managed policy to {request.iam_user_name}")
            applied_method = "attach_user_policy"
        
        # Log to audit trail
        credential_manager._log_audit(
            credential_id=request.credential_id,
            user_id=user_id,
            action='auto_grant_permission',
            details={
                'iam_user': request.iam_user_name,
                'policy_arn': request.policy_arn,
                'role_arn': request.role_arn,
                'method': applied_method
            }
        )
        
        return AutoPermissionResponse(
            success=True,
            message=f"Permission granted successfully to {request.iam_user_name}",
            attached_policy=request.policy_arn if not request.role_arn else "inline-AssumeRole"
        )
        
    except ClientError as e:
        error_code = e.response['Error']['Code']
        error_message = e.response['Error']['Message']
        
        logger.error(f"[AutoPermission] AWS API error: {error_code} - {error_message}")
        
        import json
        
        # Pre-generate manual fix JSONs
        identity_json = ""
        trust_json = ""
        if request.role_arn:
            identity_json = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Action": "sts:AssumeRole",
                    "Resource": request.role_arn
                }]
            }, indent=4)
            
            # Trust policy might be needed if the error persists
            trust_json = json.dumps({
                "Version": "2012-10-17",
                "Statement": [{
                    "Effect": "Allow",
                    "Principal": { "AWS": f"arn:aws:iam::{request.policy_arn.split(':')[4]}:root" },
                    "Action": "sts:AssumeRole",
                    "Condition": {
                        "StringEquals": { "sts:ExternalId": "CloudGuard-Scanner-Validation" }
                    }
                }]
            }, indent=4)

        # Provide helpful error messages
        if error_code == 'NoSuchEntity':
            detail = f"IAM user '{request.iam_user_name}' not found"
        elif error_code == 'AccessDenied':
            # Check if it was a PutUserPolicy failure
            if 'iam:PutUserPolicy' in error_message:
                detail = f"Your AWS credentials (user: {request.iam_user_name}) don't have permission to modify IAM policies (missing 'iam:PutUserPolicy'). "
                
                # Check for Account ID mismatch (likely cause of Trust Relationship issues)
                if request.role_arn and current_account_id:
                    role_account = request.role_arn.split(':')[4]
                    
                    if current_account_id != role_account:
                        detail += f"⚠️ NOTE: Your IAM User is in account {current_account_id}, but the Role is in account {role_account}. This is a cross-account setup. "
                    else:
                        detail += "Please use an Admin account to grant this permission, or use the 'Console JSON' tab below."
            elif 'sts:AssumeRole' in error_message:
                 detail = "The scanner still cannot assume the role. This usually means the 'Trust Relationship' on the role in AWS is blocking your user. Ensure it trusts your account root."
            else:
                detail = f"Access Denied: {error_message}"
            
            
            # Generate BOTH CLI commands for the user (Step 1 and Step 2)
            if request.role_arn:
                # Step 1: Identity Policy (User side - grants permission to assume role)
                policy_doc = identity_json.replace("\n", "").replace(" ", "")
                identity_cmd = f'aws iam put-user-policy --user-name {request.iam_user_name} --policy-name CloudGuard-AssumeRole-Permission --policy-document \'{policy_doc}\''
                
                # Step 2: Trust Relationship (Role side - allows role to trust the user's account)
                role_name = request.role_arn.split('/')[-1]  # Extract role name from ARN
                trust_doc = trust_json.replace("\n", "").replace(" ", "")
                trust_cmd = f'aws iam update-assume-role-policy --role-name {role_name} --policy-document \'{trust_doc}\''
                
                return AutoPermissionResponse(
                    success=False,
                    message="Authorization Failed (Limited Permissions)",
                    error_details=detail,
                    recommended_cli_command=identity_cmd,
                    trust_relationship_cli_command=trust_cmd,
                    identity_policy_json=identity_json,
                    trust_policy_json=trust_json
                )
        elif error_code == 'InvalidInput':
            detail = f"Invalid policy ARN: {request.policy_arn}"
        else:
            detail = f"AWS error: {error_message}"
        
        return AutoPermissionResponse(
            success=False,
            message="Failed to grant permission",
            error_details=detail,
            identity_policy_json=identity_json,
            trust_policy_json=trust_json
        )
        
    except Exception as e:
        logger.error(f"[AutoPermission] Unexpected error: {e}")
        return AutoPermissionResponse(
            success=False,
            message="Failed to grant permission",
            error_details=str(e)
        )

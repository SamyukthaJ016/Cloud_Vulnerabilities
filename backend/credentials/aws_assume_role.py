import os
import boto3
import logging

logger = logging.getLogger(__name__)

DEFAULT_AWS_REGION = os.getenv("DEFAULT_AWS_REGION", "ap-south-1")

def get_aws_session(region: str = DEFAULT_AWS_REGION, creds: dict = None):
    """
    Get AWS session with optional role assumption.
    
    Args:
        region: AWS region
        creds: Credentials dict with access_key_id, secret_access_key, and optional role_arn
    
    Returns:
        boto3.Session configured with credentials
    """
    if not creds:
        # Use default credentials from environment
        return boto3.Session(region_name=region)
    
    access_key = creds.get('access_key_id')
    secret_key = creds.get('secret_access_key')
    session_token = creds.get('session_token')
    role_arn = creds.get('role_arn')  # Get role ARN from credentials if provided
    
    if not access_key or not secret_key:
        raise ValueError("AWS credentials must include access_key_id and secret_access_key")
    
    # Create base session with provided credentials
    base_session = boto3.Session(
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key,
        aws_session_token=session_token,
        region_name=region
    )
    
    # If role_arn is provided, assume that role
    if role_arn:
        logger.info(f"[AWS] Assuming role: {role_arn}")
        sts = base_session.client('sts')
        
        try:
            assumed = sts.assume_role(
                RoleArn=role_arn,
                RoleSessionName='cloudguard-scanner-session',
                ExternalId='CloudGuard-Scanner-Validation'
            )
            
            # Create session with assumed role credentials
            return boto3.Session(
                aws_access_key_id=assumed['Credentials']['AccessKeyId'],
                aws_secret_access_key=assumed['Credentials']['SecretAccessKey'],
                aws_session_token=assumed['Credentials']['SessionToken'],
                region_name=region
            )
        except Exception as e:
            from botocore.exceptions import ClientError
            if isinstance(e, ClientError) and e.response['Error']['Code'] == 'AccessDenied':
                # Try to get the IAM user ARN to help with auto-fix
                try:
                    identity = sts.get_caller_identity()
                    user_arn = identity.get('Arn', 'unknown')
                    logger.error(f"[AWS] AccessDenied assuming role {role_arn}. Current user: {user_arn}")
                    
                    # Store metadata on the exception for the API to catch
                    e.iam_user_arn = user_arn
                    e.role_arn = role_arn
                    # Guess the policy ARN based on the role name (standard for our CloudFormation)
                    # Example role: arn:aws:iam::809567033449:role/CloudGuardReadOnlyRole-xxx
                    # Example policy: arn:aws:iam::809567033449:policy/CloudGuard-Scanner-Policy-xxx
                    if 'role/' in role_arn:
                        account_id = role_arn.split(':')[4]
                        # Support both direct match and prefixed roles (like CloudGuard-Scanner-xxx-CloudGuardReadOnlyRole-yyy)
                        if 'CloudGuardReadOnlyRole-' in role_arn:
                            role_suffix = role_arn.split('CloudGuardReadOnlyRole-')[-1]
                            e.recommended_policy_arn = f"arn:aws:iam::{account_id}:policy/CloudGuard-Scanner-Policy-{role_suffix}"
                        else:
                            # Fallback if naming convention is totally different
                            e.recommended_policy_arn = f"arn:aws:iam::{account_id}:policy/CloudGuard-Scanner-Policy-Default"
                except Exception:
                    pass
            
            logger.error(f"[AWS] Failed to assume role {role_arn}: {e}")
            raise
    
    # No role assumption needed, return base session
    logger.info("[AWS] Using direct credentials (no role assumption)")
    return base_session

# [file name]: backend/credentials/api.py

"""
Credentials API endpoints
"""

import os
import json
import logging
import secrets
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlencode, quote
from pathlib import Path

from fastapi import APIRouter, HTTPException, Depends, Request, BackgroundTasks
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, validator
from starlette.responses import JSONResponse

from backend.credentials.manager import credential_manager, CloudCredential
from backend.credentials import auto_permission
from backend.user_context import resolve_user_id

logger = logging.getLogger("credentials_api")

router = APIRouter(prefix="/api/credentials", tags=["credentials"])

# Include auto-permission router
router.include_router(auto_permission.router, prefix="/aws", tags=["auto-permission"])


# Request/Response Models
class CredentialBase(BaseModel):
    """Base credential model"""
    user_id: str = Field(default="anonymous")
    credential_name: str = Field(default="default")
    is_default: bool = Field(default=True)


class AWSCredentialRequest(CredentialBase):
    """AWS credential request model"""
    cloud_provider: str = Field(default="aws")
    aws_access_key_id: str
    aws_secret_access_key: str
    aws_region: Optional[str] = Field(default="us-east-1")
    aws_role_arn: Optional[str] = None
    aws_session_token: Optional[str] = None


class OpenAICredentialRequest(CredentialBase):
    """OpenAI credential request model"""
    cloud_provider: str = Field(default="openai")
    openai_api_key: str
    openai_org_id: Optional[str] = None


class GCPCredentialRequest(CredentialBase):
    """GCP credential request model"""
    cloud_provider: str = Field(default="gcp")
    gcp_service_account_json: str  # JSON string
    gcp_project_id: Optional[str] = None


class AzureCredentialRequest(CredentialBase):
    """Azure credential request model"""
    cloud_provider: str = Field(default="azure")
    azure_client_id: str
    azure_client_secret: str
    azure_tenant_id: str
    azure_subscription_id: Optional[str] = None


class CredentialResponse(BaseModel):
    """Credential response model"""
    id: int
    user_id: str
    cloud_provider: str
    credential_name: str
    is_default: bool
    is_valid: bool
    validation_status: str
    validation_message: Optional[str]
    last_used: Optional[datetime]
    created_at: datetime
    aws_role_arn: Optional[str] = None
    aws_access_key_id: Optional[str] = None


class ValidationRequest(BaseModel):
    """Credential validation request"""
    credential_id: int
    user_id: str = Field(default="anonymous")


class ValidationResponse(BaseModel):
    """Validation response"""
    valid: bool
    message: str
    details: Dict[str, Any]


class ScanSessionRequest(BaseModel):
    """Scan session creation request"""
    user_id: str = Field(default="anonymous")
    aws_credential_id: Optional[int] = None
    gcp_credential_id: Optional[int] = None
    openai_credential_id: Optional[int] = None
    azure_credential_id: Optional[int] = None
    scan_config: Dict[str, Any] = Field(default_factory=dict)


class ScanSessionResponse(BaseModel):
    """Scan session response"""
    session_id: str
    expires_at: datetime
    credentials_available: List[str]


# Helper function to get user ID from request
def get_user_id(request: Request) -> str:
    """Extract user ID from request"""
    user_id = resolve_user_id(request)
    logger.info("Resolved credential user_id=%s", user_id)
    return user_id


@router.post("/aws", response_model=CredentialResponse)
async def save_aws_credential(
    request: AWSCredentialRequest,
    bg_tasks: BackgroundTasks,
    user_id: str = Depends(get_user_id)
):
    """Save AWS credentials"""
    try:
        # Override user_id from request with authenticated user
        request.user_id = user_id
        
        # Create CloudCredential object
        credential = CloudCredential(
            user_id=request.user_id,
            cloud_provider=request.cloud_provider,
            credential_name=request.credential_name,
            aws_access_key_id=request.aws_access_key_id,
            aws_secret_access_key=request.aws_secret_access_key,
            aws_region=request.aws_region,
            aws_role_arn=request.aws_role_arn,
            aws_session_token=request.aws_session_token,
            is_default=request.is_default
        )
        
        # Save credential
        credential_id = credential_manager.save_credential(credential)
        
        # Validate in background
        bg_tasks.add_task(
            credential_manager.validate_credential,
            credential
        )
        
        # Return response
        return CredentialResponse(
            id=credential_id,
            user_id=credential.user_id,
            cloud_provider=credential.cloud_provider,
            credential_name=credential.credential_name,
            is_default=credential.is_default,
            is_valid=False,  # Will be updated after validation
            validation_status="pending",
            validation_message=None,
            last_used=None,
            created_at=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Failed to save AWS credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/openai", response_model=CredentialResponse)
async def save_openai_credential(
    request: OpenAICredentialRequest,
    bg_tasks: BackgroundTasks,
    user_id: str = Depends(get_user_id)
):
    """Save OpenAI credentials"""
    try:
        request.user_id = user_id
        
        credential = CloudCredential(
            user_id=request.user_id,
            cloud_provider=request.cloud_provider,
            credential_name=request.credential_name,
            openai_api_key=request.openai_api_key,
            openai_org_id=request.openai_org_id,
            is_default=request.is_default
        )
        
        credential_id = credential_manager.save_credential(credential)
        
        bg_tasks.add_task(
            credential_manager.validate_credential,
            credential
        )
        
        return CredentialResponse(
            id=credential_id,
            user_id=credential.user_id,
            cloud_provider=credential.cloud_provider,
            credential_name=credential.credential_name,
            is_default=credential.is_default,
            is_valid=False,
            validation_status="pending",
            validation_message=None,
            last_used=None,
            created_at=datetime.utcnow()
        )
        
    except Exception as e:
        logger.error(f"Failed to save OpenAI credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/gcp", response_model=CredentialResponse)
async def save_gcp_credential(
    request: GCPCredentialRequest,
    bg_tasks: BackgroundTasks,
    user_id: str = Depends(get_user_id)
):
    """Save GCP credentials"""
    try:
        request.user_id = user_id
        
        # Validate JSON
        try:
            service_account_data = json.loads(request.gcp_service_account_json)
            # Extract project_id from service account JSON if not provided
            if not request.gcp_project_id:
                request.gcp_project_id = service_account_data.get("project_id")
        except json.JSONDecodeError:
            raise HTTPException(status_code=400, detail="Invalid JSON for service account")
        
        credential = CloudCredential(
            user_id=request.user_id,
            cloud_provider=request.cloud_provider,
            credential_name=request.credential_name,
            gcp_service_account_json=request.gcp_service_account_json,
            gcp_project_id=request.gcp_project_id,
            is_default=True # Force default for new uploads
        )
        
        credential_id = credential_manager.save_credential(credential)
        
        bg_tasks.add_task(
            credential_manager.validate_credential,
            credential
        )
        
        logger.info(f"✅ Saved GCP credential {credential_id} for user {user_id} (default=True)")
        
        return CredentialResponse(
            id=credential_id,
            user_id=credential.user_id,
            cloud_provider=credential.cloud_provider,
            credential_name=credential.credential_name,
            is_default=credential.is_default,
            is_valid=False,
            validation_status="pending",
            validation_message=None,
            last_used=None,
            created_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to save GCP credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/", response_model=List[CredentialResponse])
async def get_credentials(
    user_id: str = Depends(get_user_id),
    provider: Optional[str] = None
):
    """Get all credentials for user"""
    try:
        credentials = credential_manager.get_all_user_credentials(user_id, provider)
        
        response = []
        for cred in credentials:
            response.append(CredentialResponse(
                id=cred['id'],
                user_id=cred['user_id'],
                cloud_provider=cred['cloud_provider'],
                credential_name=cred['credential_name'],
                is_default=cred['is_default'],
                is_valid=cred.get('is_valid', False),
                validation_status=cred.get('validation_status', 'pending'),
                validation_message=cred.get('validation_message'),
                last_used=cred.get('last_used'),
                created_at=cred.get('created_at', datetime.utcnow()),
                aws_role_arn=cred.get('aws_role_arn'),
                aws_access_key_id=cred.get('aws_access_key_id')
            ))
        
        return response
        
    except Exception as e:
        logger.error(f"Failed to get credentials: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/validate", response_model=ValidationResponse)
async def validate_credential(request: ValidationRequest):
    """Validate a credential"""
    try:
        credential = credential_manager.get_credentials(
            request.credential_id,
            request.user_id
        )
        
        if not credential:
            raise HTTPException(status_code=404, detail="Credential not found")
        
        result = credential_manager.validate_credential(credential)
        
        return ValidationResponse(
            valid=result['valid'],
            message=result['message'],
            details=result.get('details', {})
        )
        
    except Exception as e:
        logger.error(f"Failed to validate credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{credential_id}")
async def delete_credential(
    credential_id: int,
    user_id: str = Depends(get_user_id)
):
    """Delete a credential"""
    try:
        success = credential_manager.delete_credential(credential_id, user_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Credential not found")
        
        return {"success": True, "message": "Credential deleted"}
        
    except Exception as e:
        logger.error(f"Failed to delete credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{credential_id}/default")
async def set_default_credential(
    credential_id: int,
    user_id: str = Depends(get_user_id)
):
    """Mark a credential as the default for its provider"""
    try:
        success = credential_manager.set_default_credential(credential_id, user_id)

        if not success:
            raise HTTPException(status_code=404, detail="Credential not found")

        return {"success": True, "message": "Credential set as default"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to set default credential: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# @router.post("/session", response_model=ScanSessionResponse)
# async def create_scan_session(request: ScanSessionRequest):
#     """Create a scan session with credentials"""
#     try:
#         credential_ids = {}
        
#         if request.aws_credential_id:
#             credential_ids['aws'] = request.aws_credential_id
#         if request.gcp_credential_id:
#             credential_ids['gcp'] = request.gcp_credential_id
#         if request.openai_credential_id:
#             credential_ids['openai'] = request.openai_credential_id
#         if request.azure_credential_id:
#             credential_ids['azure'] = request.azure_credential_id
        
#         session_id = credential_manager.create_session(
#             request.user_id,
#             credential_ids,
#             request.scan_config
#         )
        
#         credentials_available = list(credential_ids.keys())
        
#         return ScanSessionResponse(
#             session_id=session_id,
#             expires_at=datetime.utcnow(),
#             credentials_available=credentials_available
#         )
        
#     except Exception as e:
#         logger.error(f"Failed to create scan session: {e}")
#         raise HTTPException(status_code=500, detail=str(e))

@router.post("/session", response_model=ScanSessionResponse)
async def create_scan_session(
    request: ScanSessionRequest,
    user_id: str = Depends(get_user_id)
):
    """Create a scan session with credentials"""
    try:
        # 🔥 FORCE session user_id to match credential user_id
        request.user_id = user_id

        credential_ids = {}

        if request.aws_credential_id:
            credential_ids['aws'] = request.aws_credential_id
        if request.gcp_credential_id:
            credential_ids['gcp'] = request.gcp_credential_id
        if request.openai_credential_id:
            credential_ids['openai'] = request.openai_credential_id
        if request.azure_credential_id:
            credential_ids['azure'] = request.azure_credential_id

        session_id = credential_manager.create_session(
            request.user_id,
            credential_ids,
            request.scan_config
        )

        credentials_available = list(credential_ids.keys())

        return ScanSessionResponse(
            session_id=session_id,
            expires_at=datetime.utcnow(),
            credentials_available=credentials_available
        )

    except Exception as e:
        logger.error(f"Failed to create scan session: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/providers/status")
async def get_providers_status(user_id: str = Depends(get_user_id)):
    """Get status of all cloud providers for user"""
    try:
        credentials = credential_manager.get_all_user_credentials(user_id)
        
        providers = {
            'aws': {'configured': False, 'valid': False, 'default_id': None},
            'gcp': {'configured': False, 'valid': False, 'default_id': None},
            'openai': {'configured': False, 'valid': False, 'default_id': None},
            'azure': {'configured': False, 'valid': False, 'default_id': None}
        }
        
        for cred in credentials:
            provider = cred['cloud_provider']
            if provider in providers:
                providers[provider]['configured'] = True
                providers[provider]['valid'] = cred.get('is_valid', False)
                if cred.get('is_default'):
                    providers[provider]['default_id'] = cred['id']
        
        return providers
        
    except Exception as e:
        logger.error(f"Failed to get providers status: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/aws/cloudformation-url")
async def get_cloudformation_url(
    user_id: str = Depends(get_user_id),
    template_url: Optional[str] = None
):
    """
    Generate CloudFormation quick-create console URL for automated role setup.
    
    Args:
        template_url: Optional S3 URL to the CloudFormation template. 
                     If not provided, uses default S3 template.
    
    Returns:
        CloudFormation console URL with pre-filled parameters
    """
    try:
        # Use the public S3 URL for the template
        template_url = "https://cloudguard-cfn-templates.s3.eu-north-1.amazonaws.com/aws-readonly-role.yaml"
        
        # Master Scanner Account ID (fixed - this is the account where the scanner runs)
        master_scanner_account_id = "766363046973"
        
        # Generate unique stack name
        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        stack_name = f"CloudGuard-Scanner-{timestamp}"
        
        region = "us-east-1"
        
        # Build URL with parameters pre-filled (always use master scanner account)
        params = {
            "templateURL": template_url,
            "stackName": stack_name,
            "param_ScannerAccountId": master_scanner_account_id
        }
            
        cfn_url = (
            f"https://console.aws.amazon.com/cloudformation/home"
            f"?region={region}"
            f"#/stacks/quickcreate"
            f"?{urlencode(params)}"
        )
        
        
        return {
            "cloudformation_url": cfn_url,
            "stack_name": stack_name,
            "region": region,
            "detected_account_id": master_scanner_account_id,
            "template_url": template_url,
            "instructions": [
                "🔐 Cross-Account Scanning Setup",
                "This creates a role in YOUR account that the master scanner can assume",
                "Click 'Launch CloudFormation Stack' to open AWS Console",
                "The ScannerAccountId is pre-filled with the master scanner account (766363046973)",
                "The created IAM role is tagged Owner=cloudvul@iitm",
                "Check the IAM acknowledgment box",
                "Click 'Create stack'",
                "Wait for stack creation to complete (~2 minutes)",
                "Copy the 'RoleArn' from the Outputs tab",
                "Paste it into your AWS credential settings in the dashboard"
            ]
        }
        
    except Exception as e:
        logger.error(f"Failed to generate CloudFormation URL: {e}")
        raise HTTPException(status_code=500, detail=str(e))




@router.get("/aws/cloudformation-template", response_class=PlainTextResponse)
async def get_cloudformation_template():
    """
    Download the CloudFormation template for manual deployment.
    
    Returns:
        YAML content of the CloudFormation template
    """
    try:
        # Get the template file path
        template_path = Path(__file__).parent.parent.parent / "infra" / "enhanced-cloudformation-template.yaml"
        
        if not template_path.exists():
            raise HTTPException(
                status_code=404, 
                detail="CloudFormation template not found"
            )
        
        # Read and return the template
        with open(template_path, 'r') as f:
            template_content = f.read()
        
        return template_content
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to read CloudFormation template: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# Test endpoint (for development)
@router.post("/test/connection")
async def test_connection():
    """Test database connection for credentials"""
    try:
        # Try to get connection
        conn = credential_manager._get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.close()
        conn.close()
        
        return {"status": "connected", "message": "Database connection successful"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

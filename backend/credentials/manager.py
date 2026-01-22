# [file name]: backend/credentials/manager.py

"""
Secure Credential Management Module
Handles user credential storage, validation, and usage
"""

import os
import json
import logging
import base64
import secrets
import hashlib
from fastapi import HTTPException
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import psycopg2
from psycopg2.extras import RealDictCursor

logger = logging.getLogger("credential_manager")


@dataclass
class CloudCredential:
    
    user_id: str
    cloud_provider: str
    credential_name: str
    id: Optional[int] = None 
    aws_access_key_id: Optional[str] = None
    aws_secret_access_key: Optional[str] = None
    aws_region: Optional[str] = "us-east-1"
    aws_session_token: Optional[str] = None

    gcp_service_account_json: Optional[str] = None
    gcp_project_id: Optional[str] = None

    openai_api_key: Optional[str] = None
    openai_org_id: Optional[str] = None

    azure_client_id: Optional[str] = None
    azure_client_secret: Optional[str] = None
    azure_tenant_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None

    is_default: bool = False
    is_valid: bool = True



class CredentialManager:
    """Manages secure storage and retrieval of cloud credentials"""
    
    def __init__(self, db_url: Optional[str] = None):
        self.db_url = db_url or os.getenv("DATABASE_URL")
        if not self.db_url:
            raise ValueError("DATABASE_URL environment variable is required")

        # DEV MODE: encryption disabled
        self.encryption_key = None
        self.cipher = None

    def _get_encryption_key(self) -> bytes:
        """
        DEV MODE: no encryption key needed.
        Kept only for compatibility if called somewhere.
        """
        return b""
    
    def encrypt(self, text: str) -> str:
        """DEV MODE: no encryption, store as plain text"""
        if not text:
            return ""
        return text

    def decrypt(self, encrypted_text: str) -> str:
        """DEV MODE: no decryption, value is already plain text"""
        if not encrypted_text:
            return ""
        return encrypted_text
    
    def _get_connection(self):
        """Get database connection"""
        return psycopg2.connect(self.db_url)
    
    def ensure_user(self, user_id: str, email: Optional[str] = None, name: Optional[str] = None) -> str:
        """Ensure user exists, create if not"""
        conn = self._get_connection()
        cur = conn.cursor()
        
        try:
            # Check if user exists
            cur.execute(
                "SELECT user_id FROM user_profiles WHERE user_id = %s",
                (user_id,)
            )
            
            if not cur.fetchone():
                # Create user
                cur.execute(
                    """
                    INSERT INTO user_profiles (user_id, email, name)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE
                    SET last_login = NOW()
                    """,
                    (user_id, email or f"{user_id}@cloudguard.local", name or user_id)
                )
            
            conn.commit()
            return user_id
            
        finally:
            cur.close()
            conn.close()

    def save_credential(self, credential: CloudCredential) -> int:
        """
        Save encrypted credential to database
        Returns credential ID
        """
        conn = self._get_connection()
        cur = conn.cursor()
    
        try:
        # Ensure user exists
            self.ensure_user(credential.user_id)
        
        # Encrypt sensitive fields
            encrypted_credential = asdict(credential)
        
        # Encrypt sensitive data
            if credential.aws_secret_access_key:
                encrypted_credential['aws_secret_access_key'] = self.encrypt(credential.aws_secret_access_key)
            if credential.aws_access_key_id:
                encrypted_credential['aws_access_key_id'] = self.encrypt(credential.aws_access_key_id)
            if credential.aws_session_token:
                encrypted_credential['aws_session_token'] = self.encrypt(credential.aws_session_token)
            if credential.gcp_service_account_json:
                encrypted_credential['gcp_service_account_json'] = self.encrypt(credential.gcp_service_account_json)
            if credential.openai_api_key:
                encrypted_credential['openai_api_key'] = self.encrypt(credential.openai_api_key)
            if credential.azure_client_secret:
                encrypted_credential['azure_client_secret'] = self.encrypt(credential.azure_client_secret)
        
        # Check if credential already exists
            cur.execute(
                """
                SELECT id FROM cloud_credentials 
                WHERE user_id = %s AND cloud_provider = %s AND credential_name = %s
                """,
                (credential.user_id, credential.cloud_provider, credential.credential_name)
            )
        
            existing = cur.fetchone()
            credential_id = None
        
            if existing:
            # Update existing credential
                credential_id = existing[0]
                update_fields = []
                update_values = []
            
                for field, value in encrypted_credential.items():
                    if value is not None and field not in ['user_id', 'cloud_provider', 'credential_name']:
                        update_fields.append(f"{field} = %s")
                        update_values.append(value)
            
                update_values.append(credential_id)
            
                update_query = f"""
                    UPDATE cloud_credentials 
                    SET {', '.join(update_fields)}, updated_at = NOW()
                    WHERE id = %s
                """
            
                cur.execute(update_query, update_values)
            
            else:
            # Insert new credential
                fields = []
                values = []
            
                for field, value in encrypted_credential.items():
                    if value is not None:
                        fields.append(field)
                        values.append(value)
            
                placeholders = ['%s'] * len(fields)
            
                insert_query = f"""
                    INSERT INTO cloud_credentials ({', '.join(fields)})
                    VALUES ({', '.join(placeholders)})
                    RETURNING id
                """
            
                cur.execute(insert_query, values)
                credential_id = cur.fetchone()[0]
        
        # If this is default, unset other defaults for this provider and user
            if credential.is_default:
                cur.execute(
                    """
                    UPDATE cloud_credentials 
                    SET is_default = FALSE 
                    WHERE user_id = %s 
                    AND cloud_provider = %s 
                    AND id != %s
                    """,
                    (credential.user_id, credential.cloud_provider, credential_id)
                )
        
        # Now log the audit AFTER the credential is saved
            conn.commit()
            if credential_id:
                self._log_audit(
                    credential_id,
                    credential.user_id,
                    'create' if not existing else 'update',
                    {'provider': credential.cloud_provider}
                )
        
            
            return credential_id
        
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to save credential: {e}")
            raise
        
        finally:
            cur.close()  # FIXED: Changed 'ur.close()' to 'cur.close()'
            conn.close()
    # def get_user_credentials(self, credential_id: int, user_id: str) -> Optional[CloudCredential]:
    #     """Get and decrypt a specific credential"""
    #     conn = self._get_connection()
    #     cur = conn.cursor(cursor_factory=RealDictCursor)
        
    #     try:
    #         cur.execute(
    #             """
    #             SELECT * FROM cloud_credentials 
    #             WHERE id = %s AND user_id = %s
    #             """,
    #             (credential_id, user_id)
    #         )
            
    #         row = cur.fetchone()
    #         if not row:
    #             return None
            
    #         # Decrypt sensitive fields
    #         credential_dict = dict(row)
            
    #         # Decrypt fields
    #         for field in ['aws_secret_access_key', 'aws_access_key_id', 'aws_session_token',
    #                      'gcp_service_account_json', 'openai_api_key', 'azure_client_secret']:
    #             if credential_dict.get(field):
    #                 try:
    #                     credential_dict[field] = self.decrypt(credential_dict[field])
    #                 except Exception as e:
    #                     logger.warning(f"Failed to decrypt field {field}: {e}")
    #                     credential_dict[field] = None
            
    #         # Update last used
    #         cur.execute(
    #             "UPDATE cloud_credentials SET last_used = NOW() WHERE id = %s",
    #             (credential_id,)
    #         )
            
    #         # Log usage
    #         self._log_audit(
    #             credential_id,
    #             user_id,
    #             'use',
    #             {'provider': credential_dict['cloud_provider']}
    #         )
            
    #         conn.commit()
            
    #         # Convert to CloudCredential object
    #         # Convert to CloudCredential object
    #         credential_dict.pop("id", None)
    #         credential_dict.pop("created_at", None)
    #         credential_dict.pop("updated_at", None)
    #         credential_dict.pop("last_used", None)

    #         return CloudCredential(**credential_dict)

            
    #     finally:
    #         cur.close()
    #         conn.close()
    
    # [file name]: backend/credentials/manager.py (FIXED get_credentials method)

# Replace the existing get_credentials method with this:

    def get_credentials(self, credential_id: int, user_id: str) -> Optional[CloudCredential]:
        """
        🔥 FIXED: Get and decrypt a specific credential by ID
        Returns CloudCredential object with decrypted sensitive fields
        """
        conn = self._get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
    
        try:
            cur.execute(
                """
                SELECT * FROM cloud_credentials 
                WHERE id = %s AND user_id = %s
                """,
                (credential_id, user_id)
            )
        
            row = cur.fetchone()
            if not row:
                logger.warning(f"Credential {credential_id} not found for user {user_id}")
                return None
        
        # Convert to dict
            credential_dict = dict(row)
        
        # 🔥 DECRYPT sensitive fields
            for field in ['aws_secret_access_key', 'aws_access_key_id', 'aws_session_token',
                     'gcp_service_account_json', 'openai_api_key', 'azure_client_secret']:
                if credential_dict.get(field):
                    try:
                        credential_dict[field] = self.decrypt(credential_dict[field])
                    except Exception as e:
                        logger.warning(f"Failed to decrypt field {field}: {e}")
                        credential_dict[field] = None
        
        # 🔥 Remove fields that aren't part of CloudCredential constructor
            fields_to_remove = [
                'created_at', 'updated_at', 'last_used', 'validation_status', 'validation_message',
                'last_validated'
            ]
        
            for field in fields_to_remove:
                if field in credential_dict:
                    del credential_dict[field]
        
        # Update last used timestamp
            cur.execute(
                "UPDATE cloud_credentials SET last_used = NOW() WHERE id = %s",
                (credential_id,)
            )
            conn.commit()
            logger.error(f"FINAL credential_dict keys: {list(credential_dict.keys())}")

        # Convert to CloudCredential object
            return CloudCredential(
                id=credential_dict["id"],
                user_id=credential_dict["user_id"],
                cloud_provider=credential_dict["cloud_provider"],
                credential_name=credential_dict["credential_name"],

                aws_access_key_id=credential_dict["aws_access_key_id"],
                aws_secret_access_key=credential_dict["aws_secret_access_key"],
                aws_region=credential_dict["aws_region"],
                aws_session_token=credential_dict["aws_session_token"],

                gcp_service_account_json=credential_dict["gcp_service_account_json"],
                gcp_project_id=credential_dict["gcp_project_id"],

                openai_api_key=credential_dict["openai_api_key"],
                openai_org_id=credential_dict["openai_org_id"],

                azure_client_id=credential_dict["azure_client_id"],
                azure_client_secret=credential_dict["azure_client_secret"],
                azure_tenant_id=credential_dict["azure_tenant_id"],
                azure_subscription_id=credential_dict["azure_subscription_id"],

                is_default=credential_dict["is_default"],
                is_valid=credential_dict["is_valid"],
            )


        
        except Exception as e:
            logger.error(f"Failed to get credential {credential_id}: {e}")
            return None
        
        finally:
            cur.close()
            conn.close()


    def get_all_user_credentials(self, user_id: str, provider: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get all credentials for a user (sensitive fields omitted)"""
        conn = self._get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
    
        try:
            if provider:
                cur.execute(
                    """
                    SELECT 
                        id, user_id, cloud_provider, credential_name,
                        aws_region, gcp_project_id, openai_org_id,
                        azure_tenant_id, azure_subscription_id,
                        is_default, is_valid, validation_status,
                        validation_message, last_used, created_at,
                        updated_at, last_validated
                    FROM cloud_credentials 
                    WHERE user_id = %s AND cloud_provider = %s
                    ORDER BY is_default DESC, last_used DESC NULLS LAST
                    """,
                    (user_id, provider)
                )
            else:
                cur.execute(
                    """
                    SELECT 
                        id, user_id, cloud_provider, credential_name,
                        aws_region, gcp_project_id, openai_org_id,
                        azure_tenant_id, azure_subscription_id,
                        is_default, is_valid, validation_status,
                        validation_message, last_used, created_at,
                        updated_at, last_validated
                    FROM cloud_credentials 
                    WHERE user_id = %s
                    ORDER BY cloud_provider, is_default DESC, last_used DESC NULLS LAST
                    """,
                    (user_id,)
                )
        
            rows = cur.fetchall()
            return [dict(row) for row in rows]
        
        except Exception as e:
            logger.error(f"Failed to get user credentials: {e}")
            return []
        
        finally:
            cur.close()
            conn.close()
    
    def get_default_credential(self, user_id: str, provider: str) -> Optional[CloudCredential]:
        """Get user's default credential for a provider"""
        conn = self._get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cur.execute(
                """
                SELECT id FROM cloud_credentials 
                WHERE user_id = %s AND cloud_provider = %s AND is_default = TRUE
                LIMIT 1
                """,
                (user_id, provider)
            )
            
            row = cur.fetchone()
            if row:
                return self.get_credentials(row['id'], user_id)
            return None
            
        finally:
            cur.close()
            conn.close()
    
    def delete_credential(self, credential_id: int, user_id: str) -> bool:
        """Delete a credential"""
        conn = self._get_connection()
        cur = conn.cursor()
    
        try:
        # First, check if credential is used in any scan sessions
            cur.execute("""
                SELECT 1 FROM scan_sessions
                WHERE aws_credential_id = %s
                OR gcp_credential_id = %s
                OR openai_credential_id = %s
                OR azure_credential_id = %s
                LIMIT 1
            """, (credential_id, credential_id, credential_id, credential_id))

            if cur.fetchone():
                raise HTTPException(
                    status_code=409,
                    detail="Credential is used in one or more scan sessions"
                )
        
        # Check if credential belongs to user
            cur.execute(
                "SELECT 1 FROM cloud_credentials WHERE id = %s AND user_id = %s",
                (credential_id, user_id)
            )
        
            if not cur.fetchone():
                return False
        
        # Log before deletion
            self._log_audit(credential_id, user_id, 'delete')
            logger.warning(f"⚠️ DELETE CREDENTIAL TRIGGERED: id={credential_id}, user={user_id}")
            import traceback
            logger.info(f"Traceback:\n{''.join(traceback.format_stack())}")
        
        # Delete associated scans first (to clean up history)
            cur.execute(
                "DELETE FROM scans WHERE aws_credential_id = %s",
                (credential_id,)
            )

        # Delete credential
            cur.execute(
                "DELETE FROM cloud_credentials WHERE id = %s AND user_id = %s",
                (credential_id, user_id)
            )
        
            conn.commit()
            return True
        
        except HTTPException:
            raise
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to delete credential: {e}")
            return False
        
        finally:
            cur.close()
            conn.close()
    def validate_credential(self, credential: CloudCredential) -> Dict[str, Any]:
        """
        Validate cloud credential by testing API access
        Returns validation result
        """
        validation_result = {
            'valid': False,
            'message': 'Validation pending',
            'details': {}
        }
        
        try:
            if credential.cloud_provider == 'aws':
                validation_result = self._validate_aws_credential(credential)
            elif credential.cloud_provider == 'openai':
                validation_result = self._validate_openai_credential(credential)
            elif credential.cloud_provider == 'gcp':
                validation_result = self._validate_gcp_credential(credential)
            elif credential.cloud_provider == 'azure':
                validation_result = self._validate_azure_credential(credential)
            else:
                validation_result['message'] = f'Unknown provider: {credential.cloud_provider}'
            
            # Update credential validation status
            self._update_validation_status(
                credential_id=None,  # Will be set after save
                user_id=credential.user_id,
                is_valid=validation_result['valid'],
                message=validation_result['message']
            )
            
        except Exception as e:
            validation_result = {
                'valid': False,
                'message': f'Validation error: {str(e)}',
                'details': {}
            }
        
        return validation_result
    
    def _validate_aws_credential(self, credential: CloudCredential) -> Dict[str, Any]:
        """Validate AWS credentials"""
        try:
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            
            # Try to create a client with the credentials
            session = boto3.Session(
                aws_access_key_id=credential.aws_access_key_id,
                aws_secret_access_key=credential.aws_secret_access_key,
                aws_session_token=credential.aws_session_token,
                region_name=credential.aws_region or 'us-east-1'
            )
            
            # Test STS to get caller identity
            sts = session.client('sts')
            identity = sts.get_caller_identity()
            
            # Test S3 to verify permissions
            s3 = session.client('s3')
            s3.list_buckets()  # Just test if we can call
            
            return {
                'valid': True,
                'message': 'AWS credentials validated successfully',
                'details': {
                    'user_arn': identity['Arn'],
                    'account_id': identity['Account'],
                    'user_id': identity['UserId']
                }
            }
            
        except NoCredentialsError:
            return {
                'valid': False,
                'message': 'No AWS credentials provided',
                'details': {}
            }
        except ClientError as e:
            error_code = e.response['Error']['Code']
            error_msg = e.response['Error']['Message']
            return {
                'valid': False,
                'message': f'AWS validation failed: {error_code} - {error_msg}',
                'details': {}
            }
        except Exception as e:
            return {
                'valid': False,
                'message': f'AWS validation error: {str(e)}',
                'details': {}
            }
    
    def _validate_openai_credential(self, credential: CloudCredential) -> Dict[str, Any]:
        """Validate OpenAI credentials"""
        try:
            from openai import OpenAI
            
            client = OpenAI(
                api_key=credential.openai_api_key,
                organization=credential.openai_org_id
            )
            
            # Test API key by listing models
            models = client.models.list()
            
            return {
                'valid': True,
                'message': 'OpenAI credentials validated successfully',
                'details': {
                    'model_count': len(models.data),
                    'organization': credential.openai_org_id or 'default'
                }
            }
            
        except Exception as e:
            return {
                'valid': False,
                'message': f'OpenAI validation failed: {str(e)}',
                'details': {}
            }
    
    def _validate_gcp_credential(self, credential: CloudCredential) -> Dict[str, Any]:
        """Validate GCP credentials"""
        try:
            from google.oauth2 import service_account
            from google.auth.transport.requests import Request
            
            if credential.gcp_service_account_json:
                # Parse service account JSON
                sa_info = json.loads(credential.gcp_service_account_json)
                
                # Create credentials object
                credentials = service_account.Credentials.from_service_account_info(
                    sa_info,
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
                
                # Refresh token
                credentials.refresh(Request())
                
                return {
                    'valid': True,
                    'message': 'GCP credentials validated successfully',
                    'details': {
                        'client_email': sa_info.get('client_email'),
                        'project_id': sa_info.get('project_id') or credential.gcp_project_id
                    }
                }
            else:
                return {
                    'valid': False,
                    'message': 'No GCP service account JSON provided',
                    'details': {}
                }
                
        except json.JSONDecodeError:
            return {
                'valid': False,
                'message': 'Invalid GCP service account JSON',
                'details': {}
            }
        except Exception as e:
            return {
                'valid': False,
                'message': f'GCP validation failed: {str(e)}',
                'details': {}
            }
    
    def _validate_azure_credential(self, credential: CloudCredential) -> Dict[str, Any]:
        """Validate Azure credentials"""
        try:
            from azure.identity import ClientSecretCredential
            from azure.mgmt.resource import ResourceManagementClient
            
            if not all([credential.azure_client_id, credential.azure_client_secret, credential.azure_tenant_id]):
                return {
                    'valid': False,
                    'message': 'Missing Azure credentials (client_id, client_secret, or tenant_id)',
                    'details': {}
                }
            
            # Create credential object
            credential_obj = ClientSecretCredential(
                tenant_id=credential.azure_tenant_id,
                client_id=credential.azure_client_id,
                client_secret=credential.azure_client_secret
            )
            
            # Test by trying to get subscription
            if credential.azure_subscription_id:
                client = ResourceManagementClient(credential_obj, credential.azure_subscription_id)
                subscriptions = list(client.subscriptions.list())
                
                return {
                    'valid': True,
                    'message': 'Azure credentials validated successfully',
                    'details': {
                        'subscription_id': credential.azure_subscription_id,
                        'subscription_count': len(subscriptions)
                    }
                }
            else:
                # Just validate credentials without subscription
                return {
                    'valid': True,
                    'message': 'Azure credentials validated (subscription not tested)',
                    'details': {}
                }
                
        except Exception as e:
            return {
                'valid': False,
                'message': f'Azure validation failed: {str(e)}',
                'details': {}
            }
    
    def _update_validation_status(self, credential_id: Optional[int], user_id: str, 
                                 is_valid: bool, message: str) -> None:
        """Update credential validation status in database"""
        if not credential_id:
            # This would be called after credential is saved
            return
        
        conn = self._get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute(
                """
                UPDATE cloud_credentials 
                SET 
                    is_valid = %s,
                    validation_status = %s,
                    validation_message = %s,
                    last_validated = NOW()
                WHERE id = %s AND user_id = %s
                """,
                (is_valid, 'valid' if is_valid else 'invalid', message, credential_id, user_id)
            )
            
            conn.commit()
            
        finally:
            cur.close()
            conn.close()
    
    # 
  

    def _log_audit(self, credential_id: int, user_id: str, action: str, details: Optional[Dict] = None) -> None:
        """Log credential action to audit log"""
        conn = self._get_connection()
        cur = conn.cursor()
    
        try:
            cur.execute(
                """
                INSERT INTO credential_audit_log 
                (credential_id, user_id, action, details)
                VALUES (%s, %s, %s, %s)
                """,
                (credential_id, user_id, action, json.dumps(details or {}))
            )
        
            conn.commit()
        
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to log audit: {e}")
        # Don't raise here - audit logging failure shouldn't break main operation
        
        finally:
            cur.close()
            conn.close()

    
    def create_session(self, user_id: str, credential_ids: Dict[str, int], 
                      scan_config: Dict = None) -> str:
        """Create a scan session with credentials"""
        session_id = secrets.token_urlsafe(32)
        
        conn = self._get_connection()
        cur = conn.cursor()
        
        try:
            cur.execute(
                """
                INSERT INTO scan_sessions 
                (session_id, user_id, aws_credential_id, gcp_credential_id, 
                 openai_credential_id, azure_credential_id, scan_config, expires_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, NOW() + INTERVAL '1 hour')
                """,
                (session_id, user_id,
                 credential_ids.get('aws'),
                 credential_ids.get('gcp'),
                 credential_ids.get('openai'),
                 credential_ids.get('azure'),
                 json.dumps(scan_config or {}))
            )
            
            conn.commit()
            return session_id
            
        finally:
            cur.close()
            conn.close()
    
    def get_session_credentials(self, session_id: str) -> Dict[str, Any]:
        """Get credentials for a session"""
        conn = self._get_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        try:
            cur.execute(
                """
                SELECT * FROM scan_sessions 
                WHERE session_id = %s AND status = 'active' 
                AND expires_at > NOW()
                """,
                (session_id,)
            )
            
            session = cur.fetchone()
            if not session:
                return {}
            
            credentials = {}
            
            # Get AWS credential if present
            if session['aws_credential_id']:
                aws_cred = self.get_credentials(session['aws_credential_id'], session['user_id'])
                if aws_cred:
                    credentials['aws'] = {
                        'access_key_id': aws_cred.aws_access_key_id,
                        'secret_access_key': aws_cred.aws_secret_access_key,
                        'session_token': aws_cred.aws_session_token,
                        'region': aws_cred.aws_region
                    }
            
            # Get OpenAI credential if present
            if session['openai_credential_id']:
                openai_cred = self.get_credentials(session['openai_credential_id'], session['user_id'])
                if openai_cred:
                    credentials['openai'] = {
                        'api_key': openai_cred.openai_api_key,
                        'org_id': openai_cred.openai_org_id
                    }
            
            # Get GCP credential if present
            if session['gcp_credential_id']:
                gcp_cred = self.get_credentials(session['gcp_credential_id'], session['user_id'])
                if gcp_cred:
                    credentials['gcp'] = {
                        'service_account_json': gcp_cred.gcp_service_account_json,
                        'project_id': gcp_cred.gcp_project_id
                    }
            
            return credentials
            
        finally:
            cur.close()
            conn.close()


# Singleton instance
credential_manager = CredentialManager()

"""
Interactive Cloud Security Scanner
Prompts for real credentials and performs actual security scans
"""

import os
import sys
import json
import getpass
import logging
from typing import Dict, Optional, List
from pathlib import Path

# Third-party imports
import boto3
from google.cloud import storage
from google.oauth2 import service_account
from openai import OpenAI
from dotenv import load_dotenv, set_key
from tabulate import tabulate

# Local imports
from mcp_base import mcp_registry, ScanResult
from mcp_aws_plugin import AWSPlugin
from mcp_gcp_plugin import GCPPlugin
from mcp_openai_plugin import OpenAIPlugin
from ai_recommender import AIRecommendationEngine
from database import (
    create_scan_record,
    store_resource,
    store_finding,
    DB_CONN
)

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')
logger = logging.getLogger("interactive_scanner")


class CredentialManager:
    """Handles credential collection, validation, and storage"""
    
    def __init__(self):
        self.credentials = {
            'aws': {},
            'gcp': {},
            'openai': {}
        }
        self.env_file = Path('.env')
    
    def prompt_aws_credentials(self) -> Dict[str, str]:
        """Prompt for AWS credentials interactively"""
        print("\n" + "="*60)
        print("AWS CREDENTIALS")
        print("="*60)
        print("You need: AWS Access Key ID and Secret Access Key")
        print("Get them from: AWS Console → IAM → Users → Security Credentials")
        print("\nRequired IAM Permissions (ReadOnly):")
        print("  - s3:ListAllMyBuckets, s3:GetBucketPolicy, s3:GetBucketAcl")
        print("  - iam:ListUsers, iam:ListAccessKeys, iam:ListMFADevices")
        print("  - ec2:DescribeSecurityGroups")
        print("  - cloudtrail:DescribeTrails, cloudtrail:GetTrailStatus")
        print("  - kms:ListKeys, kms:DescribeKey")
        print("-"*60)
        
        use_existing = input("\nUse credentials from .env file? (y/n): ").lower()
        
        if use_existing == 'y' and self.env_file.exists():
            load_dotenv()
            access_key = os.getenv('AWS_ACCESS_KEY_ID')
            secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
            region = os.getenv('AWS_REGION', 'us-east-1')
            
            if access_key and secret_key:
                print(f"✓ Loaded AWS credentials from .env")
                print(f"  Access Key: {access_key[:10]}...")
                return {
                    'access_key_id': access_key,
                    'secret_access_key': secret_key,
                    'region': region
                }
        
        # Prompt for new credentials
        access_key = input("\nEnter AWS Access Key ID: ").strip()
        secret_key = getpass.getpass("Enter AWS Secret Access Key (hidden): ").strip()
        region = input("Enter AWS Region (default: us-east-1): ").strip() or "us-east-1"
        
        save = input("\nSave credentials to .env file? (y/n): ").lower()
        if save == 'y':
            self._save_to_env('AWS_ACCESS_KEY_ID', access_key)
            self._save_to_env('AWS_SECRET_ACCESS_KEY', secret_key)
            self._save_to_env('AWS_REGION', region)
            print("✓ Credentials saved to .env")
        
        return {
            'access_key_id': access_key,
            'secret_access_key': secret_key,
            'region': region
        }
    
    def prompt_gcp_credentials(self) -> Dict[str, str]:
        """Prompt for GCP credentials interactively"""
        print("\n" + "="*60)
        print("GCP CREDENTIALS")
        print("="*60)
        print("You need: Service Account JSON key file")
        print("Get it from: GCP Console → IAM → Service Accounts → Keys → Create Key")
        print("\nRequired Roles:")
        print("  - Storage Object Viewer (roles/storage.objectViewer)")
        print("  - Security Reviewer (roles/iam.securityReviewer)")
        print("-"*60)
        
        use_existing = input("\nUse credentials from .env file? (y/n): ").lower()
        
        if use_existing == 'y' and self.env_file.exists():
            load_dotenv()
            sa_json = os.getenv('GCP_SERVICE_ACCOUNT_JSON')
            project_id = os.getenv('GCP_PROJECT_ID')
            
            if sa_json and project_id and Path(sa_json).exists():
                print(f"✓ Loaded GCP credentials from .env")
                print(f"  Service Account: {sa_json}")
                print(f"  Project ID: {project_id}")
                return {
                    'service_account_json': sa_json,
                    'project_id': project_id
                }
        
        # Prompt for new credentials
        sa_json = input("\nEnter path to Service Account JSON file: ").strip()
        
        # Validate file exists
        if not Path(sa_json).exists():
            print(f"✗ Error: File not found: {sa_json}")
            return {}
        
        # Extract project ID from JSON
        try:
            with open(sa_json, 'r') as f:
                sa_data = json.load(f)
                project_id = sa_data.get('project_id', '')
        except Exception as e:
            print(f"✗ Error reading JSON: {e}")
            return {}
        
        if not project_id:
            project_id = input("Enter GCP Project ID: ").strip()
        
        print(f"✓ Project ID: {project_id}")
        
        save = input("\nSave credentials to .env file? (y/n): ").lower()
        if save == 'y':
            self._save_to_env('GCP_SERVICE_ACCOUNT_JSON', sa_json)
            self._save_to_env('GCP_PROJECT_ID', project_id)
            print("✓ Credentials saved to .env")
        
        return {
            'service_account_json': sa_json,
            'project_id': project_id
        }
    
    def prompt_openai_credentials(self) -> Dict[str, str]:
        """Prompt for OpenAI credentials interactively"""
        print("\n" + "="*60)
        print("OPENAI CREDENTIALS")
        print("="*60)
        print("You need: OpenAI API Key")
        print("Get it from: https://platform.openai.com/api-keys")
        print("-"*60)
        
        use_existing = input("\nUse credentials from .env file? (y/n): ").lower()
        
        if use_existing == 'y' and self.env_file.exists():
            load_dotenv()
            api_key = os.getenv('OPENAI_API_KEY')
            org_id = os.getenv('OPENAI_ORG_ID', '')
            
            if api_key:
                print(f"✓ Loaded OpenAI credentials from .env")
                print(f"  API Key: {api_key[:10]}...")
                return {
                    'api_key': api_key,
                    'org_id': org_id
                }
        
        # Prompt for new credentials
        api_key = getpass.getpass("\nEnter OpenAI API Key (hidden): ").strip()
        org_id = input("Enter OpenAI Organization ID (optional): ").strip()
        
        save = input("\nSave credentials to .env file? (y/n): ").lower()
        if save == 'y':
            self._save_to_env('OPENAI_API_KEY', api_key)
            if org_id:
                self._save_to_env('OPENAI_ORG_ID', org_id)
            print("✓ Credentials saved to .env")
        
        return {
            'api_key': api_key,
            'org_id': org_id
        }
    
    def validate_aws_credentials(self, creds: Dict[str, str]) -> tuple[bool, Optional[str]]:
        """Validate AWS credentials and get real account ID"""
        print("\n🔍 Validating AWS credentials...")
        try:
            sts = boto3.client(
                'sts',
                aws_access_key_id=creds['access_key_id'],
                aws_secret_access_key=creds['secret_access_key'],
                region_name=creds.get('region', 'us-east-1')
            )
            identity = sts.get_caller_identity()
            account_id = identity['Account']
            user_arn = identity['Arn']
            
            print(f"✓ AWS credentials valid!")
            print(f"  Account ID: {account_id}")
            print(f"  User/Role: {user_arn}")
            
            return True, account_id
        except Exception as e:
            print(f"✗ AWS credentials invalid: {e}")
            return False, None
    
    def validate_gcp_credentials(self, creds: Dict[str, str]) -> tuple[bool, Optional[str]]:
        """Validate GCP credentials and get real project ID"""
        print("\n🔍 Validating GCP credentials...")
        try:
            credentials = service_account.Credentials.from_service_account_file(
                creds['service_account_json']
            )
            client = storage.Client(
                credentials=credentials,
                project=creds['project_id']
            )
            
            # Test by listing buckets (just to validate access)
            list(client.list_buckets(max_results=1))
            
            print(f"✓ GCP credentials valid!")
            print(f"  Project ID: {creds['project_id']}")
            
            return True, creds['project_id']
        except Exception as e:
            print(f"✗ GCP credentials invalid: {e}")
            return False, None
    
    def validate_openai_credentials(self, creds: Dict[str, str]) -> tuple[bool, Optional[str]]:
        """Validate OpenAI credentials"""
        print("\n🔍 Validating OpenAI credentials...")
        try:
            client = OpenAI(api_key=creds['api_key'])
            
            # Test by listing models
            models = client.models.list()
            model_count = len(list(models.data))
            
            org_id = creds.get('org_id', 'default')
            
            print(f"✓ OpenAI credentials valid!")
            print(f"  Organization: {org_id}")
            print(f"  Available Models: {model_count}")
            
            return True, org_id
        except Exception as e:
            print(f"✗ OpenAI credentials invalid: {e}")
            return False, None
    
    def _save_to_env(self, key: str, value: str):
        """Save credential to .env file"""
        if not self.env_file.exists():
            self.env_file.touch()
        
        set_key(self.env_file, key, value)


class InteractiveScanner:
    """Main interactive scanning interface"""
    
    def __init__(self):
        self.cred_manager = CredentialManager()
        self.plugins = {}
        self.account_ids = {}
    
    def welcome(self):
        """Display welcome message"""
        print("\n" + "="*60)
        print("  MULTI-CLOUD SECURITY SCANNER - INTERACTIVE MODE")
        print("="*60)
        print("\nThis tool will:")
        print("  1. Prompt for your cloud credentials")
        print("  2. Validate they work")
        print("  3. Scan for security vulnerabilities")
        print("  4. Generate AI-powered recommendations")
        print("\nSupported Providers: AWS, GCP, OpenAI")
        print("="*60)
    
    def select_providers(self) -> List[str]:
        """Let user select which clouds to scan"""
        print("\n📋 SELECT CLOUD PROVIDERS TO SCAN")
        print("-"*60)
        
        providers = []
        
        scan_aws = input("Scan AWS? (y/n): ").lower() == 'y'
        if scan_aws:
            providers.append('aws')
        
        scan_gcp = input("Scan GCP? (y/n): ").lower() == 'y'
        if scan_gcp:
            providers.append('gcp')
        
        scan_openai = input("Scan OpenAI? (y/n): ").lower() == 'y'
        if scan_openai:
            providers.append('openai')
        
        if not providers:
            print("\n✗ No providers selected. Exiting.")
            sys.exit(0)
        
        print(f"\n✓ Selected providers: {', '.join(providers)}")
        return providers
    
    def setup_provider(self, provider: str) -> bool:
        """Setup and validate credentials for a provider"""
        print(f"\n{'='*60}")
        print(f"SETTING UP: {provider.upper()}")
        print(f"{'='*60}")
        
        if provider == 'aws':
            creds = self.cred_manager.prompt_aws_credentials()
            if not creds:
                return False
            
            valid, account_id = self.cred_manager.validate_aws_credentials(creds)
            if not valid:
                return False
            
            self.account_ids['aws'] = account_id
            self.plugins['aws'] = AWSPlugin(creds)
            mcp_registry.register('aws', self.plugins['aws'])
            
        elif provider == 'gcp':
            creds = self.cred_manager.prompt_gcp_credentials()
            if not creds:
                return False
            
            valid, project_id = self.cred_manager.validate_gcp_credentials(creds)
            if not valid:
                return False
            
            self.account_ids['gcp'] = project_id
            self.plugins['gcp'] = GCPPlugin(creds)
            mcp_registry.register('gcp', self.plugins['gcp'])
            
        elif provider == 'openai':
            creds = self.cred_manager.prompt_openai_credentials()
            if not creds:
                return False
            
            valid, org_id = self.cred_manager.validate_openai_credentials(creds)
            if not valid:
                return False
            
            self.account_ids['openai'] = org_id
            self.plugins['openai'] = OpenAIPlugin(creds)
            mcp_registry.register('openai', self.plugins['openai'])
        
        print(f"\n✅ {provider.upper()} setup complete!")
        return True
    
    async def scan_provider(self, provider: str) -> Optional[ScanResult]:
        """Execute security scan for a provider"""
        print(f"\n{'='*60}")
        print(f"🔍 SCANNING: {provider.upper()}")
        print(f"{'='*60}")
        
        account_id = self.account_ids[provider]
        print(f"Account/Project: {account_id}")
        
        try:
            # Execute scan
            result = await mcp_registry.scan(provider, account_id)
            
            # Store in database
            scan_id = create_scan_record(account_id, provider)
            
            # Update scan status to completed
            cur = DB_CONN.cursor()
            cur.execute(
                "UPDATE scans SET status = 'completed' WHERE id = %s",
                (scan_id,)
            )
            DB_CONN.commit()
            cur.close()
            
            # Store resources
            for resource in result.resources:
                resource_id = store_resource(
                    scan_id=scan_id,
                    cloud=provider,
                    resource_type=resource.resource_type,
                    name=resource.name,
                    config=resource.config,
                    is_public=resource.is_public
                )
            
            # Store findings
            for finding in result.findings:
                # Find resource_id
                cur = DB_CONN.cursor()
                cur.execute(
                    "SELECT id FROM resources WHERE scan_id = %s AND name = %s LIMIT 1",
                    (scan_id, finding.resource.name)
                )
                resource_row = cur.fetchone()
                cur.close()
                
                if resource_row:
                    store_finding(
                        scan_id=scan_id,
                        resource_id=resource_row[0],
                        severity=finding.severity.value,
                        description=f"{finding.issue}: {finding.description}",
                        source=provider
                    )
            
            print(f"\n✅ {provider.upper()} SCAN COMPLETE")
            print(f"  Resources Found: {len(result.resources)}")
            print(f"  Security Findings: {len(result.findings)}")
            print(f"  Scan Duration: {result.scan_duration:.2f}s")
            print(f"  Database Scan ID: {scan_id}")
            
            return result
            
        except Exception as e:
            print(f"\n✗ {provider.upper()} scan failed: {e}")
            logger.exception("Scan error")
            return None
    
    def display_results(self, scan_results: List[ScanResult]):
        """Display scan results in formatted tables"""
        print("\n" + "="*60)
        print("📊 SCAN RESULTS SUMMARY")
        print("="*60)
        
        # Summary table
        summary_data = []
        total_resources = 0
        total_findings = 0
        
        for result in scan_results:
            summary_data.append([
                result.provider.upper(),
                self.account_ids[result.provider],
                len(result.resources),
                len(result.findings),
                f"{result.scan_duration:.1f}s"
            ])
            total_resources += len(result.resources)
            total_findings += len(result.findings)
        
        print(tabulate(
            summary_data,
            headers=['Provider', 'Account/Project', 'Resources', 'Findings', 'Duration'],
            tablefmt='grid'
        ))
        
        print(f"\n📈 TOTALS:")
        print(f"  Total Resources: {total_resources}")
        print(f"  Total Findings: {total_findings}")
        
        # Findings by severity
        print("\n" + "="*60)
        print("🚨 FINDINGS BY SEVERITY")
        print("="*60)
        
        severity_counts = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        
        for result in scan_results:
            for finding in result.findings:
                severity_counts[finding.severity.value] += 1
        
        severity_data = [[k, v] for k, v in severity_counts.items() if v > 0]
        print(tabulate(severity_data, headers=['Severity', 'Count'], tablefmt='grid'))
        
        # Top 10 critical findings
        if severity_counts['CRITICAL'] > 0 or severity_counts['HIGH'] > 0:
            print("\n" + "="*60)
            print("⚠️  TOP CRITICAL & HIGH FINDINGS")
            print("="*60)
            
            top_findings = []
            for result in scan_results:
                for finding in result.findings:
                    if finding.severity.value in ['CRITICAL', 'HIGH']:
                        top_findings.append([
                            finding.severity.value,
                            result.provider.upper(),
                            finding.resource.name[:30],
                            finding.issue[:40]
                        ])
            
            # Show first 10
            print(tabulate(
                top_findings[:10],
                headers=['Severity', 'Cloud', 'Resource', 'Issue'],
                tablefmt='grid'
            ))
            
            if len(top_findings) > 10:
                print(f"\n... and {len(top_findings) - 10} more findings")
    
    async def generate_ai_recommendations(self, scan_results: List[ScanResult]):
        """Generate AI-powered recommendations"""
        print("\n" + "="*60)
        print("🤖 GENERATING AI RECOMMENDATIONS")
        print("="*60)
        
        # Check if OpenAI API key is available
        load_dotenv()
        api_key = os.getenv('OPENAI_API_KEY')
        
        if not api_key:
            print("✗ OpenAI API key not found. Skipping AI analysis.")
            print("  (AI recommendations require OPENAI_API_KEY in .env)")
            return
        
        try:
            ai_engine = AIRecommendationEngine(api_key=api_key)
            analysis = await ai_engine.analyze_scan_results(scan_results)
            
            # Display AI Analysis
            print("\n📝 AI SECURITY ANALYSIS:")
            print("-"*60)
            print(analysis.get('ai_analysis', 'N/A'))
            
            # Display Executive Summary
            summary = analysis.get('executive_summary', {})
            print("\n" + "="*60)
            print("📊 SECURITY SCORE")
            print("="*60)
            print(f"  Score: {summary.get('security_score', 0)}/100")
            print(f"  Posture: {summary.get('security_posture', 'UNKNOWN')}")
            
            # Display Remediation Plan
            plan = analysis.get('remediation_plan', {})
            if plan and 'error' not in plan:
                print("\n" + "="*60)
                print("📅 7-DAY REMEDIATION PLAN")
                print("="*60)
                
                for day_key in sorted([k for k in plan.keys() if k.startswith('day_')]):
                    day_data = plan[day_key]
                    print(f"\n{day_key.upper()}: {day_data.get('focus', 'N/A')}")
                    tasks = day_data.get('tasks', [])
                    for i, task in enumerate(tasks, 1):
                        print(f"  {i}. {task}")
            
        except Exception as e:
            print(f"✗ AI analysis failed: {e}")
            logger.exception("AI analysis error")
    
    async def run(self):
        """Main execution flow"""
        self.welcome()
        
        # Step 1: Select providers
        providers = self.select_providers()
        
        # Step 2: Setup each provider
        print("\n" + "="*60)
        print("STEP 1: CREDENTIAL SETUP")
        print("="*60)
        
        successful_providers = []
        for provider in providers:
            if self.setup_provider(provider):
                successful_providers.append(provider)
            else:
                print(f"\n⚠️  Skipping {provider.upper()} due to credential issues")
        
        if not successful_providers:
            print("\n✗ No valid providers configured. Exiting.")
            sys.exit(1)
        
        # Step 3: Execute scans
        print("\n" + "="*60)
        print("STEP 2: SECURITY SCANNING")
        print("="*60)
        
        scan_results = []
        for provider in successful_providers:
            result = await self.scan_provider(provider)
            if result:
                scan_results.append(result)
        
        if not scan_results:
            print("\n✗ All scans failed. Exiting.")
            sys.exit(1)
        
        # Step 4: Display results
        print("\n" + "="*60)
        print("STEP 3: RESULTS")
        print("="*60)
        self.display_results(scan_results)
        
        # Step 5: AI recommendations
        print("\n" + "="*60)
        print("STEP 4: AI RECOMMENDATIONS")
        print("="*60)
        await self.generate_ai_recommendations(scan_results)
        
        # Final message
        print("\n" + "="*60)
        print("✅ SCAN COMPLETE")
        print("="*60)
        print("\nYou can view detailed results in the database:")
        print("  psql $DATABASE_URL -c 'SELECT * FROM scans ORDER BY id DESC LIMIT 5;'")
        print("\nOr use the API to get reports:")
        print("  curl http://localhost:8000/posture/dashboard")


async def main():
    """Entry point"""
    try:
        scanner = InteractiveScanner()
        await scanner.run()
    except KeyboardInterrupt:
        print("\n\n⚠️  Scan interrupted by user")
        sys.exit(0)
    except Exception as e:
        print(f"\n✗ Fatal error: {e}")
        logger.exception("Fatal error")
        sys.exit(1)


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
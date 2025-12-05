"""
Integration test for MCP Security Scanner
Tests all components end-to-end
"""

import asyncio
import os
from dotenv import load_dotenv

# Import MCP components
from mcp_base import mcp_registry, CloudResource, SecurityFinding, Severity
from mcp_aws_plugin import AWSPlugin
from mcp_gcp_plugin import GCPPlugin
from mcp_openai_plugin import OpenAIPlugin
from ai_recommender import AIRecommendationEngine

load_dotenv()


async def test_mcp_architecture():
    """Test MCP plugin architecture"""
    print("\n" + "="*60)
    print("🧪 TESTING MCP ARCHITECTURE")
    print("="*60)
    
    # Test 1: Plugin Registration
    print("\n1️⃣ Testing Plugin Registration...")
    
    aws_plugin = AWSPlugin({
        'access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
        'secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
        'region': 'us-east-1'
    })
    mcp_registry.register('aws', aws_plugin)
    print("✓ AWS Plugin registered")
    
    gcp_plugin = GCPPlugin({
        'service_account_json': os.getenv('GCP_SERVICE_ACCOUNT_JSON'),
        'project_id': os.getenv('GCP_PROJECT_ID')
    })
    mcp_registry.register('gcp', gcp_plugin)
    print("✓ GCP Plugin registered")
    
    openai_plugin = OpenAIPlugin({
        'api_key': os.getenv('OPENAI_API_KEY'),
        'org_id': os.getenv('OPENAI_ORG_ID')
    })
    mcp_registry.register('openai', openai_plugin)
    print("✓ OpenAI Plugin registered")
    
    providers = mcp_registry.list_providers()
    print(f"\n✓ Total providers registered: {len(providers)}")
    print(f"  Providers: {', '.join(providers)}")
    
    # Test 2: AWS Scan
    print("\n2️⃣ Testing AWS Scan...")
    try:
        aws_result = await mcp_registry.scan('aws', 'test-account')
        print(f"✓ AWS Scan completed in {aws_result.scan_duration:.2f}s")
        print(f"  Resources found: {len(aws_result.resources)}")
        print(f"  Findings: {len(aws_result.findings)}")
        
        if aws_result.findings:
            critical = [f for f in aws_result.findings if f.severity == Severity.CRITICAL]
            high = [f for f in aws_result.findings if f.severity == Severity.HIGH]
            print(f"  Critical: {len(critical)}, High: {len(high)}")
            
            # Show first finding
            if aws_result.findings:
                first = aws_result.findings[0]
                print(f"\n  Sample Finding:")
                print(f"    Severity: {first.severity.value}")
                print(f"    Issue: {first.issue}")
                print(f"    Resource: {first.resource.name}")
    except Exception as e:
        print(f"✗ AWS Scan failed: {e}")
    
    # Test 3: GCP Scan
    print("\n3️⃣ Testing GCP Scan...")
    try:
        gcp_result = await mcp_registry.scan('gcp', 'test-project')
        print(f"✓ GCP Scan completed in {gcp_result.scan_duration:.2f}s")
        print(f"  Resources found: {len(gcp_result.resources)}")
        print(f"  Findings: {len(gcp_result.findings)}")
    except Exception as e:
        print(f"✗ GCP Scan failed: {e}")
    
    # Test 4: OpenAI Scan
    print("\n4️⃣ Testing OpenAI Scan...")
    try:
        openai_result = await mcp_registry.scan('openai', 'test-org')
        print(f"✓ OpenAI Scan completed in {openai_result.scan_duration:.2f}s")
        print(f"  Resources found: {len(openai_result.resources)}")
        print(f"  Findings: {len(openai_result.findings)}")
    except Exception as e:
        print(f"✗ OpenAI Scan failed: {e}")
    
    # Test 5: AI Recommendation Engine
    print("\n5️⃣ Testing AI Recommendation Engine...")
    try:
        ai_engine = AIRecommendationEngine(os.getenv('OPENAI_API_KEY'))
        
        # Combine all scan results
        all_results = []
        if 'aws_result' in locals():
            all_results.append(aws_result)
        if 'gcp_result' in locals():
            all_results.append(gcp_result)
        if 'openai_result' in locals():
            all_results.append(openai_result)
        
        if all_results:
            analysis = await ai_engine.analyze_scan_results(all_results)
            
            print("✓ AI Analysis generated")
            
            if 'executive_summary' in analysis:
                summary = analysis['executive_summary']
                print(f"\n  Security Score: {summary.get('security_score', 'N/A')}/100")
                print(f"  Posture: {summary.get('security_posture', 'N/A')}")
                print(f"  Total Resources: {summary.get('total_resources', 0)}")
                print(f"  Total Findings: {summary.get('total_findings', 0)}")
            
            if 'remediation_plan' in analysis:
                plan = analysis['remediation_plan']
                if 'day_1' in plan:
                    print(f"\n  Day 1 Focus: {plan['day_1'].get('focus', 'N/A')}")
    except Exception as e:
        print(f"✗ AI Analysis failed: {e}")
    
    print("\n" + "="*60)
    print("✅ MCP ARCHITECTURE TEST COMPLETE")
    print("="*60)


async def test_vulnerability_checks():
    """Test specific vulnerability checks"""
    print("\n" + "="*60)
    print("🔍 TESTING VULNERABILITY CHECKS")
    print("="*60)
    
    # Create mock resources to test vulnerability detection
    
    # Test 1: Public S3 Bucket Detection
    print("\n1️⃣ Testing S3 Vulnerability Detection...")
    mock_s3 = CloudResource(
        provider="aws",
        resource_type="s3_bucket",
        name="test-public-bucket",
        is_public=True,
        config={
            "encryption": None,
            "versioning": {"Status": "Disabled"},
            "logging": False
        }
    )
    
    aws_plugin = AWSPlugin({
        'access_key_id': 'dummy',
        'secret_access_key': 'dummy'
    })
    
    s3_findings = aws_plugin._check_s3_vulnerabilities(mock_s3)
    print(f"✓ Found {len(s3_findings)} S3 vulnerabilities")
    for finding in s3_findings:
        print(f"  - {finding.severity.value}: {finding.issue}")
    
    # Test 2: IAM User Without MFA
    print("\n2️⃣ Testing IAM Vulnerability Detection...")
    mock_iam = CloudResource(
        provider="aws",
        resource_type="iam_user",
        name="test-user",
        config={
            "mfa_enabled": False,
            "access_keys": [
                {"Status": "Active", "CreateDate": "2023-01-01"}
            ],
            "policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]
        }
    )
    
    iam_findings = aws_plugin._check_iam_vulnerabilities(mock_iam)
    print(f"✓ Found {len(iam_findings)} IAM vulnerabilities")
    for finding in iam_findings:
        print(f"  - {finding.severity.value}: {finding.issue}")
    
    # Test 3: Security Group Open to World
    print("\n3️⃣ Testing Security Group Detection...")
    mock_sg = CloudResource(
        provider="aws",
        resource_type="security_group",
        name="test-sg",
        config={
            "ingress_rules": [
                {
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                },
                {
                    "FromPort": 3389,
                    "ToPort": 3389,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                }
            ]
        }
    )
    
    sg_findings = aws_plugin._check_sg_vulnerabilities(mock_sg)
    print(f"✓ Found {len(sg_findings)} Security Group vulnerabilities")
    for finding in sg_findings:
        print(f"  - {finding.severity.value}: {finding.issue}")
    
    print("\n" + "="*60)
    print("✅ VULNERABILITY CHECK TEST COMPLETE")
    print("="*60)


async def main():
    """Run all tests"""
    print("\n🚀 STARTING MCP SECURITY SCANNER TESTS")
    print("="*60)
    
    # Test MCP Architecture
    await test_mcp_architecture()
    
    # Test Vulnerability Checks
    await test_vulnerability_checks()
    
    print("\n" + "="*60)
    print("🎉 ALL TESTS COMPLETE!")
    print("="*60)
    print("\nYour MCP Security Scanner is ready to use!")
    print("\nNext steps:")
    print("1. Start the server: python app_refactored.py")
    print("2. Test the API: curl http://localhost:8000/")
    print("3. Run a scan: curl -X POST http://localhost:8000/scan -H 'Content-Type: application/json' -d '{\"message\": \"Scan AWS\"}'")
    print()


if __name__ == "__main__":
    asyncio.run(main())

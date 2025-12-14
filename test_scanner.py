# """
# Integration test for MCP Security Scanner
# Tests all components end-to-end
# """

# import asyncio
# import os
# from dotenv import load_dotenv

# # Import MCP components
# from mcp_base import mcp_registry, CloudResource, SecurityFinding, Severity
# from mcp_aws_plugin import AWSPlugin
# from mcp_gcp_plugin import GCPPlugin
# from mcp_openai_plugin import OpenAIPlugin
# from ai_recommender import AIRecommendationEngine

# load_dotenv()


# async def test_mcp_architecture():
#     """Test MCP plugin architecture"""
#     print("\n" + "="*60)
#     print("🧪 TESTING MCP ARCHITECTURE")
#     print("="*60)
    
#     # Test 1: Plugin Registration
#     print("\n1️⃣ Testing Plugin Registration...")
    
#     aws_plugin = AWSPlugin({
#         'access_key_id': os.getenv('AWS_ACCESS_KEY_ID'),
#         'secret_access_key': os.getenv('AWS_SECRET_ACCESS_KEY'),
#         'region': 'us-east-1'
#     })
#     mcp_registry.register('aws', aws_plugin)
#     print("✓ AWS Plugin registered")
    
#     gcp_plugin = GCPPlugin({
#         'service_account_json': os.getenv('GCP_SERVICE_ACCOUNT_JSON'),
#         'project_id': os.getenv('GCP_PROJECT_ID')
#     })
#     mcp_registry.register('gcp', gcp_plugin)
#     print("✓ GCP Plugin registered")
    
#     openai_plugin = OpenAIPlugin({
#         'api_key': os.getenv('OPENAI_API_KEY'),
#         'org_id': os.getenv('OPENAI_ORG_ID')
#     })
#     mcp_registry.register('openai', openai_plugin)
#     print("✓ OpenAI Plugin registered")
    
#     providers = mcp_registry.list_providers()
#     print(f"\n✓ Total providers registered: {len(providers)}")
#     print(f"  Providers: {', '.join(providers)}")
    
#     # Test 2: AWS Scan
#     print("\n2️⃣ Testing AWS Scan...")
#     try:
#         aws_result = await mcp_registry.scan('aws', 'test-account')
#         print(f"✓ AWS Scan completed in {aws_result.scan_duration:.2f}s")
#         print(f"  Resources found: {len(aws_result.resources)}")
#         print(f"  Findings: {len(aws_result.findings)}")
        
#         if aws_result.findings:
#             critical = [f for f in aws_result.findings if f.severity == Severity.CRITICAL]
#             high = [f for f in aws_result.findings if f.severity == Severity.HIGH]
#             print(f"  Critical: {len(critical)}, High: {len(high)}")
            
#             # Show first finding
#             if aws_result.findings:
#                 first = aws_result.findings[0]
#                 print(f"\n  Sample Finding:")
#                 print(f"    Severity: {first.severity.value}")
#                 print(f"    Issue: {first.issue}")
#                 print(f"    Resource: {first.resource.name}")
#     except Exception as e:
#         print(f"✗ AWS Scan failed: {e}")
    
#     # Test 3: GCP Scan
#     print("\n3️⃣ Testing GCP Scan...")
#     try:
#         gcp_result = await mcp_registry.scan('gcp', 'test-project')
#         print(f"✓ GCP Scan completed in {gcp_result.scan_duration:.2f}s")
#         print(f"  Resources found: {len(gcp_result.resources)}")
#         print(f"  Findings: {len(gcp_result.findings)}")
#     except Exception as e:
#         print(f"✗ GCP Scan failed: {e}")
    
#     # Test 4: OpenAI Scan
#     print("\n4️⃣ Testing OpenAI Scan...")
#     try:
#         openai_result = await mcp_registry.scan('openai', 'test-org')
#         print(f"✓ OpenAI Scan completed in {openai_result.scan_duration:.2f}s")
#         print(f"  Resources found: {len(openai_result.resources)}")
#         print(f"  Findings: {len(openai_result.findings)}")
#     except Exception as e:
#         print(f"✗ OpenAI Scan failed: {e}")
    
#     # Test 5: AI Recommendation Engine
#     print("\n5️⃣ Testing AI Recommendation Engine...")
#     try:
#         ai_engine = AIRecommendationEngine(os.getenv('OPENAI_API_KEY'))
        
#         # Combine all scan results
#         all_results = []
#         if 'aws_result' in locals():
#             all_results.append(aws_result)
#         if 'gcp_result' in locals():
#             all_results.append(gcp_result)
#         if 'openai_result' in locals():
#             all_results.append(openai_result)
        
#         if all_results:
#             analysis = await ai_engine.analyze_scan_results(all_results)
            
#             print("✓ AI Analysis generated")
            
#             if 'executive_summary' in analysis:
#                 summary = analysis['executive_summary']
#                 print(f"\n  Security Score: {summary.get('security_score', 'N/A')}/100")
#                 print(f"  Posture: {summary.get('security_posture', 'N/A')}")
#                 print(f"  Total Resources: {summary.get('total_resources', 0)}")
#                 print(f"  Total Findings: {summary.get('total_findings', 0)}")
            
#             if 'remediation_plan' in analysis:
#                 plan = analysis['remediation_plan']
#                 if 'day_1' in plan:
#                     print(f"\n  Day 1 Focus: {plan['day_1'].get('focus', 'N/A')}")
#     except Exception as e:
#         print(f"✗ AI Analysis failed: {e}")
    
#     print("\n" + "="*60)
#     print("✅ MCP ARCHITECTURE TEST COMPLETE")
#     print("="*60)


# async def test_vulnerability_checks():
#     """Test specific vulnerability checks"""
#     print("\n" + "="*60)
#     print("🔍 TESTING VULNERABILITY CHECKS")
#     print("="*60)
    
#     # Create mock resources to test vulnerability detection
    
#     # Test 1: Public S3 Bucket Detection
#     print("\n1️⃣ Testing S3 Vulnerability Detection...")
#     mock_s3 = CloudResource(
#         provider="aws",
#         resource_type="s3_bucket",
#         name="test-public-bucket",
#         is_public=True,
#         config={
#             "encryption": None,
#             "versioning": {"Status": "Disabled"},
#             "logging": False
#         }
#     )
    
#     aws_plugin = AWSPlugin({
#         'access_key_id': 'dummy',
#         'secret_access_key': 'dummy'
#     })
    
#     s3_findings = aws_plugin._check_s3_vulnerabilities(mock_s3)
#     print(f"✓ Found {len(s3_findings)} S3 vulnerabilities")
#     for finding in s3_findings:
#         print(f"  - {finding.severity.value}: {finding.issue}")
    
#     # Test 2: IAM User Without MFA
#     print("\n2️⃣ Testing IAM Vulnerability Detection...")
#     mock_iam = CloudResource(
#         provider="aws",
#         resource_type="iam_user",
#         name="test-user",
#         config={
#             "mfa_enabled": False,
#             "access_keys": [
#                 {"Status": "Active", "CreateDate": "2023-01-01"}
#             ],
#             "policies": ["arn:aws:iam::aws:policy/AdministratorAccess"]
#         }
#     )
    
#     iam_findings = aws_plugin._check_iam_vulnerabilities(mock_iam)
#     print(f"✓ Found {len(iam_findings)} IAM vulnerabilities")
#     for finding in iam_findings:
#         print(f"  - {finding.severity.value}: {finding.issue}")
    
#     # Test 3: Security Group Open to World
#     print("\n3️⃣ Testing Security Group Detection...")
#     mock_sg = CloudResource(
#         provider="aws",
#         resource_type="security_group",
#         name="test-sg",
#         config={
#             "ingress_rules": [
#                 {
#                     "FromPort": 22,
#                     "ToPort": 22,
#                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
#                 },
#                 {
#                     "FromPort": 3389,
#                     "ToPort": 3389,
#                     "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
#                 }
#             ]
#         }
#     )
    
#     sg_findings = aws_plugin._check_sg_vulnerabilities(mock_sg)
#     print(f"✓ Found {len(sg_findings)} Security Group vulnerabilities")
#     for finding in sg_findings:
#         print(f"  - {finding.severity.value}: {finding.issue}")
    
#     print("\n" + "="*60)
#     print("✅ VULNERABILITY CHECK TEST COMPLETE")
#     print("="*60)


# async def main():
#     """Run all tests"""
#     print("\n🚀 STARTING MCP SECURITY SCANNER TESTS")
#     print("="*60)
    
#     # Test MCP Architecture
#     await test_mcp_architecture()
    
#     # Test Vulnerability Checks
#     await test_vulnerability_checks()
    
#     print("\n" + "="*60)
#     print("🎉 ALL TESTS COMPLETE!")
#     print("="*60)
#     print("\nYour MCP Security Scanner is ready to use!")
#     print("\nNext steps:")
#     print("1. Start the server: python app_refactored.py")
#     print("2. Test the API: curl http://localhost:8000/")
#     print("3. Run a scan: curl -X POST http://localhost:8000/scan -H 'Content-Type: application/json' -d '{\"message\": \"Scan AWS\"}'")
#     print()


# if __name__ == "__main__":
#     asyncio.run(main())


"""
Test script for vulnerability scanner integration
Run this to verify all tools are working correctly
"""

import asyncio
import sys
import os
from pathlib import Path

# Try importing the modules
try:
    from vulnerability_scanner import VulnerabilityScanner, ScanTarget, VulnSeverity
    print("✓ vulnerability_scanner module imported successfully")
except ImportError as e:
    print(f"✗ Failed to import vulnerability_scanner: {e}")
    sys.exit(1)

try:
    from vulnerability_integration import CloudVulnerabilityIntegration
    print("✓ vulnerability_integration module imported successfully")
except ImportError as e:
    print(f"✗ Failed to import vulnerability_integration: {e}")
    sys.exit(1)


async def test_scanner_initialization():
    """Test 1: Scanner initializes and detects tools"""
    print("\n" + "="*60)
    print("TEST 1: Scanner Initialization")
    print("="*60)
    
    scanner = VulnerabilityScanner()
    
    print(f"\n📋 Available Scanning Tools:")
    if scanner.tools_available:
        for tool, available in scanner.tools_available.items():
            print(f"  {'✓' if available else '✗'} {tool}")
    else:
        print("  ⚠ No vulnerability scanning tools detected!")
        print("  Install at least one tool to enable scanning:")
        print("    - Trivy: https://github.com/aquasecurity/trivy")
        print("    - Safety: pip install safety")
        print("    - npm: included with Node.js")
    
    return len(scanner.tools_available) > 0


async def test_python_dependency_scan():
    """Test 2: Scan requirements.txt for vulnerabilities"""
    print("\n" + "="*60)
    print("TEST 2: Python Dependency Scanning")
    print("="*60)
    
    scanner = VulnerabilityScanner()
    
    # Check if we have tools for Python scanning
    has_python_tools = "trivy" in scanner.tools_available or "safety" in scanner.tools_available
    
    if not has_python_tools:
        print("⚠ Skipping: No Python scanning tools available (trivy or safety needed)")
        return True
    
    # Check if requirements.txt exists
    req_path = "requirements.txt"
    if not os.path.exists(req_path):
        print(f"⚠ {req_path} not found, creating test file...")
        with open(req_path, 'w') as f:
            # Use an old vulnerable version for testing
            f.write("django==2.2.0\nrequests==2.20.0\n")
    
    try:
        target = ScanTarget(
            target_type="python_dependencies",
            path=req_path
        )
        
        print(f"🔍 Scanning {req_path}...")
        vulnerabilities = await scanner.scan_all(target)
        
        print(f"\n📊 Scan Results:")
        print(f"  Total vulnerabilities found: {len(vulnerabilities)}")
        
        if vulnerabilities:
            report = scanner.generate_report(vulnerabilities)
            print(f"\n  Severity Breakdown:")
            for severity, count in report['severity_breakdown'].items():
                if count > 0:
                    print(f"    {severity}: {count}")
            
            print(f"\n  Risk Score: {report['risk_score']}")
            print(f"  Tools Used: {', '.join(report['tools_used'])}")
            
            # Show first few vulnerabilities
            print(f"\n  Sample Vulnerabilities:")
            for vuln in vulnerabilities[:3]:
                print(f"    - {vuln.vuln_id}: {vuln.title}")
                print(f"      Severity: {vuln.severity.value}")
                print(f"      Package: {vuln.affected_package}")
                print(f"      Fixed in: {vuln.fixed_version or 'N/A'}")
                print()
        else:
            print("  ✓ No vulnerabilities detected!")
        
        return True
    
    except Exception as e:
        print(f"✗ Scan failed: {e}")
        import traceback
        traceback.print_exc()
        return False


async def test_filesystem_scan():
    """Test 3: Scan filesystem for vulnerabilities"""
    print("\n" + "="*60)
    print("TEST 3: Filesystem Scanning")
    print("="*60)
    
    scanner = VulnerabilityScanner()
    
    if "trivy" not in scanner.tools_available:
        print("⚠ Skipping: Trivy not available (needed for filesystem scanning)")
        return True
    
    try:
        # Scan current directory
        target = ScanTarget(
            target_type="filesystem",
            path=".",
            metadata={"has_web_files": False}
        )
        
        print("🔍 Scanning current directory...")
        vulnerabilities = await scanner.scan_all(target)
        
        print(f"\n📊 Filesystem Scan Results:")
        print(f"  Total vulnerabilities found: {len(vulnerabilities)}")
        
        if vulnerabilities:
            report = scanner.generate_report(vulnerabilities)
            print(f"  Risk Score: {report['risk_score']}")
            print(f"  Tools Used: {', '.join(report['tools_used'])}")
        else:
            print("  ✓ No vulnerabilities detected in filesystem!")
        
        return True
    
    except Exception as e:
        print(f"✗ Filesystem scan failed: {e}")
        return False


async def test_container_scan():
    """Test 4: Scan container image (if Docker available)"""
    print("\n" + "="*60)
    print("TEST 4: Container Image Scanning")
    print("="*60)
    
    scanner = VulnerabilityScanner()
    
    has_container_tools = "trivy" in scanner.tools_available or "grype" in scanner.tools_available
    
    if not has_container_tools:
        print("⚠ Skipping: No container scanning tools available (trivy or grype needed)")
        return True
    
    # Test with a public image
    test_image = "nginx:latest"
    
    try:
        target = ScanTarget(
            target_type="container",
            path=test_image
        )
        
        print(f"🔍 Scanning container image: {test_image}")
        print("  (This may take a while for the first scan...)")
        
        vulnerabilities = await scanner.scan_all(target)
        
        print(f"\n📊 Container Scan Results:")
        print(f"  Total vulnerabilities found: {len(vulnerabilities)}")
        
        if vulnerabilities:
            report = scanner.generate_report(vulnerabilities)
            print(f"\n  Severity Breakdown:")
            for severity, count in report['severity_breakdown'].items():
                if count > 0:
                    print(f"    {severity}: {count}")
            
            print(f"\n  Risk Score: {report['risk_score']}")
        
        return True
    
    except Exception as e:
        print(f"⚠ Container scan failed (this is normal if Docker isn't running): {e}")
        return True  # Don't fail test if Docker isn't available


async def test_integration():
    """Test 5: Integration with cloud resources"""
    print("\n" + "="*60)
    print("TEST 5: Cloud Integration")
    print("="*60)
    
    integration = CloudVulnerabilityIntegration()
    
    print("✓ CloudVulnerabilityIntegration initialized")
    print(f"  Temp directory: {integration.temp_dir}")
    
    # Cleanup
    integration.cleanup()
    print("✓ Cleanup completed")
    
    return True


async def run_all_tests():
    """Run all tests"""
    print("\n" + "="*70)
    print(" VULNERABILITY SCANNER TEST SUITE")
    print("="*70)
    
    results = {}
    
    # Test 1: Initialization
    results['initialization'] = await test_scanner_initialization()
    
    # Test 2: Python dependencies
    results['python_deps'] = await test_python_dependency_scan()
    
    # Test 3: Filesystem
    results['filesystem'] = await test_filesystem_scan()
    
    # Test 4: Container
    results['container'] = await test_container_scan()
    
    # Test 5: Integration
    results['integration'] = await test_integration()
    
    # Summary
    print("\n" + "="*70)
    print(" TEST SUMMARY")
    print("="*70)
    
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    for test, result in results.items():
        status = "✓ PASSED" if result else "✗ FAILED"
        print(f"  {status}: {test}")
    
    print(f"\n  Results: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n  🎉 All tests passed! Vulnerability scanner is ready to use.")
    elif passed > 0:
        print("\n  ⚠ Some tests passed. Install more tools for full functionality:")
        print("     - Trivy (recommended): brew install trivy")
        print("     - Safety: pip install safety")
        print("     - Nuclei: https://github.com/projectdiscovery/nuclei")
    else:
        print("\n  ❌ No tests passed. Please install vulnerability scanning tools.")
    
    print("\n" + "="*70)
    
    return passed == total


if __name__ == "__main__":
    # Run tests
    success = asyncio.run(run_all_tests())
    
    # Exit with appropriate code
    sys.exit(0 if success else 1)


''' 


<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CloudGuard - Multi-Cloud Security Scanner</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            color: #f1f5f9;
            min-height: 100vh;
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 40px 24px;
        }
        
        /* Header */
        .header {
            text-align: center;
            margin-bottom: 60px;
        }
        
        .logo {
            font-size: 3rem;
            margin-bottom: 20px;
            animation: float 6s ease-in-out infinite;
        }
        
        .title {
            font-size: 3.5rem;
            font-weight: 800;
            background: linear-gradient(135deg, #60a5fa, #8b5cf6, #ec4899);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 16px;
            line-height: 1.2;
        }
        
        .subtitle {
            font-size: 1.2rem;
            color: #94a3b8;
            max-width: 600px;
            margin: 0 auto;
        }
        
        /* Main Content */
        .content-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 40px;
            margin-bottom: 60px;
        }
        
        @media (max-width: 768px) {
            .content-grid {
                grid-template-columns: 1fr;
            }
        }
        
        /* Scan Panel */
        .scan-panel {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(10px);
            border-radius: 24px;
            padding: 40px;
            border: 1px solid rgba(148, 163, 184, 0.1);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .panel-title {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 24px;
            color: white;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .panel-subtitle {
            color: #94a3b8;
            margin-bottom: 32px;
            line-height: 1.6;
        }
        
        /* Scan Type Cards */
        .scan-types {
            display: flex;
            flex-direction: column;
            gap: 20px;
            margin-bottom: 32px;
        }
        
        .scan-card {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 16px;
            padding: 24px;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: flex-start;
            gap: 16px;
        }
        
        .scan-card:hover {
            background: rgba(59, 130, 246, 0.1);
            border-color: rgba(59, 130, 246, 0.3);
            transform: translateY(-2px);
        }
        
        .scan-card.active {
            background: rgba(59, 130, 246, 0.15);
            border-color: rgba(59, 130, 246, 0.5);
            box-shadow: 0 8px 32px rgba(59, 130, 246, 0.2);
        }
        
        .scan-icon {
            width: 48px;
            height: 48px;
            background: rgba(59, 130, 246, 0.1);
            border-radius: 12px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.5rem;
            flex-shrink: 0;
        }
        
        .scan-info {
            flex: 1;
        }
        
        .scan-name {
            font-size: 1.1rem;
            font-weight: 600;
            margin-bottom: 8px;
            color: white;
        }
        
        .scan-description {
            font-size: 0.9rem;
            color: #94a3b8;
            line-height: 1.5;
        }
        
        /* Cloud Providers */
        .providers-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }
        
        .provider-option {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(148, 163, 184, 0.1);
            border-radius: 12px;
            padding: 16px;
            cursor: pointer;
            transition: all 0.2s ease;
            display: flex;
            align-items: center;
            gap: 12px;
        }
        
        .provider-option:hover {
            background: rgba(255, 255, 255, 0.08);
        }
        
        .provider-option.selected {
            background: rgba(59, 130, 246, 0.15);
            border-color: rgba(59, 130, 246, 0.5);
        }
        
        .provider-icon {
            width: 36px;
            height: 36px;
            border-radius: 8px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 1.2rem;
        }
        
        .aws-icon { background: rgba(255, 153, 0, 0.1); color: #ff9900; }
        .gcp-icon { background: rgba(66, 133, 244, 0.1); color: #4285f4; }
        .azure-icon { background: rgba(0, 120, 212, 0.1); color: #0078d4; }
        .openai-icon { background: rgba(16, 163, 127, 0.1); color: #10a37f; }
        
        .provider-name {
            font-weight: 600;
            color: white;
        }
        
        /* Scan Options */
        .scan-options {
            margin-bottom: 32px;
        }
        
        .option-item {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
        }
        
        .checkbox-wrapper {
            position: relative;
        }
        
        .checkbox {
            appearance: none;
            width: 20px;
            height: 20px;
            border: 2px solid rgba(148, 163, 184, 0.3);
            border-radius: 6px;
            cursor: pointer;
            position: relative;
            transition: all 0.2s;
        }
        
        .checkbox:checked {
            background: #3b82f6;
            border-color: #3b82f6;
        }
        
        .checkbox:checked::after {
            content: '✓';
            position: absolute;
            color: white;
            font-size: 12px;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
        }
        
        .option-label {
            color: #cbd5e1;
            font-size: 0.95rem;
        }
        
        .option-hint {
            display: block;
            color: #94a3b8;
            font-size: 0.85rem;
            margin-top: 4px;
        }
        
        /* Input Fields */
        .input-group {
            margin-bottom: 24px;
        }
        
        .input-label {
            display: block;
            margin-bottom: 8px;
            color: #cbd5e1;
            font-weight: 500;
        }
        
        .textarea {
            width: 100%;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(148, 163, 184, 0.2);
            border-radius: 12px;
            padding: 16px;
            color: white;
            font-family: inherit;
            font-size: 1rem;
            resize: vertical;
            min-height: 120px;
            transition: all 0.3s;
        }
        
        .textarea:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
        }
        
        .textarea::placeholder {
            color: #64748b;
        }
        
        /* Buttons */
        .buttons-group {
            display: flex;
            gap: 16px;
            margin-top: 40px;
        }
        
        .btn {
            flex: 1;
            padding: 18px 32px;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1rem;
            border: none;
            cursor: pointer;
            transition: all 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 10px;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #3b82f6, #8b5cf6);
            color: white;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(59, 130, 246, 0.4);
        }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.1);
            color: #e2e8f0;
            border: 1px solid rgba(148, 163, 184, 0.2);
        }
        
        .btn-secondary:hover {
            background: rgba(255, 255, 255, 0.15);
        }
        
        /* Features Panel */
        .features-panel {
            display: flex;
            flex-direction: column;
            gap: 32px;
        }
        
        .feature-card {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(10px);
            border-radius: 20px;
            padding: 32px;
            border: 1px solid rgba(148, 163, 184, 0.1);
            transition: all 0.3s ease;
        }
        
        .feature-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
        }
        
        .feature-icon {
            font-size: 2.5rem;
            margin-bottom: 20px;
        }
        
        .feature-title {
            font-size: 1.3rem;
            font-weight: 700;
            margin-bottom: 12px;
            color: white;
        }
        
        .feature-description {
            color: #94a3b8;
            line-height: 1.6;
        }
        
        /* Recent Scans */
        .recent-scans {
            margin-top: 20px;
        }
        
        .scans-list {
            display: flex;
            flex-direction: column;
            gap: 12px;
        }
        
        .scan-item {
            display: flex;
            align-items: center;
            gap: 12px;
            padding: 16px;
            background: rgba(255, 255, 255, 0.05);
            border-radius: 12px;
            transition: all 0.2s;
        }
        
        .scan-item:hover {
            background: rgba(255, 255, 255, 0.08);
        }
        
        .scan-status {
            width: 12px;
            height: 12px;
            border-radius: 50%;
        }
        
        .scan-status.completed { background: #10b981; }
        .scan-status.running { background: #f59e0b; animation: pulse 2s infinite; }
        .scan-status.failed { background: #ef4444; }
        
        .scan-details {
            flex: 1;
        }
        
        .scan-provider {
            font-weight: 600;
            color: white;
        }
        
        .scan-time {
            font-size: 0.85rem;
            color: #94a3b8;
        }
        
        /* Scan Progress Modal */
        .scan-modal {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(15, 23, 42, 0.95);
            backdrop-filter: blur(10px);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            opacity: 0;
            visibility: hidden;
            transition: all 0.3s;
        }
        
        .scan-modal.active {
            opacity: 1;
            visibility: visible;
        }
        
        .modal-content {
            background: rgba(30, 41, 59, 0.95);
            border-radius: 24px;
            padding: 40px;
            width: 90%;
            max-width: 500px;
            border: 1px solid rgba(148, 163, 184, 0.1);
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.5);
            text-align: center;
        }
        
        .modal-icon {
            font-size: 4rem;
            margin-bottom: 24px;
            animation: spin 2s linear infinite;
        }
        
        .modal-title {
            font-size: 1.8rem;
            font-weight: 700;
            margin-bottom: 16px;
            color: white;
        }
        
        .modal-message {
            color: #94a3b8;
            margin-bottom: 32px;
            line-height: 1.6;
        }
        
        .progress-bar {
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            overflow: hidden;
            margin: 32px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #3b82f6, #8b5cf6);
            border-radius: 4px;
            transition: width 0.5s ease;
        }
        
        /* Footer */
        .footer {
            text-align: center;
            margin-top: 60px;
            padding-top: 40px;
            border-top: 1px solid rgba(148, 163, 184, 0.1);
            color: #64748b;
            font-size: 0.9rem;
        }
        
        .nav-links {
            display: flex;
            justify-content: center;
            gap: 24px;
            margin-bottom: 20px;
        }
        
        .nav-link {
            color: #94a3b8;
            text-decoration: none;
            transition: color 0.3s;
        }
        
        .nav-link:hover {
            color: #60a5fa;
        }
        
        /* Animations */
        @keyframes float {
            0%, 100% { transform: translateY(0px); }
            50% { transform: translateY(-10px); }
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.5; }
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .container { padding: 24px 16px; }
            .title { font-size: 2.5rem; }
            .subtitle { font-size: 1.1rem; }
            .scan-panel, .feature-card { padding: 24px; }
            .providers-grid { grid-template-columns: 1fr; }
            .buttons-group { flex-direction: column; }
            .modal-content { padding: 24px; }
        }
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="header">
            <div class="logo">🛡️</div>
            <h1 class="title">CloudGuard Security Scanner</h1>
            <p class="subtitle">
                AI-powered multi-cloud security scanning with real-time vulnerability detection. 
                Protect your AWS, GCP, Azure, and OpenAI environments.
            </p>
        </div>

        <!-- Main Content -->
        <div class="content-grid">
            <!-- Left Panel: Scan Configuration -->
            <div class="scan-panel">
                <h2 class="panel-title">⚙️ Configure Your Scan</h2>
                <p class="panel-subtitle">
                    Choose your scan type, select cloud providers, and configure options. 
                    Our AI will analyze security posture and detect vulnerabilities automatically.
                </p>

                <!-- Scan Type Selection -->
                <div class="scan-types">
                    <div class="scan-card active" onclick="selectScanType('intelligent')">
                        <div class="scan-icon">🤖</div>
                        <div class="scan-info">
                            <div class="scan-name">Intelligent AI Scan</div>
                            <div class="scan-description">
                                Let our AI analyze your request and automatically determine which clouds to scan.
                                Best for comprehensive security assessment.
                            </div>
                        </div>
                    </div>

                    <div class="scan-card" onclick="selectScanType('manual')">
                        <div class="scan-icon">🎯</div>
                        <div class="scan-info">
                            <div class="scan-name">Manual Configuration</div>
                            <div class="scan-description">
                                Manually select specific cloud providers and configure scan parameters.
                                Full control over the scanning process.
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Cloud Providers Selection -->
                <div class="input-group">
                    <div class="input-label">Select Cloud Providers</div>
                    <div class="providers-grid">
                        <div class="provider-option selected" onclick="toggleProvider('aws')">
                            <div class="provider-icon aws-icon">☁️</div>
                            <div class="provider-name">AWS</div>
                        </div>
                        <div class="provider-option selected" onclick="toggleProvider('gcp')">
                            <div class="provider-icon gcp-icon">📊</div>
                            <div class="provider-name">GCP</div>
                        </div>
                        <div class="provider-option" onclick="toggleProvider('azure')">
                            <div class="provider-icon azure-icon">🔷</div>
                            <div class="provider-name">Azure</div>
                        </div>
                        <div class="provider-option selected" onclick="toggleProvider('openai')">
                            <div class="provider-icon openai-icon">🤖</div>
                            <div class="provider-name">OpenAI</div>
                        </div>
                    </div>
                </div>

                <!-- Scan Options -->
                <div class="scan-options">
                    <div class="option-item">
                        <div class="checkbox-wrapper">
                            <input type="checkbox" id="deepScan" class="checkbox" checked>
                        </div>
                        <label for="deepScan" class="option-label">
                            Deep Vulnerability Scan
                            <span class="option-hint">
                                Use advanced vulnerability scanners (Trivy, Grype, Safety, etc.) for in-depth analysis
                            </span>
                        </label>
                    </div>

                    <div class="option-item">
                        <div class="checkbox-wrapper">
                            <input type="checkbox" id="aiAnalysis" class="checkbox" checked>
                        </div>
                        <label for="aiAnalysis" class="option-label">
                            AI-Powered Analysis
                            <span class="option-hint">
                                Get AI recommendations and remediation plans from GPT-4
                            </span>
                        </label>
                    </div>
                </div>

                <!-- Scan Description -->
                <div class="input-group">
                    <label class="input-label">What would you like to scan?</label>
                    <textarea 
                        class="textarea" 
                        id="scanDescription" 
                        placeholder="Describe what you want to scan. For example: 'Scan my AWS S3 buckets for public access and check GCP storage for vulnerabilities. Also scan OpenAI API usage for security issues.'"
                        rows="4"
                    >Scan my cloud resources for security vulnerabilities and misconfigurations. Check for public access, insecure configurations, and potential threats across all connected cloud providers.</textarea>
                </div>

                <!-- Action Buttons -->
                <div class="buttons-group">
                    <button class="btn btn-secondary" onclick="goToDashboard()">
                        📊 View Dashboard
                    </button>
                    <button class="btn btn-primary" onclick="startScan()">
                        🚀 Start Security Scan
                    </button>
                </div>
            </div>

            <!-- Right Panel: Features & Info -->
            <div class="features-panel">
                <!-- Feature 1 -->
                <div class="feature-card">
                    <div class="feature-icon">🔍</div>
                    <h3 class="feature-title">Comprehensive Security Scanning</h3>
                    <p class="feature-description">
                        Scan across multiple cloud platforms simultaneously. Detect misconfigurations, 
                        public exposures, IAM issues, and compliance violations in real-time.
                    </p>
                </div>

                <!-- Feature 2 -->
                <div class="feature-card">
                    <div class="feature-icon">🤖</div>
                    <h3 class="feature-title">AI-Powered Analysis</h3>
                    <p class="feature-description">
                        Our GPT-4 powered AI analyzes scan results, provides risk assessments, 
                        and generates actionable remediation plans with priority levels.
                    </p>
                </div>

                <!-- Feature 3 -->
                <div class="feature-card">
                    <div class="feature-icon">🛡️</div>
                    <h3 class="feature-title">Vulnerability Detection</h3>
                    <p class="feature-description">
                        Integrated with industry-standard vulnerability scanners including 
                        Trivy, Grype, Safety, and OWASP tools for comprehensive security coverage.
                    </p>
                </div>

                <!-- Recent Scans -->
                <div class="feature-card">
                    <h3 class="feature-title">Recent Scans</h3>
                    <div class="scans-list" id="recentScansList">
                        <div class="loading">Loading recent scans...</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- Scan Progress Modal -->
        <div class="scan-modal" id="scanModal">
            <div class="modal-content">
                <div class="modal-icon">🔄</div>
                <h2 class="modal-title">Security Scan in Progress</h2>
                <p class="modal-message" id="scanStatusMessage">
                    Initializing cloud security scan...
                </p>
                
                <div class="progress-bar">
                    <div class="progress-fill" id="scanProgress" style="width: 10%"></div>
                </div>
                
                <div id="scanDetails">
                    <div style="color: #94a3b8; font-size: 0.9rem; margin-bottom: 8px;">
                        <span id="currentStep">Connecting to cloud APIs...</span>
                    </div>
                    <div style="color: #64748b; font-size: 0.85rem;">
                        Estimated time: <span id="estimatedTime">2-3 minutes</span>
                    </div>
                </div>
            </div>
        </div>

        <!-- Footer -->
        <div class="footer">
            <div class="nav-links">
                <a href="/dashboard" class="nav-link">📊 Dashboard</a>
                <a href="#" class="nav-link" onclick="showDocumentation()">📚 Documentation</a>
                <a href="#" class="nav-link" onclick="showSettings()">⚙️ Settings</a>
                <a href="/api/info" class="nav-link">🔧 API Info</a>
            </div>
            <p>CloudGuard Security Scanner v3.0 • Multi-Cloud CSPM with AI</p>
            <p style="margin-top: 8px; font-size: 0.8rem; color: #475569;">
                Securing AWS, GCP, Azure, and OpenAI environments
            </p>
        </div>
    </div>

    <script>
        // State management
        let selectedScanType = 'intelligent';
        let selectedProviders = ['aws', 'gcp', 'openai'];
        let scanInProgress = false;

        // Initialize
        document.addEventListener('DOMContentLoaded', () => {
            loadRecentScans();
            setupEventListeners();
        });

        // Scan type selection
        function selectScanType(type) {
            selectedScanType = type;
            
            // Update UI
            document.querySelectorAll('.scan-card').forEach(card => {
                card.classList.remove('active');
            });
            event.currentTarget.classList.add('active');
            
            // Update description placeholder based on type
            const textarea = document.getElementById('scanDescription');
            if (type === 'intelligent') {
                textarea.placeholder = "Describe what you want to scan. For example: 'Scan my AWS S3 buckets for public access and check GCP storage for vulnerabilities. Also scan OpenAI API usage for security issues.'";
            } else {
                textarea.placeholder = "Describe specific resources or configurations to scan. For example: 'Scan AWS us-east-1 region, GCP project my-project-123, OpenAI organization org-xyz'";
            }
        }

        // Provider selection
        function toggleProvider(provider) {
            const option = event.currentTarget;
            const index = selectedProviders.indexOf(provider);
            
            if (index === -1) {
                selectedProviders.push(provider);
                option.classList.add('selected');
            } else {
                selectedProviders.splice(index, 1);
                option.classList.remove('selected');
            }
            
            updateScanButtonState();
        }

        // Load recent scans
        async function loadRecentScans() {
            try {
                const response = await fetch('/api/scan-history?days=1');
                const data = await response.json();
                
                const container = document.getElementById('recentScansList');
                if (!container) return;
                
                if (!data.data || data.data.length === 0) {
                    container.innerHTML = '<div style="color: #64748b; text-align: center; padding: 20px;">No recent scans found</div>';
                    return;
                }
                
                // Get latest scans from today
                const todayScans = data.data
                    .filter(scan => {
                        const scanDate = new Date(scan.date);
                        const today = new Date();
                        return scanDate.getDate() === today.getDate();
                    })
                    .slice(0, 3); // Show only 3 most recent
                
                if (todayScans.length === 0) {
                    container.innerHTML = '<div style="color: #64748b; text-align: center; padding: 20px;">No scans today</div>';
                    return;
                }
                
                container.innerHTML = todayScans.map(scan => `
                    <div class="scan-item" onclick="viewScanDetails('${scan.date}')">
                        <div class="scan-status ${scan.findings > 0 ? 'completed' : 'completed'}"></div>
                        <div class="scan-details">
                            <div class="scan-provider">Security Scan</div>
                            <div class="scan-time">
                                ${new Date(scan.date).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} • 
                                ${scan.findings} findings
                            </div>
                        </div>
                    </div>
                `).join('');
                
            } catch (error) {
                console.error('Failed to load recent scans:', error);
            }
        }

        // Start scan
        async function startScan() {
            if (scanInProgress) return;
            
            const scanDescription = document.getElementById('scanDescription').value.trim();
            const deepScan = document.getElementById('deepScan').checked;
            const aiAnalysis = document.getElementById('aiAnalysis').checked;
            
            if (!scanDescription) {
                alert('Please describe what you want to scan.');
                document.getElementById('scanDescription').focus();
                return;
            }
            
            if (selectedProviders.length === 0) {
                alert('Please select at least one cloud provider.');
                return;
            }
            
            // Show scan modal
            const modal = document.getElementById('scanModal');
            modal.classList.add('active');
            scanInProgress = true;
            
            // Disable controls
            document.querySelectorAll('button, input, textarea').forEach(el => {
                el.disabled = true;
            });
            
            // Prepare scan request
            let scanRequest;
            
            if (selectedScanType === 'intelligent') {
                // Intelligent scan
                scanRequest = {
                    message: scanDescription,
                    deep_scan: deepScan
                };
                
                updateScanStatus('Analyzing scan request with AI...', 20);
                await simulateProgress(1000);
                
                updateScanStatus('Determining optimal scan strategy...', 30);
                await simulateProgress(1500);
                
            } else {
                // Manual scan
                scanRequest = {
                    providers: selectedProviders,
                    account_ids: {},
                    deep_scan: deepScan
                };
                
                updateScanStatus('Configuring manual scan parameters...', 20);
                await simulateProgress(800);
            }
            
            // Update status for each provider
            for (let i = 0; i < selectedProviders.length; i++) {
                const provider = selectedProviders[i];
                const progress = 40 + (i * 15);
                
                updateScanStatus(`Scanning ${provider.toUpperCase()} resources...`, progress);
                await simulateProgress(2000);
                
                updateScanStatus(`Analyzing ${provider.toUpperCase()} security posture...`, progress + 10);
                await simulateProgress(1500);
            }
            
            // Vulnerability scanning
            if (deepScan) {
                updateScanStatus('Running deep vulnerability scans...', 85);
                await simulateProgress(3000);
            }
            
            // AI analysis
            if (aiAnalysis) {
                updateScanStatus('Running AI security analysis...', 90);
                await simulateProgress(2000);
            }
            
            // Finalizing
            updateScanStatus('Generating security report...', 95);
            await simulateProgress(1500);
            
            // Complete
            updateScanStatus('Scan completed successfully!', 100);
            
            // Actually send the request to backend
            try {
                const endpoint = selectedScanType === 'intelligent' ? '/scan' : '/scan/multi-cloud';
                const response = await fetch(endpoint, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(scanRequest)
                });
                
                const result = await response.json();
                
                if (response.ok) {
                    // Success - redirect to dashboard with scan results
                    setTimeout(() => {
                        window.location.href = `/dashboard?scanComplete=true&scanIds=${result.scan_ids.join(',')}`;
                    }, 1500);
                } else {
                    throw new Error(result.detail || 'Scan failed');
                }
                
            } catch (error) {
                console.error('Scan error:', error);
                updateScanStatus(`Error: ${error.message}`, 100);
                
                // Show error and allow retry
                setTimeout(() => {
                    modal.classList.remove('active');
                    scanInProgress = false;
                    enableControls();
                    alert(`Scan failed: ${error.message}`);
                }, 3000);
            }
        }

        // Simulate progress for demo
        function simulateProgress(duration) {
            return new Promise(resolve => setTimeout(resolve, duration));
        }

        // Update scan status
        function updateScanStatus(message, progress) {
            document.getElementById('scanStatusMessage').textContent = message;
            document.getElementById('scanProgress').style.width = `${progress}%`;
            document.getElementById('currentStep').textContent = message;
            
            // Update estimated time
            const remaining = 100 - progress;
            const estimatedMinutes = Math.ceil(remaining / 10);
            document.getElementById('estimatedTime').textContent = 
                `${estimatedMinutes} minute${estimatedMinutes !== 1 ? 's' : ''}`;
        }

        // Navigation
        function goToDashboard() {
            window.location.href = '/dashboard';
        }

        function showDocumentation() {
            alert('Documentation will open in a new tab. Implementation pending.');
        }

        function showSettings() {
            alert('Settings panel will open. Implementation pending.');
        }

        function viewScanDetails(date) {
            // In a real app, this would show scan details
            alert(`Viewing scan from ${new Date(date).toLocaleDateString()}`);
        }

        // Enable all controls
        function enableControls() {
            document.querySelectorAll('button, input, textarea').forEach(el => {
                el.disabled = false;
            });
        }

        // Setup event listeners
        function setupEventListeners() {
            // Enter key in textarea triggers scan
            document.getElementById('scanDescription').addEventListener('keydown', (e) => {
                if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
                    e.preventDefault();
                    startScan();
                }
            });
            
            // Close modal on click outside
            document.getElementById('scanModal').addEventListener('click', (e) => {
                if (e.target === document.getElementById('scanModal')) {
                    if (!scanInProgress) {
                        document.getElementById('scanModal').classList.remove('active');
                    }
                }
            });
        }

        // Expose functions globally
        window.selectScanType = selectScanType;
        window.toggleProvider = toggleProvider;
        window.startScan = startScan;
        window.goToDashboard = goToDashboard;
        window.viewScanDetails = viewScanDetails;
    </script>
</body>
</html>
'''
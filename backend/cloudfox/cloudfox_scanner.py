# backend/cloudfox/cloudfox_scanner.py

"""
CloudFox Integration for AWS Penetration Testing
https://github.com/BishopFox/cloudfox

CloudFox is an open-source command-line tool for penetration testing
and offensive security in AWS environments.
"""

import os
import json
import logging
import asyncio
import subprocess
import tempfile
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from backend.utils.audit_logger import AuditLogger
from backend.mcp.mcp_base import CloudResource, SecurityFinding, Severity

logger = logging.getLogger("cloudfox_scanner")


@dataclass
class CloudFoxFinding:
    """CloudFox scan finding"""
    check_name: str
    severity: str
    title: str
    description: str
    resource_arn: Optional[str]
    recommendation: str
    raw_data: Dict[str, Any]


class CloudFoxScanner:
    """
    CloudFox Scanner Integration
    
    CloudFox provides:
    - Attack path enumeration
    - Secrets discovery (EC2 userdata, environment vars)
    - Permission analysis (admin roles, overprivileged principals)
    - Network exposure (public endpoints, open ports)
    - Trust relationship analysis
    """
    
    def __init__(self):
        self.cloudfox_path = self._find_cloudfox()
        self.available = self.cloudfox_path is not None
        
        if not self.available:
            logger.warning("CloudFox not found. Install: go install github.com/BishopFox/cloudfox@latest")
    
    def _find_cloudfox(self) -> Optional[str]:
        """Find CloudFox executable"""
        # Minimal diagnostic logging
        logger.debug(f"Checking CloudFox availability (UID: {os.getuid() if hasattr(os, 'getuid') else 'unknown'})")
        
        # Check common locations
        locations = [
            "cloudfox",  # In PATH
            "/usr/local/bin/cloudfox",
            os.path.expanduser("~/go/bin/cloudfox"),
            "./cloudfox"
        ]
        
        for location in locations:
            try:
                result = subprocess.run(
                    [location, "--version"],
                    capture_output=True,
                    timeout=5,
                    text=True
                )
                if result.returncode == 0:
                    logger.info(f"CloudFox found at: {location}")
                    return location
                else:
                    logger.debug(f"CloudFox at {location} exists but --version failed (code {result.returncode})")
            except FileNotFoundError:
                continue
            except subprocess.TimeoutExpired:
                logger.warning(f"CloudFox at {location} timed out while checking version")
                continue
            except OSError as e:
                if "Exec format error" in str(e):
                    logger.error(f"❌ Binary architecture mismatch for CloudFox at {location}: {e}")
                    logger.error("   This usually means an ARM64 binary is being run on x86_64 or vice-versa.")
                else:
                    logger.error(f"⚠ OSError checking CloudFox at {location}: {e}")
                continue
            except Exception as e:
                logger.error(f"Unexpected error checking CloudFox at {location}: {e}")
                continue
        
        return None
    
    async def scan_aws_account(
        self,
        profile: str = None,
        region: str = "us-east-1",
        checks: List[str] = None
    ) -> Dict[str, Any]:
        """
        Run CloudFox scan on AWS account
        
        Args:
            profile: AWS CLI profile name
            region: AWS region
            checks: List of specific checks to run (None = all checks)
        
        Returns:
            Dict with scan results
        """
        if not self.available:
            return {
                "error": "CloudFox not installed",
                "install_guide": "go install github.com/BishopFox/cloudfox@latest"
            }
        
        profile = profile or os.getenv("AWS_PROFILE", "default")
        logger.info(f"Starting CloudFox scan (profile={profile}, region={region})...")
        
        # Create temporary directory for results
        with tempfile.TemporaryDirectory() as temp_dir:
            results = {
                "scan_id": f"cloudfox-{datetime.utcnow().timestamp()}",
                "timestamp": datetime.utcnow().isoformat(),
                "profile": profile,
                "region": region,
                "findings": [],
                "summary": {},
                "raw_results": {}
            }
            
            # Run checks
            if checks is None:
                # Run all checks
                checks = [
                    "all-checks"  # CloudFox convenience command
                ]
            
            for check in checks:
                try:
                    check_result = await self._run_check(
                        check=check,
                        profile=profile,
                        region=region,
                        output_dir=temp_dir
                    )
                    
                    results["raw_results"][check] = check_result
                    
                    # Parse findings
                    findings = self._parse_check_output(check, check_result)
                    results["findings"].extend(findings)
                
                except Exception as e:
                    logger.error(f"CloudFox check '{check}' failed: {e}")
                    results["raw_results"][check] = {"error": str(e)}
            
            # Generate summary
            results["summary"] = self._generate_summary(results["findings"])
            
            return results
    
    async def _run_check(
        self,
        check: str,
        profile: str,
        region: str,
        output_dir: str
    ) -> Dict[str, Any]:
        """Run a specific CloudFox check"""
        
        cmd = [
            self.cloudfox_path,
            "aws",
            "--profile", profile,
            "--region", region,
            "--output", "json",
            "--output-dir", output_dir,
            check
        ]
        
        logger.info(f"Running CloudFox: {' '.join(cmd)}")
        
        try:
            # Audit logging setup
            auditor = AuditLogger(f"cloudfox/{check}", "pentest", "aws")
            auditor.log_input({"check": check, "profile": profile, "region": region, "cmd": cmd})

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=300  # 5 minute timeout
            )
            
            stdout_str = stdout.decode() if stdout else ""
            stderr_str = stderr.decode() if stderr else ""

            if process.returncode != 0:
                error_msg = stderr_str if stderr_str else "Unknown error"
                auditor.log_failure(error_msg, output=stdout_str)
                raise RuntimeError(f"CloudFox failed: {error_msg}")
            
            # Parse JSON output
            output = stdout_str
            
            # CloudFox may output multiple JSON objects or CSV
            # Try to parse as JSON first
            try:
                result = json.loads(output)
                auditor.log_success(result)
                return result
            except json.JSONDecodeError:
                # If not JSON, return raw output
                result = {"raw_output": output}
                auditor.log_success(result)
                return result
        
        except asyncio.TimeoutError:
            msg = f"CloudFox check '{check}' timed out"
            auditor.log_failure(msg)
            raise RuntimeError(msg)
        except Exception as e:
            msg = f"CloudFox execution failed: {e}"
            if 'auditor' in locals():
                auditor.log_failure(msg)
            raise RuntimeError(msg)
    
    def _parse_check_output(self, check: str, result: Dict[str, Any]) -> List[CloudFoxFinding]:
        """Parse CloudFox check output into findings"""
        findings = []
        
        if "error" in result:
            return findings
        
        # CloudFox-specific parsing based on check type
        if check == "all-checks" or "endpoints" in check:
            findings.extend(self._parse_endpoints(result))
        
        if check == "all-checks" or "secrets" in check:
            findings.extend(self._parse_secrets(result))
        
        if check == "all-checks" or "principals" in check:
            findings.extend(self._parse_principals(result))
        
        if check == "all-checks" or "role-trusts" in check:
            findings.extend(self._parse_role_trusts(result))
        
        if check == "all-checks" or "env-vars" in check:
            findings.extend(self._parse_env_vars(result))
        
        if check == "all-checks" or "access-keys" in check:
            findings.extend(self._parse_access_keys(result))
        
        return findings
    
    def _parse_endpoints(self, result: Dict[str, Any]) -> List[CloudFoxFinding]:
        """Parse endpoint findings"""
        findings = []
        
        # CloudFox endpoints shows publicly accessible resources
        endpoints = result.get("endpoints", result.get("data", []))
        
        for endpoint in endpoints:
            if isinstance(endpoint, dict):
                findings.append(CloudFoxFinding(
                    check_name="endpoints",
                    severity="HIGH" if endpoint.get("public") else "MEDIUM",
                    title=f"Exposed Endpoint: {endpoint.get('name', 'Unknown')}",
                    description=f"Endpoint {endpoint.get('arn', 'unknown')} is accessible from the internet",
                    resource_arn=endpoint.get("arn"),
                    recommendation="Review endpoint exposure and implement network restrictions",
                    raw_data=endpoint
                ))
        
        return findings
    
    def _parse_secrets(self, result: Dict[str, Any]) -> List[CloudFoxFinding]:
        """Parse secrets findings"""
        findings = []
        
        secrets = result.get("secrets", result.get("data", []))
        
        for secret in secrets:
            if isinstance(secret, dict):
                findings.append(CloudFoxFinding(
                    check_name="secrets",
                    severity="CRITICAL",
                    title=f"Secret Exposed: {secret.get('type', 'Unknown')}",
                    description=f"Secret found in {secret.get('location', 'unknown location')}: {secret.get('value', '')[:50]}...",
                    resource_arn=secret.get("resource_arn"),
                    recommendation="Remove hardcoded secrets and use AWS Secrets Manager",
                    raw_data=secret
                ))
        
        return findings
    
    def _parse_principals(self, result: Dict[str, Any]) -> List[CloudFoxFinding]:
        """Parse principals with admin permissions"""
        findings = []
        
        principals = result.get("principals", result.get("data", []))
        
        for principal in principals:
            if isinstance(principal, dict) and principal.get("is_admin"):
                findings.append(CloudFoxFinding(
                    check_name="principals",
                    severity="HIGH",
                    title=f"Admin Principal: {principal.get('name', 'Unknown')}",
                    description=f"Principal {principal.get('arn', 'unknown')} has administrator permissions",
                    resource_arn=principal.get("arn"),
                    recommendation="Apply principle of least privilege, use custom policies instead of AdministratorAccess",
                    raw_data=principal
                ))
        
        return findings
    
    def _parse_role_trusts(self, result: Dict[str, Any]) -> List[CloudFoxFinding]:
        """Parse role trust relationships"""
        findings = []
        
        trusts = result.get("role_trusts", result.get("data", []))
        
        for trust in trusts:
            if isinstance(trust, dict):
                trusted_principal = trust.get("trusted_principal", "")
                
                # Flag overly permissive trusts
                if "*" in trusted_principal or "root" in trusted_principal.lower():
                    findings.append(CloudFoxFinding(
                        check_name="role-trusts",
                        severity="HIGH",
                        title=f"Permissive Role Trust: {trust.get('role_name', 'Unknown')}",
                        description=f"Role {trust.get('role_arn', 'unknown')} trusts {trusted_principal}",
                        resource_arn=trust.get("role_arn"),
                        recommendation="Restrict role trust to specific principals",
                        raw_data=trust
                    ))
        
        return findings
    
    def _parse_env_vars(self, result: Dict[str, Any]) -> List[CloudFoxFinding]:
        """Parse environment variables for secrets"""
        findings = []
        
        env_vars = result.get("env_vars", result.get("data", []))
        
        for var in env_vars:
            if isinstance(var, dict):
                name = var.get("name", "").upper()
                
                # Check for common secret patterns
                secret_patterns = ["KEY", "SECRET", "PASSWORD", "TOKEN", "API", "CREDENTIAL"]
                
                if any(pattern in name for pattern in secret_patterns):
                    findings.append(CloudFoxFinding(
                        check_name="env-vars",
                        severity="HIGH",
                        title=f"Potential Secret in Environment: {name}",
                        description=f"Environment variable '{name}' may contain sensitive data in {var.get('resource', 'unknown')}",
                        resource_arn=var.get("resource_arn"),
                        recommendation="Use AWS Secrets Manager or Parameter Store for sensitive values",
                        raw_data=var
                    ))
        
        return findings
    
    def _parse_access_keys(self, result: Dict[str, Any]) -> List[CloudFoxFinding]:
        """Parse access key findings"""
        findings = []
        
        keys = result.get("access_keys", result.get("data", []))
        
        for key in keys:
            if isinstance(key, dict):
                age_days = key.get("age_days", 0)
                
                if age_days > 90:
                    findings.append(CloudFoxFinding(
                        check_name="access-keys",
                        severity="HIGH" if age_days > 180 else "MEDIUM",
                        title=f"Old Access Key: {key.get('key_id', 'Unknown')}",
                        description=f"Access key for {key.get('user', 'unknown')} is {age_days} days old",
                        resource_arn=None,
                        recommendation="Rotate access keys every 90 days",
                        raw_data=key
                    ))
        
        return findings
    
    def _generate_summary(self, findings: List[CloudFoxFinding]) -> Dict[str, Any]:
        """Generate summary statistics"""
        return {
            "total_findings": len(findings),
            "by_severity": {
                "CRITICAL": len([f for f in findings if f.severity == "CRITICAL"]),
                "HIGH": len([f for f in findings if f.severity == "HIGH"]),
                "MEDIUM": len([f for f in findings if f.severity == "MEDIUM"]),
                "LOW": len([f for f in findings if f.severity == "LOW"])
            },
            "by_check": {
                check: len([f for f in findings if f.check_name == check])
                for check in set(f.check_name for f in findings)
            }
        }
    
    def convert_to_security_findings(
        self,
        cloudfox_findings: List[CloudFoxFinding],
        resource: CloudResource
    ) -> List[SecurityFinding]:
        """Convert CloudFox findings to SecurityFinding format"""
        
        security_findings = []
        
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW
        }
        
        for cf_finding in cloudfox_findings:
            finding = SecurityFinding(
                resource=resource,
                severity=severity_map.get(cf_finding.severity, Severity.MEDIUM),
                issue=f"[CLOUDFOX-{cf_finding.check_name.upper()}] {cf_finding.title}",
                description=cf_finding.description,
                recommendation=cf_finding.recommendation,
                compliance=["AWS-Penetration-Testing"],
                detection_tool="CLOUDFOX",
                tool_category="pentest"
            )
            
            security_findings.append(finding)
        
        return security_findings


# Singleton instance
cloudfox_scanner = CloudFoxScanner()


# Quick check functions for specific vulnerabilities

async def check_for_secrets(profile: str = None) -> List[CloudFoxFinding]:
    """Quick check for exposed secrets"""
    if not cloudfox_scanner.available:
        return []
    
    result = await cloudfox_scanner.scan_aws_account(
        profile=profile,
        checks=["secrets", "env-vars"]
    )
    
    return result.get("findings", [])


async def check_for_admin_principals(profile: str = None) -> List[CloudFoxFinding]:
    """Quick check for admin principals"""
    if not cloudfox_scanner.available:
        return []
    
    result = await cloudfox_scanner.scan_aws_account(
        profile=profile,
        checks=["principals"]
    )
    
    return result.get("findings", [])


async def check_exposed_endpoints(profile: str = None) -> List[CloudFoxFinding]:
    """Quick check for exposed endpoints"""
    if not cloudfox_scanner.available:
        return []
    
    result = await cloudfox_scanner.scan_aws_account(
        profile=profile,
        checks=["endpoints"]
    )
    
    return result.get("findings", [])


async def full_offensive_scan(profile: str = None) -> Dict[str, Any]:
    """
    Run a complete offensive security scan with CloudFox
    
    This is the most comprehensive scan, checking:
    - All attack paths
    - Secrets and credentials
    - Admin permissions
    - Network exposure
    - Trust relationships
    """
    if not cloudfox_scanner.available:
        return {
            "error": "CloudFox not installed",
            "install_guide": "Install CloudFox: go install github.com/BishopFox/cloudfox@latest"
        }
    
    result = await cloudfox_scanner.scan_aws_account(
        profile=profile,
        checks=["all-checks"]
    )
    
    return result


# CLI-style output formatter
def format_cloudfox_report(scan_result: Dict[str, Any]) -> str:
    """Format CloudFox results as a text report"""
    
    report = []
    report.append("=" * 80)
    report.append("CloudFox Penetration Testing Report")
    report.append("=" * 80)
    report.append(f"Scan ID: {scan_result.get('scan_id')}")
    report.append(f"Timestamp: {scan_result.get('timestamp')}")
    report.append(f"Profile: {scan_result.get('profile')}")
    report.append("")
    
    # Summary
    summary = scan_result.get("summary", {})
    report.append("SUMMARY")
    report.append("-" * 80)
    report.append(f"Total Findings: {summary.get('total_findings', 0)}")
    
    by_severity = summary.get("by_severity", {})
    report.append(f"  Critical: {by_severity.get('CRITICAL', 0)}")
    report.append(f"  High:     {by_severity.get('HIGH', 0)}")
    report.append(f"  Medium:   {by_severity.get('MEDIUM', 0)}")
    report.append(f"  Low:      {by_severity.get('LOW', 0)}")
    report.append("")
    
    # Findings
    findings = scan_result.get("findings", [])
    if findings:
        report.append("FINDINGS")
        report.append("-" * 80)
        
        for i, finding in enumerate(findings, 1):
            report.append(f"\n[{i}] {finding.title}")
            report.append(f"    Severity: {finding.severity}")
            report.append(f"    Check: {finding.check_name}")
            report.append(f"    Description: {finding.description}")
            report.append(f"    Recommendation: {finding.recommendation}")
            if finding.resource_arn:
                report.append(f"    Resource: {finding.resource_arn}")
    
    report.append("")
    report.append("=" * 80)
    
    return "\n".join(report)


if __name__ == "__main__":
    # Test CloudFox availability
    print("CloudFox Scanner Test")
    print("=" * 80)
    print(f"CloudFox Available: {cloudfox_scanner.available}")
    
    if cloudfox_scanner.available:
        print(f"CloudFox Path: {cloudfox_scanner.cloudfox_path}")
        print("\nRun: python -m backend.cloudfox.cloudfox_scanner to test scanning")
    else:
        print("\nCloudFox not found. Install it:")
        print("  go install github.com/BishopFox/cloudfox@latest")
        print("\nOr add it to your PATH")

"""Scanner contracts for the four intentionally vulnerable demo labs."""

import unittest
from pathlib import Path

import yaml
from google.cloud import compute_v1

from backend.mcp_servers.aws_server import AWSMCPServer
from backend.mcp_servers.gcp_server import GCPMCPServer
from backend.mcp_servers.iac_server import create_iac_server
from backend.mcp_servers.kubernetes_server import KubernetesMCPServer


ROOT = Path(__file__).resolve().parents[2]
LABS = ROOT / "grc-platform" / "cloudguard-test-labs"


class FakeIamClient:
    def list_mfa_devices(self, **_kwargs):
        return {"MFADevices": []}

    def list_user_policies(self, **_kwargs):
        return {"PolicyNames": ["CloudGuardSandboxWildcard"]}

    def get_user_policy(self, **_kwargs):
        return {
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            }
        }

    def list_access_keys(self, **_kwargs):
        return {"AccessKeyMetadata": []}


class FakeFirewallClient:
    def __init__(self, firewalls):
        self.firewalls = firewalls

    def list(self, request):
        assert request.project == "cloudguard-sandbox"
        return self.firewalls


class VulnerableLabContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_aws_lab_rules_are_detected(self):
        server = AWSMCPServer.__new__(AWSMCPServer)
        server.iam = FakeIamClient()

        iam_result = await server._check_iam_security("cg-test-no-mfa")
        iam_issues = {finding["issue"] for finding in iam_result["findings"]}
        self.assertIn("IAM User Without MFA", iam_issues)
        self.assertIn("IAM User Has Wildcard Administrative Policy", iam_issues)

        group_findings = server._check_security_group_security({
            "group_id": "sg-cloudguard-test",
            "ip_permissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
                {
                    "IpProtocol": "-1",
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                },
            ],
        })
        self.assertEqual({finding["severity"] for finding in group_findings}, {"HIGH", "CRITICAL"})

    async def test_gcp_lab_firewalls_are_detected(self):
        admin_rule = compute_v1.Firewall(
            name="cg-open-admin",
            direction="INGRESS",
            source_ranges=["0.0.0.0/0"],
            allowed=[compute_v1.Allowed(I_p_protocol="tcp", ports=["22", "3389", "5432"])],
        )
        all_rule = compute_v1.Firewall(
            name="cg-open-all",
            direction="INGRESS",
            source_ranges=["0.0.0.0/0"],
            allowed=[compute_v1.Allowed(I_p_protocol="all")],
        )
        server = GCPMCPServer.__new__(GCPMCPServer)
        server.project_id = "cloudguard-sandbox"
        server.firewall_client = FakeFirewallClient([admin_rule, all_rule])

        result = await server._check_firewall_security()

        self.assertEqual(result["count"], 2)
        self.assertEqual({finding["severity"] for finding in result["findings"]}, {"HIGH", "CRITICAL"})

    async def test_kubernetes_lab_exercises_live_scanner_checks(self):
        path = LABS / "kubernetes" / "vulnerable-k8s.yaml"
        documents = [doc for doc in yaml.safe_load_all(path.read_text()) if isinstance(doc, dict)]
        server = KubernetesMCPServer({})
        findings = []
        for document in documents:
            resource = server._resource_from_manifest(path, document)
            findings.extend(server._scan_manifest(resource, document))

        issues = {finding["issue"] for finding in findings}
        self.assertTrue(any("runs privileged" in issue for issue in issues))
        self.assertTrue(any("Binding grants cluster-admin" in issue for issue in issues))
        self.assertTrue(any("Service exposes a node port" in issue for issue in issues))
        self.assertTrue(any("Service exposes an external load balancer" in issue for issue in issues))

    async def test_iac_lab_produces_findings_without_cloud_credentials(self):
        files = []
        for path in [
            LABS / "iac" / "terraform" / "vulnerable-aws.tf",
            LABS / "iac" / "cloudformation" / "vulnerable-aws.yaml",
            LABS / "kubernetes" / "vulnerable-k8s.yaml",
        ]:
            files.append({"filename": path.name, "content": path.read_text()})

        result = await create_iac_server({"root_path": str(ROOT)})._full_scan(
            account_id="sandbox-contract-test",
            deep_scan=True,
            files=files,
        )

        self.assertGreaterEqual(len(result["findings"]), 12)
        issues = {finding["issue"] for finding in result["findings"]}
        self.assertTrue(any("public" in issue.lower() for issue in issues))
        self.assertTrue(any("wildcard" in issue.lower() for issue in issues))


if __name__ == "__main__":
    unittest.main()

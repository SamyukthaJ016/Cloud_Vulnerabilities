"""Evidence serialization and external object-storage loading tests."""

import hashlib
import json
import os
import unittest
from io import BytesIO
from unittest.mock import patch

from backend.evidence_payloads import (
    load_evidence_payload,
    scan_result_evidence_payload,
    stored_finding_control,
)
from backend.mcp.mcp_base import CloudResource, ScanResult, SecurityFinding, Severity


class FakeObjectStorageClient:
    def __init__(self, body: bytes):
        self.body = body

    def get_object(self, **_kwargs):
        return {"Body": BytesIO(self.body)}


class EvidencePayloadTests(unittest.TestCase):
    def test_externalized_payload_is_loaded_and_verified(self):
        body = json.dumps({
            "findings": [{
                "issue": "Public bucket",
                "severity": "HIGH",
                "compliance": ["CIS AWS 2.1.5"],
            }],
        }).encode()
        pointer = {"externalized": True, "uri": "s3://evidence/tenant/result.json"}

        with patch.dict(os.environ, {"OBJECT_STORAGE_ENDPOINT_URL": "http://minio:9000"}, clear=False):
            with patch("boto3.client", return_value=FakeObjectStorageClient(body)):
                loaded = load_evidence_payload(
                    pointer,
                    "minio",
                    pointer["uri"],
                    hashlib.sha256(body).hexdigest(),
                )

        self.assertEqual(loaded["findings"][0]["compliance"], ["CIS AWS 2.1.5"])
        self.assertEqual(loaded["findings"][0]["severity"], "HIGH")

    def test_scan_evidence_keeps_findings_but_not_resource_config(self):
        resource = CloudResource(
            provider="aws",
            resource_type="s3_bucket",
            name="demo-bucket",
            config={"secret": "must-not-be-copied"},
            is_public=True,
        )
        result = ScanResult(
            provider="aws",
            account_id="sandbox",
            resources=[resource],
            findings=[SecurityFinding(
                resource=resource,
                severity=Severity.HIGH,
                issue="Public bucket",
                description="Bucket permits public access",
                recommendation="Block public access",
                compliance=["CIS AWS 2.1.5"],
            )],
        )

        evidence = scan_result_evidence_payload(result)

        self.assertNotIn("config", evidence["resources"][0])
        self.assertEqual(evidence["findings"][0]["compliance"], ["CIS AWS 2.1.5"])

    def test_stored_aws_findings_map_to_controls(self):
        self.assertEqual(
            stored_finding_control("aws", "iam_user", "IAM User Without MFA"),
            "CIS AWS 1.2",
        )
        self.assertEqual(
            stored_finding_control("aws", "security_group", "Ingress 0.0.0.0/0 on port 22"),
            "CIS AWS 4.1",
        )


if __name__ == "__main__":
    unittest.main()

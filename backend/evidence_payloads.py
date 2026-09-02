"""Audit-safe evidence serialization and object-storage retrieval helpers."""

import hashlib
import json
import logging
import os
from typing import Any, Dict, Optional

from backend.mcp.mcp_base import ScanResult


logger = logging.getLogger("evidence_payloads")


def scan_result_evidence_payload(result: ScanResult) -> Dict[str, Any]:
    """Serialize detailed findings without copying resource configuration secrets."""
    return {
        "provider": result.provider,
        "account_id": result.account_id,
        "scan_duration": result.scan_duration,
        "errors": result.errors or [],
        "resources": [
            {
                "provider": resource.provider,
                "resource_type": resource.resource_type,
                "name": resource.name,
                "region": resource.region,
                "is_public": resource.is_public,
            }
            for resource in result.resources
        ],
        "findings": [
            {
                "resource": {
                    "provider": finding.resource.provider,
                    "resource_type": finding.resource.resource_type,
                    "name": finding.resource.name,
                    "region": finding.resource.region,
                },
                "severity": finding.severity.value,
                "issue": finding.issue,
                "description": finding.description,
                "recommendation": finding.recommendation,
                "cve_id": finding.cve_id,
                "compliance": finding.compliance or [],
                "detection_tool": finding.detection_tool,
                "tool_category": finding.tool_category,
            }
            for finding in result.findings
        ],
    }


def load_evidence_payload(
    payload: Any,
    storage_type: Optional[str],
    uri: Optional[str],
    checksum_sha256: Optional[str] = None,
) -> Any:
    """Resolve JSON evidence externalized to S3-compatible object storage."""
    if not isinstance(payload, dict) or not payload.get("externalized"):
        return payload
    resolved_uri = str(uri or payload.get("uri") or "")
    if "://" not in resolved_uri:
        return payload

    scheme, location = resolved_uri.split("://", 1)
    if scheme not in {"s3", "spaces"} or "/" not in location:
        return payload
    bucket, key = location.split("/", 1)
    if not bucket or not key:
        return payload

    try:
        import boto3

        client_kwargs: Dict[str, Any] = {
            "service_name": "s3",
            "region_name": os.getenv("OBJECT_STORAGE_REGION") or os.getenv("AWS_REGION") or "blr1",
        }
        endpoint = os.getenv("OBJECT_STORAGE_ENDPOINT_URL") or os.getenv("AWS_S3_ENDPOINT_URL")
        access_key = os.getenv("OBJECT_STORAGE_ACCESS_KEY_ID") or os.getenv("AWS_ACCESS_KEY_ID")
        secret_key = os.getenv("OBJECT_STORAGE_SECRET_ACCESS_KEY") or os.getenv("AWS_SECRET_ACCESS_KEY")
        if endpoint:
            client_kwargs["endpoint_url"] = endpoint
        if access_key and secret_key:
            client_kwargs["aws_access_key_id"] = access_key
            client_kwargs["aws_secret_access_key"] = secret_key

        body = boto3.client(**client_kwargs).get_object(Bucket=bucket, Key=key)["Body"].read()
        if checksum_sha256 and hashlib.sha256(body).hexdigest() != checksum_sha256:
            logger.warning("Evidence payload checksum verification failed for %s", resolved_uri)
            return payload
        return json.loads(body.decode("utf-8"))
    except Exception as exc:
        logger.warning(
            "Could not load %s evidence payload from object storage: %s",
            storage_type or "externalized",
            exc,
        )
        return payload


def stored_finding_control(
    cloud: Optional[str],
    resource_type: Optional[str],
    description: Optional[str],
) -> str:
    """Map legacy stored findings, which predate explicit compliance IDs."""
    text = f"{cloud or ''} {resource_type or ''} {description or ''}".lower()
    if "kubernetes" in text or any(term in text for term in ("cluster-admin", "nodeport", "privileged pod")):
        return "CIS Kubernetes Benchmark"
    if "iac" in text or "terraform" in text or "cloudformation" in text:
        return "CIS Infrastructure as Code"
    if "gcp" in text or "google" in text or "gcs" in text:
        return "CIS-GCP-5.1"
    if "mfa" in text:
        return "CIS AWS 1.2"
    if "encrypt" in text and any(term in text for term in ("s3", "bucket", "storage")):
        return "CIS AWS 2.1.1"
    if any(term in text for term in ("public bucket", "bucket public", "publicly accessible", "public access")):
        return "CIS AWS 2.1.5"
    if any(term in text for term in ("ingress", "0.0.0.0/0", "security group", "firewall", "open port")):
        return "CIS AWS 4.1"
    if any(term in text for term in ("cve", "vulnerable component", "outdated component")):
        return "OWASP-A06:2021"
    return "NIST-800-53-AU-2"

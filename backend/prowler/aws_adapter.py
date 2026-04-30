"""
Prowler AWS adapter for CloudGuard.

Runs Prowler CLI against AWS using the already-initialized boto session,
parses JSON-OCSF output, and converts it into CloudGuard-style resource and
finding dictionaries that the existing scan pipeline can persist.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

from backend.utils.audit_logger import AuditLogger


logger = logging.getLogger("prowler_aws_adapter")


class ProwlerAWSAdapter:
    """Thin adapter around the Prowler AWS CLI."""

    def __init__(self, boto_session: Any, region: str, enabled: bool = True):
        self.session = boto_session
        self.region = region or "us-east-1"
        self.enabled = enabled
        self.binary = shutil.which("prowler")

    @property
    def available(self) -> bool:
        return bool(self.enabled and self.binary)

    async def run(self, account_id: str) -> dict[str, Any]:
        """
        Execute Prowler AWS CLI and return parsed resources/findings.

        Returns a dict with:
        - available: whether the CLI exists and is enabled
        - used: whether the scan actually executed successfully enough to trust
          the result set (even if there were zero findings)
        - resources: CloudGuard-normalized resource dicts
        - findings: CloudGuard-normalized finding dicts
        - summary: execution metadata
        - error: optional error string
        """
        if not self.enabled:
            return {
                "available": False,
                "used": False,
                "resources": [],
                "findings": [],
                "summary": {"engine": "prowler", "enabled": False},
            }

        if not self.binary:
            logger.info("Prowler CLI is not installed; skipping AWS posture pass.")
            return {
                "available": False,
                "used": False,
                "resources": [],
                "findings": [],
                "summary": {"engine": "prowler", "enabled": True, "installed": False},
            }

        frozen_creds = self._get_frozen_credentials()
        if not frozen_creds:
            return {
                "available": True,
                "used": False,
                "resources": [],
                "findings": [],
                "summary": {"engine": "prowler", "enabled": True, "installed": True},
                "error": "Unable to resolve AWS credentials from the active session.",
            }

        env = os.environ.copy()
        env.pop("AWS_PROFILE", None)
        env.pop("AWS_DEFAULT_PROFILE", None)
        env["AWS_ACCESS_KEY_ID"] = frozen_creds.access_key
        env["AWS_SECRET_ACCESS_KEY"] = frozen_creds.secret_key
        env["AWS_DEFAULT_REGION"] = self.region
        env["AWS_REGION"] = self.region
        if frozen_creds.token:
            env["AWS_SESSION_TOKEN"] = frozen_creds.token
        else:
            env.pop("AWS_SESSION_TOKEN", None)

        with tempfile.TemporaryDirectory(prefix="cloudguard-prowler-") as output_dir:
            cmd = [
                self.binary,
                "aws",
                "--region",
                self.region,
                "--output-formats",
                "json-ocsf",
                "--output-directory",
                output_dir,
                "--output-filename",
                "cloudguard-prowler-aws",
            ]

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env,
            )
            stdout, stderr = await process.communicate()
            stdout_str = stdout.decode() if stdout else ""
            stderr_str = stderr.decode() if stderr else ""
            AuditLogger.wrap_subprocess(
                "prowler_aws",
                "compliance",
                cmd,
                stdout_str,
                stderr_str,
                process.returncode,
            )

            records = self._load_json_ocsf_records(Path(output_dir))
            findings, resources = self._normalize_records(records, account_id)

            used = bool(records) or process.returncode == 0
            summary = {
                "engine": "prowler",
                "enabled": True,
                "installed": True,
                "executed": used,
                "region": self.region,
                "record_count": len(records),
                "findings": len(findings),
                "resources_with_findings": len(resources),
                "severity_breakdown": self._severity_breakdown(findings),
            }

            result: dict[str, Any] = {
                "available": True,
                "used": used,
                "resources": resources,
                "findings": findings,
                "summary": summary,
            }

            if process.returncode != 0 and not records:
                result["error"] = stderr_str.strip() or stdout_str.strip() or "Prowler execution failed"

            return result

    def _get_frozen_credentials(self) -> Optional[Any]:
        try:
            creds = self.session.get_credentials()
            if not creds:
                return None
            return creds.get_frozen_credentials()
        except Exception as exc:
            logger.error("Failed to resolve boto credentials for Prowler: %s", exc)
            return None

    def _load_json_ocsf_records(self, output_dir: Path) -> list[dict[str, Any]]:
        json_files = sorted(output_dir.rglob("*.json"))
        preferred = [p for p in json_files if "ocsf" in p.name.lower()]
        candidates = preferred or json_files

        records: list[dict[str, Any]] = []
        for path in candidates:
            parsed = self._read_json_file(path)
            records.extend(self._extract_records(parsed))

        return [record for record in records if isinstance(record, dict)]

    def _read_json_file(self, path: Path) -> Any:
        try:
            text = path.read_text(encoding="utf-8").strip()
        except Exception as exc:
            logger.warning("Failed to read Prowler output file %s: %s", path, exc)
            return None

        if not text:
            return None

        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Some tools emit one JSON object per line; handle that conservatively.
            items = []
            for line in text.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    items.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.debug("Skipping non-JSON line in %s", path)
            return items

    def _extract_records(self, payload: Any) -> list[dict[str, Any]]:
        if payload is None:
            return []
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        if isinstance(payload, dict):
            for key in ("findings", "results", "items", "data"):
                value = payload.get(key)
                if isinstance(value, list):
                    return [item for item in value if isinstance(item, dict)]
            return [payload]
        return []

    def _normalize_records(
        self,
        records: list[dict[str, Any]],
        account_id: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        findings: list[dict[str, Any]] = []
        resources: list[dict[str, Any]] = []
        seen_resources: set[tuple[str, str, str]] = set()

        for record in records:
            if str(record.get("status_code", "")).upper() == "PASS":
                continue

            severity = self._map_severity(
                record.get("severity"),
                record.get("severity_id"),
            )
            resource = self._resource_from_record(record, account_id)
            resource_key = (
                resource.get("resource_type", "Other"),
                resource.get("name", "unknown"),
                resource.get("region", self.region),
            )
            if resource_key not in seen_resources:
                seen_resources.add(resource_key)
                resources.append(resource)

            event_code = (
                record.get("metadata", {}).get("event_code")
                or record.get("finding_info", {}).get("title")
                or "prowler_check"
            )
            title = (
                record.get("finding_info", {}).get("title")
                or record.get("title")
                or event_code
            )
            description = (
                record.get("status_detail")
                or record.get("finding_info", {}).get("desc")
                or record.get("message")
                or title
            )
            recommendation = self._build_recommendation(record)
            compliance = self._extract_compliance(record)

            findings.append(
                {
                    "resource": resource,
                    "severity": severity,
                    "issue": f"[PROWLER] {event_code}: {title}",
                    "description": description,
                    "recommendation": recommendation,
                    "compliance": compliance,
                    "detection_tool": "PROWLER",
                    "tool_category": "config_scan",
                }
            )

        return findings, resources

    def _resource_from_record(self, record: dict[str, Any], account_id: str) -> dict[str, Any]:
        raw_resources = record.get("resources") or []
        resource = raw_resources[0] if isinstance(raw_resources, list) and raw_resources else {}
        if not isinstance(resource, dict):
            resource = {}

        cloud = record.get("cloud") or {}
        resource_uid = (
            resource.get("uid")
            or resource.get("name")
            or record.get("resource_uid")
            or account_id
        )
        resource_name = (
            resource.get("name")
            or resource_uid
            or resource.get("type")
            or "account"
        )
        resource_type = (
            resource.get("type")
            or record.get("resource_type")
            or "AwsAccount"
        )
        region = (
            cloud.get("region")
            or resource.get("region")
            or self.region
        )
        provider_service = resource.get("group", {}).get("name") if isinstance(resource.get("group"), dict) else None
        details = resource.get("data", {}).get("details") if isinstance(resource.get("data"), dict) else None

        return {
            "provider": "aws",
            "resource_type": resource_type,
            "name": str(resource_name),
            "region": str(region or self.region),
            "config": {
                "uid": resource_uid,
                "service": provider_service,
                "details": details,
                "source": "prowler",
                "event_code": record.get("metadata", {}).get("event_code"),
                "status_code": record.get("status_code"),
            },
            "is_public": False,
        }

    def _map_severity(self, raw_severity: Any, severity_id: Any) -> str:
        if isinstance(raw_severity, str):
            normalized = raw_severity.strip().upper()
            if normalized in {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "INFORMATIONAL"}:
                return "INFO" if normalized == "INFORMATIONAL" else normalized

        try:
            sev_id = int(severity_id)
        except (TypeError, ValueError):
            sev_id = None

        if sev_id is not None:
            if sev_id >= 5:
                return "CRITICAL"
            if sev_id == 4:
                return "HIGH"
            if sev_id == 3:
                return "MEDIUM"
            if sev_id == 2:
                return "LOW"
            return "INFO"

        return "MEDIUM"

    def _build_recommendation(self, record: dict[str, Any]) -> str:
        remediation = record.get("remediation") or {}
        desc = remediation.get("desc") if isinstance(remediation, dict) else None
        refs = remediation.get("references") if isinstance(remediation, dict) else None
        ref_text = ""
        if isinstance(refs, list) and refs:
            ref_text = f" Reference: {refs[0]}"

        return (desc or "Review the failed control in Prowler and remediate the AWS configuration.") + ref_text

    def _extract_compliance(self, record: dict[str, Any]) -> list[str]:
        compliance: list[str] = []
        for key in ("compliances", "compliance"):
            value = record.get(key)
            if isinstance(value, list):
                compliance.extend(str(item) for item in value if item)
            elif isinstance(value, str) and value:
                compliance.append(value)

        finding_types = record.get("finding_info", {}).get("types")
        if isinstance(finding_types, list):
            compliance.extend(str(item) for item in finding_types if item)

        deduped: list[str] = []
        seen: set[str] = set()
        for item in compliance:
            if item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped

    def _severity_breakdown(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        breakdown = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for finding in findings:
            sev = str(finding.get("severity", "MEDIUM")).upper()
            if sev not in breakdown:
                sev = "MEDIUM"
            breakdown[sev] += 1
        return breakdown

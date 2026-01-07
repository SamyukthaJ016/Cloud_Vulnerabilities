import subprocess
import os
import json
import logging

from backend.database import store_cloudfox_finding

logger = logging.getLogger("cloudfox")


def run_cloudfox(scan_id: int, profile: str = "default"):
    """
    Run CloudFox and store findings in database.
    """
    output_dir = "reports/cloudfox"
    os.makedirs(output_dir, exist_ok=True)

    logger.info("🦊 Running CloudFox IAM analysis...")

    cmd = [
        "cloudfox",
        "aws",
        "iam-permissions",
        "--profile",
        profile,
        "--output",
        "json",
        "--out",
        output_dir,
    ]

    try:
        subprocess.run(cmd, check=True)
    except Exception as e:
        logger.error(f"❌ CloudFox execution failed: {e}")
        return

    findings_file = os.path.join(output_dir, "iam_permissions.json")

    if not os.path.exists(findings_file):
        logger.warning("⚠️ CloudFox output file not found")
        return

    try:
        with open(findings_file, "r") as f:
            findings = json.load(f)
    except Exception as e:
        logger.error(f"❌ Failed to parse CloudFox output: {e}")
        return

    if not isinstance(findings, list):
        logger.warning("⚠️ Unexpected CloudFox output format")
        return

    stored = 0

    for item in findings:
        role_name = item.get("RoleName", "unknown-role")
        description = item.get(
            "Finding",
            "CloudFox detected a potential IAM misconfiguration",
        )

        try:
            store_cloudfox_finding(
                scan_id=scan_id,
                resource_name=role_name,
                resource_type="iam_role",
                cloud="aws",
                severity="HIGH",
                description=description,
            )
            stored += 1
        except Exception as e:
            logger.error(f"❌ Failed to store CloudFox finding: {e}")

    logger.info(f"✅ CloudFox completed. Stored {stored} findings.")

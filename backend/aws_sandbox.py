"""Account checks for intentionally vulnerable AWS demo resources."""

import os
import re


def allowed_aws_sandbox_accounts():
    accounts = {value.strip() for value in os.getenv("SANDBOX_AWS_ACCOUNT_IDS", "").split(",") if value.strip()}
    if any(not re.fullmatch(r"[0-9]{12}", value) for value in accounts):
        raise RuntimeError("SANDBOX_AWS_ACCOUNT_IDS must contain 12-digit AWS account IDs.")
    return accounts


def verify_aws_sandbox_identity(sts, expected_account_id=None, require_allowlisted=True):
    allowed = allowed_aws_sandbox_accounts() if require_allowlisted else set()
    if require_allowlisted and not allowed:
        raise RuntimeError("Configure SANDBOX_AWS_ACCOUNT_IDS with an approved isolated sandbox account first.")
    identity = sts.get_caller_identity()
    account_id = identity.get("Account")
    if not isinstance(account_id, str) or not re.fullmatch(r"[0-9]{12}", account_id):
        raise RuntimeError("AWS returned an invalid sandbox account identity.")
    if identity.get("Arn", "").endswith(":root"):
        raise RuntimeError("AWS demo labs must use an IAM user or role, not root credentials.")
    if expected_account_id and account_id != expected_account_id:
        raise RuntimeError("AWS credentials no longer target the account that owns this lab; cleanup refused.")
    if require_allowlisted and account_id not in allowed:
        raise RuntimeError("AWS credential account is not in SANDBOX_AWS_ACCOUNT_IDS; no lab resources were created.")
    return account_id

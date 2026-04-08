import logging
from typing import Any, Optional

from fastapi.responses import JSONResponse

from backend.credentials.manager import credential_manager


logger = logging.getLogger("scan_api_helpers")


def build_permission_required_payload(
    user_id: str,
    credential_id: Optional[int],
    exc: Exception,
) -> dict[str, Any]:
    aws_cred = None
    if credential_id:
        aws_cred = credential_manager.get_credential_by_id(user_id, credential_id)
    else:
        aws_cred = credential_manager.get_default_credential(user_id, "aws")

    resolved_cred_id = aws_cred.id if aws_cred else credential_id
    iam_user_arn = getattr(exc, "iam_user_arn", "")
    iam_user_name = iam_user_arn.split("/")[-1] if "/" in iam_user_arn else iam_user_arn

    payload = {
        "status": "permission_required",
        "permission_error": {
            "type": "missing_assume_role_permission",
            "iam_user_name": iam_user_name,
            "iam_user_arn": iam_user_arn,
            "role_arn": getattr(exc, "role_arn", None),
            "policy_arn": getattr(exc, "recommended_policy_arn", None),
            "credential_id": resolved_cred_id,
            "can_auto_grant": True,
        },
    }
    logger.warning("Permission-required response built for user=%s", user_id)
    return payload


def permission_required_json_response(
    user_id: str,
    credential_id: Optional[int],
    exc: Exception,
) -> JSONResponse:
    return JSONResponse(
        status_code=200,
        content=build_permission_required_payload(user_id, credential_id, exc),
    )

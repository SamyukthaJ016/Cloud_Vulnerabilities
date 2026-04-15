from __future__ import annotations

import json
import logging
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field

from backend.billing import (
    billing_enabled,
    create_subscription_request,
    get_billing_dashboard,
    get_provider_access_decision,
    list_plans,
    process_razorpay_webhook,
    verify_product_access,
)
from backend.user_context import resolve_user_id


logger = logging.getLogger("billing_api")
router = APIRouter(prefix="/api/billing", tags=["billing"])


class SubscriptionRequest(BaseModel):
    plan_id: str = Field(...)
    email: Optional[str] = None


def get_user_id(request: Request) -> str:
    return resolve_user_id(request)


@router.get("/plans")
async def get_billing_plans():
    return {
        "billing_enabled": billing_enabled(),
        "plans": list_plans(),
    }


@router.get("/subscription")
async def get_current_subscription(user_id: str = Depends(get_user_id)):
    return get_billing_dashboard(user_id)


@router.get("/entitlements")
async def get_current_entitlements(user_id: str = Depends(get_user_id)):
    snapshot = get_billing_dashboard(user_id)
    return {
        "role": snapshot["role"],
        "entitled_providers": snapshot["entitled_providers"],
        "current_subscription": snapshot["current_subscription"],
        "billing_enforcement": snapshot["billing_enforcement"],
    }


@router.post("/subscribe")
async def create_subscription(
    payload: SubscriptionRequest,
    user_id: str = Depends(get_user_id),
):
    try:
        return create_subscription_request(
            user_id=user_id,
            plan_id=payload.plan_id,
            email=payload.email,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error("Failed to create billing subscription: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/webhook")
async def razorpay_webhook(
    request: Request,
    x_razorpay_signature: Optional[str] = Header(default=None),
    x_razorpay_event_id: Optional[str] = Header(default=None),
):
    try:
        raw_body = await request.body()
        return process_razorpay_webhook(
            raw_body=raw_body,
            signature=x_razorpay_signature,
            provided_event_id=x_razorpay_event_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Invalid webhook payload")
    except Exception as exc:
        logger.error("Failed to process Razorpay webhook: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/verify")
async def verify_access(
    email: str,
    product: str,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
):
    try:
        return verify_product_access(
            email=email,
            product_id=product,
            api_key=x_api_key or "",
        )
    except PermissionError as exc:
        raise HTTPException(status_code=401, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.error("Billing verify failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/scan-access-check")
async def check_scan_access(
    payload: dict[str, Any],
    user_id: str = Depends(get_user_id),
):
    providers = payload.get("providers") or []
    return get_provider_access_decision(user_id, providers)

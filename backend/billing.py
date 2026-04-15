from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

import psycopg2
from psycopg2.extras import Json, RealDictCursor

from backend.credentials.manager import credential_manager


logger = logging.getLogger("billing")

ROLE_FREE = "free"
ROLE_MEMBER = "member"
ROLE_PATRON = "patron"

PRODUCT_AWS = "product_1"
PRODUCT_GCP = "product_2"
PRODUCT_KUBERNETES = "product_3"
PRODUCT_IAC = "product_4"
PRODUCT_CONTAINER = "product_5"
PRODUCT_MASTER = "master"

PRODUCT_PROVIDER_MAP = {
    "aws": PRODUCT_AWS,
    "gcp": PRODUCT_GCP,
    "kubernetes": PRODUCT_KUBERNETES,
    "iac": PRODUCT_IAC,
    "container": PRODUCT_CONTAINER,
}

PRODUCT_PROVIDER_LABELS = {
    PRODUCT_AWS: "AWS Scanner",
    PRODUCT_GCP: "GCP Scanner",
    PRODUCT_KUBERNETES: "Kubernetes Scanner",
    PRODUCT_IAC: "IaC Scanner",
    PRODUCT_CONTAINER: "Container Scanner",
    PRODUCT_MASTER: "CloudGuard Complete",
}

ACTIVE_SUBSCRIPTION_STATUSES = {"active", "authenticated"}
VALID_SUBSCRIPTION_STATUSES = {
    "created",
    "authenticated",
    "active",
    "pending",
    "halted",
    "cancelled",
    "completed",
    "expired",
}


@dataclass(frozen=True)
class BillingPlan:
    id: str
    product_id: str
    product_name: str
    billing_cycle: str
    amount_paise: int
    currency: str
    role: str
    features: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["amount_inr"] = round(self.amount_paise / 100.0, 2)
        payload["configured"] = bool(get_razorpay_plan_id(self.id))
        return payload


BILLING_PLANS: list[BillingPlan] = [
    BillingPlan(
        id="product_1_monthly",
        product_id=PRODUCT_AWS,
        product_name="AWS Scanner",
        billing_cycle="monthly",
        amount_paise=100000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "AWS posture scanning",
            "IAM and S3 checks",
            "CloudTrail and GuardDuty visibility",
        ],
    ),
    BillingPlan(
        id="product_1_yearly",
        product_id=PRODUCT_AWS,
        product_name="AWS Scanner",
        billing_cycle="yearly",
        amount_paise=1000000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "AWS posture scanning",
            "IAM and S3 checks",
            "CloudTrail and GuardDuty visibility",
        ],
    ),
    BillingPlan(
        id="product_2_monthly",
        product_id=PRODUCT_GCP,
        product_name="GCP Scanner",
        billing_cycle="monthly",
        amount_paise=100000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "GCS and Compute posture scanning",
            "Firewall and IAM analysis",
            "Project-level visibility",
        ],
    ),
    BillingPlan(
        id="product_2_yearly",
        product_id=PRODUCT_GCP,
        product_name="GCP Scanner",
        billing_cycle="yearly",
        amount_paise=1000000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "GCS and Compute posture scanning",
            "Firewall and IAM analysis",
            "Project-level visibility",
        ],
    ),
    BillingPlan(
        id="product_3_monthly",
        product_id=PRODUCT_KUBERNETES,
        product_name="Kubernetes Scanner",
        billing_cycle="monthly",
        amount_paise=100000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "Cluster posture analysis",
            "RBAC, ingress, and secret checks",
            "Workload hardening review",
        ],
    ),
    BillingPlan(
        id="product_3_yearly",
        product_id=PRODUCT_KUBERNETES,
        product_name="Kubernetes Scanner",
        billing_cycle="yearly",
        amount_paise=1000000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "Cluster posture analysis",
            "RBAC, ingress, and secret checks",
            "Workload hardening review",
        ],
    ),
    BillingPlan(
        id="product_4_monthly",
        product_id=PRODUCT_IAC,
        product_name="IaC Scanner",
        billing_cycle="monthly",
        amount_paise=100000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "Terraform and CloudFormation scanning",
            "Checkov, tfsec, Trivy, and Semgrep",
            "Secret detection with Gitleaks",
        ],
    ),
    BillingPlan(
        id="product_4_yearly",
        product_id=PRODUCT_IAC,
        product_name="IaC Scanner",
        billing_cycle="yearly",
        amount_paise=1000000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "Terraform and CloudFormation scanning",
            "Checkov, tfsec, Trivy, and Semgrep",
            "Secret detection with Gitleaks",
        ],
    ),
    BillingPlan(
        id="product_5_monthly",
        product_id=PRODUCT_CONTAINER,
        product_name="Container Scanner",
        billing_cycle="monthly",
        amount_paise=100000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "Container image vulnerability scanning",
            "SBOM generation",
            "Dockerfile linting support",
        ],
    ),
    BillingPlan(
        id="product_5_yearly",
        product_id=PRODUCT_CONTAINER,
        product_name="Container Scanner",
        billing_cycle="yearly",
        amount_paise=1000000,
        currency="INR",
        role=ROLE_MEMBER,
        features=[
            "Container image vulnerability scanning",
            "SBOM generation",
            "Dockerfile linting support",
        ],
    ),
    BillingPlan(
        id="master_monthly",
        product_id=PRODUCT_MASTER,
        product_name="CloudGuard Complete",
        billing_cycle="monthly",
        amount_paise=450000,
        currency="INR",
        role=ROLE_PATRON,
        features=[
            "All five CloudGuard scanners",
            "Priority access to new modules",
            "Unified subscription for the full suite",
        ],
    ),
    BillingPlan(
        id="master_yearly",
        product_id=PRODUCT_MASTER,
        product_name="CloudGuard Complete",
        billing_cycle="yearly",
        amount_paise=2900000,
        currency="INR",
        role=ROLE_PATRON,
        features=[
            "All five CloudGuard scanners",
            "Priority access to new modules",
            "Unified subscription for the full suite",
        ],
    ),
]

PLAN_LOOKUP = {plan.id: plan for plan in BILLING_PLANS}
PRODUCT_ENV_KEYS = {
    "product_1_monthly": "PLAN_ID_PRODUCT_1_MONTHLY",
    "product_1_yearly": "PLAN_ID_PRODUCT_1_YEARLY",
    "product_2_monthly": "PLAN_ID_PRODUCT_2_MONTHLY",
    "product_2_yearly": "PLAN_ID_PRODUCT_2_YEARLY",
    "product_3_monthly": "PLAN_ID_PRODUCT_3_MONTHLY",
    "product_3_yearly": "PLAN_ID_PRODUCT_3_YEARLY",
    "product_4_monthly": "PLAN_ID_PRODUCT_4_MONTHLY",
    "product_4_yearly": "PLAN_ID_PRODUCT_4_YEARLY",
    "product_5_monthly": "PLAN_ID_PRODUCT_5_MONTHLY",
    "product_5_yearly": "PLAN_ID_PRODUCT_5_YEARLY",
    "master_monthly": "PLAN_ID_MASTER_MONTHLY",
    "master_yearly": "PLAN_ID_MASTER_YEARLY",
}
PRODUCT_API_KEY_ENV = {
    PRODUCT_AWS: "API_KEY_PRODUCT_1",
    PRODUCT_GCP: "API_KEY_PRODUCT_2",
    PRODUCT_KUBERNETES: "API_KEY_PRODUCT_3",
    PRODUCT_IAC: "API_KEY_PRODUCT_4",
    PRODUCT_CONTAINER: "API_KEY_PRODUCT_5",
    PRODUCT_MASTER: "API_KEY_MASTER",
}

_billing_schema_checked = False


def _get_db_url() -> str:
    db_url = (os.getenv("DATABASE_URL") or "").strip()
    if not db_url:
        raise RuntimeError("DATABASE_URL not set")
    return db_url


def ensure_billing_schema() -> None:
    global _billing_schema_checked
    if _billing_schema_checked:
        return

    from backend.migration_manager import run_migrations

    run_migrations()
    _billing_schema_checked = True


def _get_connection():
    return psycopg2.connect(_get_db_url())


def billing_enabled() -> bool:
    return (os.getenv("ENABLE_BILLING") or "true").strip().lower() not in {"0", "false", "no", "off"}


def billing_enforcement_enabled() -> bool:
    return (os.getenv("BILLING_ENFORCEMENT") or "false").strip().lower() in {"1", "true", "yes", "on"}


def get_razorpay_mode() -> str:
    key_id = (os.getenv("RAZORPAY_KEY_ID") or "").strip()
    key_secret = (os.getenv("RAZORPAY_KEY_SECRET") or "").strip()
    return "live" if key_id and key_secret else "skeleton"


def get_razorpay_plan_id(plan_id: str) -> Optional[str]:
    env_key = PRODUCT_ENV_KEYS.get(plan_id)
    if not env_key:
        return None
    value = (os.getenv(env_key) or "").strip()
    return value or None


def get_plan_by_id(plan_id: str) -> Optional[BillingPlan]:
    return PLAN_LOOKUP.get(plan_id)


def list_plans() -> list[dict[str, Any]]:
    return [plan.to_dict() for plan in BILLING_PLANS]


def _serialize_subscription_row(row: dict[str, Any]) -> dict[str, Any]:
    payload = dict(row)
    for key, value in list(payload.items()):
        if isinstance(value, datetime):
            payload[key] = value.isoformat()
    return payload


def _compute_role_from_products(products: set[str]) -> str:
    if PRODUCT_MASTER in products:
        return ROLE_PATRON
    if products:
        return ROLE_MEMBER
    return ROLE_FREE


def recalculate_billing_role(user_id: str) -> str:
    ensure_billing_schema()
    conn = _get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT DISTINCT product_id
            FROM billing_subscriptions
            WHERE user_id = %s
              AND status = ANY(%s)
            """,
            (user_id, list(ACTIVE_SUBSCRIPTION_STATUSES)),
        )
        active_products = {row[0] for row in cur.fetchall()}
        role = _compute_role_from_products(active_products)
        cur.execute(
            """
            UPDATE user_profiles
            SET billing_role = %s, updated_at = NOW()
            WHERE user_id = %s
            """,
            (role, user_id),
        )
        conn.commit()
        return role
    finally:
        cur.close()
        conn.close()


def get_subscription_snapshot(user_id: str) -> dict[str, Any]:
    ensure_billing_schema()
    credential_manager.ensure_user(user_id)
    conn = _get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)

    try:
        cur.execute(
            """
            SELECT user_id, email, name, COALESCE(billing_role, 'free') AS billing_role
            FROM user_profiles
            WHERE user_id = %s
            """,
            (user_id,),
        )
        profile = cur.fetchone() or {
            "user_id": user_id,
            "email": None,
            "name": user_id,
            "billing_role": ROLE_FREE,
        }

        cur.execute(
            """
            SELECT
                id,
                plan_id,
                product_id,
                product_name,
                billing_cycle,
                role_granted,
                status,
                amount_paise,
                currency,
                razorpay_sub_id,
                razorpay_plan_id,
                customer_email,
                current_start,
                current_end,
                created_at,
                updated_at,
                metadata
            FROM billing_subscriptions
            WHERE user_id = %s
            ORDER BY
                CASE WHEN status = 'active' THEN 0 ELSE 1 END,
                created_at DESC
            """,
            (user_id,),
        )
        subscriptions = [_serialize_subscription_row(row) for row in cur.fetchall()]

        active_products = {
            subscription["product_id"]
            for subscription in subscriptions
            if subscription.get("status") in ACTIVE_SUBSCRIPTION_STATUSES
        }

        entitled_products = set(active_products)
        if PRODUCT_MASTER in entitled_products:
            entitled_products.update(PRODUCT_PROVIDER_LABELS.keys())

        role = _compute_role_from_products(active_products)
        if role != profile.get("billing_role"):
            cur.execute(
                """
                UPDATE user_profiles
                SET billing_role = %s, updated_at = NOW()
                WHERE user_id = %s
                """,
                (role, user_id),
            )
            conn.commit()
            profile["billing_role"] = role

        current_subscription = next(
            (subscription for subscription in subscriptions if subscription.get("status") in ACTIVE_SUBSCRIPTION_STATUSES),
            subscriptions[0] if subscriptions else None,
        )

        entitled_providers = sorted(
            provider
            for provider, product_id in PRODUCT_PROVIDER_MAP.items()
            if PRODUCT_MASTER in entitled_products or product_id in entitled_products
        )

        return {
            "billing_enabled": billing_enabled(),
            "billing_enforcement": billing_enforcement_enabled(),
            "mode": get_razorpay_mode(),
            "user_id": user_id,
            "email": profile.get("email"),
            "name": profile.get("name"),
            "role": profile.get("billing_role", ROLE_FREE),
            "subscriptions": subscriptions,
            "current_subscription": current_subscription,
            "entitled_products": sorted(product for product in entitled_products if product in PRODUCT_PROVIDER_LABELS),
            "entitled_providers": entitled_providers,
        }
    finally:
        cur.close()
        conn.close()


def get_billing_dashboard(user_id: str) -> dict[str, Any]:
    snapshot = get_subscription_snapshot(user_id)
    return {
        "billing_enabled": snapshot["billing_enabled"],
        "billing_enforcement": snapshot["billing_enforcement"],
        "mode": snapshot["mode"],
        "role": snapshot["role"],
        "email": snapshot["email"],
        "current_subscription": snapshot["current_subscription"],
        "entitled_providers": snapshot["entitled_providers"],
        "plans": list_plans(),
    }


def create_subscription_request(user_id: str, plan_id: str, email: Optional[str] = None) -> dict[str, Any]:
    ensure_billing_schema()
    if not billing_enabled():
        raise ValueError("Billing is disabled for this deployment.")

    plan = get_plan_by_id(plan_id)
    if not plan:
        raise ValueError("Unknown plan_id")

    normalized_email = (email or "").strip() or None
    credential_manager.ensure_user(user_id, email=normalized_email)

    conn = _get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        if normalized_email:
            cur.execute(
                """
                UPDATE user_profiles
                SET email = %s, updated_at = NOW()
                WHERE user_id = %s
                """,
                (normalized_email, user_id),
            )

        cur.execute(
            """
            SELECT id, status
            FROM billing_subscriptions
            WHERE user_id = %s
              AND product_id = %s
              AND status = ANY(%s)
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (user_id, plan.product_id, list(ACTIVE_SUBSCRIPTION_STATUSES)),
        )
        existing = cur.fetchone()
        if existing:
            raise ValueError("An active subscription already exists for this CloudGuard module.")

        razorpay_plan_id = get_razorpay_plan_id(plan.id)
        cur.execute(
            """
            INSERT INTO billing_subscriptions (
                user_id,
                plan_id,
                product_id,
                product_name,
                billing_cycle,
                role_granted,
                status,
                amount_paise,
                currency,
                razorpay_plan_id,
                customer_email,
                metadata
            )
            VALUES (%s, %s, %s, %s, %s, %s, 'created', %s, %s, %s, %s, %s)
            RETURNING
                id,
                plan_id,
                product_id,
                product_name,
                billing_cycle,
                role_granted,
                status,
                amount_paise,
                currency,
                razorpay_plan_id,
                customer_email,
                created_at,
                updated_at,
                metadata
            """,
            (
                user_id,
                plan.id,
                plan.product_id,
                plan.product_name,
                plan.billing_cycle,
                plan.role,
                plan.amount_paise,
                plan.currency,
                razorpay_plan_id,
                normalized_email,
                Json(
                    {
                        "source": "cloudguard-ui",
                        "razorpay_mode": get_razorpay_mode(),
                    }
                ),
            ),
        )
        created = _serialize_subscription_row(cur.fetchone())
        conn.commit()

        return {
            "status": "created",
            "message": (
                "Subscription request recorded. Add Razorpay plan IDs and webhook configuration to complete checkout."
                if get_razorpay_mode() == "skeleton" or not razorpay_plan_id
                else "Subscription record created. Razorpay configuration is present and ready for the next checkout step."
            ),
            "mode": get_razorpay_mode(),
            "subscription": created,
            "plan": plan.to_dict(),
            "razorpay": {
                "configured": bool(razorpay_plan_id and (os.getenv("RAZORPAY_KEY_ID") or "").strip()),
                "key_id": (os.getenv("RAZORPAY_KEY_ID") or "").strip() or None,
                "plan_id": razorpay_plan_id,
                "notes": {
                    "cloudguard_user_id": user_id,
                    "cloudguard_subscription_id": created["id"],
                    "cloudguard_plan_id": plan.id,
                },
            },
        }
    finally:
        cur.close()
        conn.close()


def _get_event_id(payload: dict[str, Any], raw_body: bytes, provided_event_id: Optional[str]) -> str:
    if provided_event_id:
        return provided_event_id

    payload_id = str(payload.get("id") or "").strip()
    if payload_id:
        return payload_id

    return hashlib.sha256(raw_body).hexdigest()


def _verify_razorpay_signature(raw_body: bytes, signature: Optional[str]) -> None:
    webhook_secret = (os.getenv("RAZORPAY_WEBHOOK_SECRET") or "").strip()
    if not webhook_secret:
        return

    if not signature:
        raise ValueError("Missing Razorpay webhook signature.")

    expected = hmac.new(
        webhook_secret.encode("utf-8"),
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(expected, signature):
        raise ValueError("Invalid Razorpay webhook signature.")


def _map_razorpay_event_status(event_name: str, subscription_entity: dict[str, Any]) -> str:
    explicit_status = str(subscription_entity.get("status") or "").strip().lower()
    if explicit_status in VALID_SUBSCRIPTION_STATUSES:
        return explicit_status

    event_map = {
        "subscription.authenticated": "authenticated",
        "subscription.activated": "active",
        "subscription.pending": "pending",
        "subscription.halted": "halted",
        "subscription.cancelled": "cancelled",
        "subscription.completed": "completed",
        "subscription.charged": "active",
    }
    return event_map.get(event_name, "pending")


def process_razorpay_webhook(raw_body: bytes, signature: Optional[str], provided_event_id: Optional[str] = None) -> dict[str, Any]:
    ensure_billing_schema()
    _verify_razorpay_signature(raw_body, signature)

    payload = json.loads(raw_body.decode("utf-8") or "{}")
    event_name = str(payload.get("event") or "unknown").strip()
    event_id = _get_event_id(payload, raw_body, provided_event_id)
    subscription_entity = (
        payload.get("payload", {})
        .get("subscription", {})
        .get("entity", {})
    )

    razorpay_sub_id = str(subscription_entity.get("id") or "").strip() or None
    next_status = _map_razorpay_event_status(event_name, subscription_entity)

    def _timestamp_to_datetime(value: Any) -> Optional[datetime]:
        if value in (None, ""):
            return None
        try:
            return datetime.fromtimestamp(int(value), tz=timezone.utc)
        except (TypeError, ValueError, OSError):
            return None

    current_start = _timestamp_to_datetime(
        subscription_entity.get("current_start") or subscription_entity.get("start_at")
    )
    current_end = _timestamp_to_datetime(
        subscription_entity.get("current_end") or subscription_entity.get("end_at") or subscription_entity.get("charge_at")
    )

    conn = _get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            INSERT INTO billing_webhook_events (event_id, event_type, payload)
            VALUES (%s, %s, %s)
            ON CONFLICT (event_id) DO NOTHING
            RETURNING event_id
            """,
            (event_id, event_name, Json(payload)),
        )
        inserted = cur.fetchone()
        if not inserted:
            conn.commit()
            return {
                "status": "duplicate",
                "event_id": event_id,
                "event_type": event_name,
                "message": "Webhook already processed.",
            }

        updated_user_id = None
        updated_subscription = None
        if razorpay_sub_id:
            cur.execute(
                """
                UPDATE billing_subscriptions
                SET
                    status = %s,
                    current_start = COALESCE(%s, current_start),
                    current_end = COALESCE(%s, current_end),
                    metadata = COALESCE(metadata, '{}'::jsonb) || %s::jsonb,
                    updated_at = NOW()
                WHERE razorpay_sub_id = %s
                RETURNING user_id, id, status
                """,
                (
                    next_status,
                    current_start,
                    current_end,
                    json.dumps({"last_webhook_event": event_name}),
                    razorpay_sub_id,
                ),
            )
            updated_subscription = cur.fetchone()
            if updated_subscription:
                updated_user_id = updated_subscription["user_id"]

        conn.commit()
    finally:
        cur.close()
        conn.close()

    new_role = recalculate_billing_role(updated_user_id) if updated_user_id else None
    return {
        "status": "processed",
        "event_id": event_id,
        "event_type": event_name,
        "subscription_id": updated_subscription["id"] if updated_subscription else None,
        "user_id": updated_user_id,
        "user_role": new_role,
    }


def _is_valid_product(product_id: str) -> bool:
    return product_id in PRODUCT_PROVIDER_LABELS


def _is_valid_api_key(product_id: str, api_key: str) -> bool:
    if not api_key:
        return False

    env_key_name = PRODUCT_API_KEY_ENV.get(product_id)
    env_value = (os.getenv(env_key_name or "") or "").strip() if env_key_name else ""
    if env_value and hmac.compare_digest(env_value, api_key):
        return True

    ensure_billing_schema()
    conn = _get_connection()
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT 1
            FROM billing_product_api_keys
            WHERE product_id = %s AND api_key = %s
            LIMIT 1
            """,
            (product_id, api_key),
        )
        return cur.fetchone() is not None
    finally:
        cur.close()
        conn.close()


def verify_product_access(email: str, product_id: str, api_key: str) -> dict[str, Any]:
    ensure_billing_schema()
    normalized_email = (email or "").strip().lower()
    if not normalized_email:
        raise ValueError("email is required")
    if not _is_valid_product(product_id):
        raise ValueError("unknown product")
    if not _is_valid_api_key(product_id, api_key):
        raise PermissionError("invalid API key")

    conn = _get_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT user_id, email, COALESCE(billing_role, 'free') AS billing_role
            FROM user_profiles
            WHERE LOWER(email) = %s
            LIMIT 1
            """,
            (normalized_email,),
        )
        user = cur.fetchone()
        if not user:
            return {
                "email": normalized_email,
                "product": product_id,
                "has_access": False,
                "role": ROLE_FREE,
                "reason": "user not found",
            }

        snapshot = get_subscription_snapshot(user["user_id"])
        if snapshot["role"] == ROLE_PATRON:
            return {
                "email": normalized_email,
                "product": product_id,
                "has_access": True,
                "role": ROLE_PATRON,
                "reason": "patron access",
            }

        has_access = PRODUCT_MASTER in snapshot["entitled_products"] or product_id in snapshot["entitled_products"]
        return {
            "email": normalized_email,
            "product": product_id,
            "has_access": has_access,
            "role": snapshot["role"],
            "reason": "active subscription" if has_access else "no active subscription",
        }
    finally:
        cur.close()
        conn.close()


def get_provider_access_decision(user_id: str, providers: list[str]) -> dict[str, Any]:
    requested = [provider for provider in providers if provider in PRODUCT_PROVIDER_MAP]
    if not requested:
        return {
            "allowed": True,
            "missing_providers": [],
            "missing_products": [],
            "subscription": get_subscription_snapshot(user_id),
        }

    snapshot = get_subscription_snapshot(user_id)
    entitled_products = set(snapshot["entitled_products"])
    missing_providers = []
    missing_products = []

    for provider in requested:
        product_id = PRODUCT_PROVIDER_MAP[provider]
        if PRODUCT_MASTER in entitled_products or product_id in entitled_products:
            continue
        missing_providers.append(provider)
        missing_products.append(product_id)

    return {
        "allowed": len(missing_providers) == 0,
        "missing_providers": missing_providers,
        "missing_products": missing_products,
        "subscription": snapshot,
    }

import os
import hashlib
import hmac
import re
from typing import Optional
from urllib.parse import urlencode, urlparse, urlunparse

import psycopg2
import requests
from fastapi import HTTPException, Request


SSO_SESSION_COOKIE_NAMES = (
    "__Secure-next-auth.session-token",
    "next-auth.session-token",
    "__Secure-authjs.session-token",
    "authjs.session-token",
)
PUBLIC_PATHS = {
    "/health",
    "/api/info",
    "/api/auth/status",
    "/api/auth/sso/exchange",
    "/api/manifest",
    "/api/scan",
}
SCANNER_REPORT_PATHS = {
    "/dashboard",
    "/posture/dashboard",
    "/api/provider-breakdown",
    "/api/latest-findings",
    "/api/scans",
    "/api/scan-history",
}
HTML_PAGE_PATHS = {
    "/",
    "/dashboard",
    "/grc",
    "/msme-compliance",
    "/frontend/history.html",
    "/schedules",
    "/system-status",
}

USER_ID_COOKIE = "cloudguard_user_id"
SSO_TOKEN_COOKIE = "cloudguard_sso_token"


def _clean_user_id(value: str | None) -> str | None:
    if not value:
        return None

    cleaned = value.strip()
    return cleaned or None


def _scanner_shared_secret() -> str:
    return (
        os.getenv("CONTROL_PLANE_SCANNER_SHARED_SECRET")
        or os.getenv("SCANNER_SHARED_SECRET")
        or os.getenv("SHARED_SECRET")
        or ""
    ).strip()


def _scanner_view_secret(scan_id: str) -> str:
    secret = _scanner_shared_secret()
    if not secret:
        return ""
    return hmac.new(
        secret.encode("utf-8"),
        f"cloudguard-view.{scan_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _report_scan_token_source(request: Request) -> str | None:
    return (
        _clean_user_id(request.query_params.get("scanIds"))
        or _clean_user_id(request.query_params.get("scan_ids"))
        or _clean_user_id(request.query_params.get("scanId"))
        or _clean_user_id(request.query_params.get("scan_id"))
    )


def _report_secret(request: Request) -> str | None:
    return (
        _clean_user_id(request.query_params.get("secret"))
        or _clean_user_id(request.query_params.get("viewSecret"))
        or _clean_user_id(request.query_params.get("view_secret"))
    )


def _parse_report_scan_ids(scan_source: str) -> list[int]:
    ids: list[int] = []
    for item in scan_source.split(","):
        try:
            ids.append(int(item.strip()))
        except (TypeError, ValueError):
            continue
    return ids


def _report_scan_owner(scan_ids: list[int]) -> str | None:
    if not scan_ids:
        return None

    conn = psycopg2.connect(_get_database_url())
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id
                FROM scans
                WHERE id = ANY(%s)
                ORDER BY id ASC
                LIMIT 1
                """,
                (scan_ids,),
            )
            row = cur.fetchone()
            return row[0] if row else None
    finally:
        conn.close()


def _authenticate_scanner_report_user(request: Request) -> dict | None:
    normalized_path = request.url.path.rstrip("/") or "/"
    if normalized_path not in SCANNER_REPORT_PATHS:
        return None

    scan_source = _report_scan_token_source(request)
    supplied_secret = _report_secret(request)
    if not scan_source and not supplied_secret:
        return None
    if not scan_source or not supplied_secret:
        raise HTTPException(status_code=401, detail="Scan report token is required")

    expected_secret = _scanner_view_secret(scan_source)
    if not expected_secret or not hmac.compare_digest(expected_secret, supplied_secret):
        raise HTTPException(status_code=401, detail="Invalid scan report token")

    owner_id = _report_scan_owner(_parse_report_scan_ids(scan_source)) or "control-plane"
    user = {
        "id": owner_id,
        "email": "control-plane-report@cloudguard.local",
        "name": "Control Plane Report Viewer",
        "scanner_report": True,
    }
    request.state.authenticated_user = user
    request.state.user_id = user["id"]
    request.state.scanner_report_scan_ids = scan_source
    return user


def is_public_path(path: str) -> bool:
    normalized = path.rstrip("/") or "/"
    return (
        normalized in PUBLIC_PATHS
        or (
            normalized.startswith("/api/scans/")
            and normalized.endswith("/view-token")
        )
        or re.match(r"^/s\d+/api/manifest$", normalized) is not None
        or re.match(r"^/s\d+/api/scan$", normalized) is not None
        or re.match(r"^/s\d+/api/scans/.+/view-token$", normalized) is not None
    )


def is_html_navigation(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return request.url.path in HTML_PAGE_PATHS or "text/html" in accept


def get_sso_login_url() -> str:
    return (os.getenv("SSO_LOGIN_URL") or "").strip()


def _merge_sso_path(base_url: str, path: str) -> str:
    parsed = urlparse(base_url)
    merged_path = path if path.startswith("/") else f"/{path}"
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            merged_path,
            "",
            "",
            "",
        )
    )


def get_sso_scanner_redirect_url() -> str:
    explicit = (os.getenv("SSO_SCANNER_REDIRECT_URL") or "").strip()
    if explicit:
        return explicit
    login_url = get_sso_login_url()
    if not login_url:
        return ""
    return _merge_sso_path(login_url, "/api/scan/redirect")


def get_sso_verify_url() -> str:
    explicit = (os.getenv("SSO_VERIFY_URL") or "").strip()
    if explicit:
        return explicit
    login_url = get_sso_login_url()
    if not login_url:
        return ""
    return _merge_sso_path(login_url, "/api/sso/verify")


def build_sso_login_redirect(request: Request) -> str:
    redirect_base = get_sso_scanner_redirect_url()
    if not redirect_base:
        return str(request.base_url)

    return_to = (
        (request.query_params.get("return_to") or "").strip()
        or (request.headers.get("x-cloudguard-return-to") or "").strip()
        or (request.headers.get("referer") or "").strip()
        or str(request.url)
    )
    return f"{redirect_base}?{urlencode({'returnTo': return_to})}"


def _standalone_user_id(request: Request) -> str:
    return (
        _clean_user_id(request.cookies.get(USER_ID_COOKIE))
        or (os.getenv("STANDALONE_USER_ID") or "").strip()
        or "anonymous"
    )


def _build_standalone_user(request: Request) -> dict:
    user_id = _standalone_user_id(request)
    return {
        "id": user_id,
        "email": f"{user_id}@cloudguard.local",
        "name": "Standalone User" if user_id != "anonymous" else "Anonymous User",
    }


def use_standalone_auth(request: Request) -> bool:
    auth_mode = (os.getenv("CLOUDGUARD_AUTH_MODE") or "").strip().lower()
    if auth_mode == "standalone":
        return True
    if auth_mode == "sso":
        return False

    login_url = (os.getenv("SSO_LOGIN_URL") or "").strip()
    if not login_url:
        return True

    try:
        login_host = urlparse(login_url).netloc.lower()
    except Exception:
        login_host = ""

    request_host = request.url.netloc.lower()
    return not login_host or login_host == request_host


def _get_database_url() -> str:
    db_url = os.getenv("DATABASE_URL")
    if not db_url:
        raise RuntimeError("DATABASE_URL not set")
    return db_url


def _get_nextauth_session_token(request: Request) -> Optional[str]:
    for cookie_name in SSO_SESSION_COOKIE_NAMES:
        token = _clean_user_id(request.cookies.get(cookie_name))
        if token:
            return token
    return None


def _get_sso_exchange_token(request: Request) -> Optional[str]:
    header = (request.headers.get("authorization") or "").strip()
    if header.lower().startswith("bearer "):
        token = _clean_user_id(header[7:])
        if token:
            return token

    query_token = _clean_user_id(request.query_params.get("token"))
    if query_token:
        return query_token

    return _clean_user_id(request.cookies.get(SSO_TOKEN_COOKIE))


def verify_sso_token(token: str) -> Optional[dict]:
    verify_url = get_sso_verify_url()

    try:
        response = requests.get(
            verify_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=5,
        )
    except requests.RequestException:
        return None

    if response.status_code >= 400:
        return None

    try:
        payload = response.json()
    except ValueError:
        return None

    if not payload.get("valid") or not isinstance(payload.get("user"), dict):
        return None

    user = payload["user"]
    user_id = _clean_user_id(str(user.get("sub") or ""))
    email = _clean_user_id(user.get("email"))
    if not user_id or not email:
        return None

    return {
        "id": user_id,
        "email": email,
        "name": _clean_user_id(user.get("name")) or email,
        "role": _clean_user_id(user.get("role")),
        "image": _clean_user_id(user.get("image")),
        "token": token,
    }


def authenticate_sso_user(request: Request) -> Optional[dict]:
    cached_user = getattr(request.state, "authenticated_user", None)
    if cached_user:
        return cached_user

    scanner_report_user = _authenticate_scanner_report_user(request)
    if scanner_report_user:
        return scanner_report_user

    if use_standalone_auth(request):
        user = _build_standalone_user(request)
        request.state.authenticated_user = user
        request.state.user_id = user["id"]
        return user

    sso_token = _get_sso_exchange_token(request)
    if sso_token:
        user = verify_sso_token(sso_token)
        if user:
            request.state.authenticated_user = user
            request.state.user_id = user["id"]
            request.state.sso_token = sso_token
            return user

    session_token = _get_nextauth_session_token(request)
    if not session_token:
        return None

    conn = psycopg2.connect(_get_database_url())
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT u.id, u.email, u.name
                FROM "Session" s
                JOIN "User" u ON u.id = s."userId"
                WHERE s."sessionToken" = %s
                  AND s."expires" > NOW()
                LIMIT 1
                """,
                (session_token,),
            )
            row = cur.fetchone()
            if not row:
                return None

            user = {"id": row[0], "email": row[1], "name": row[2]}
            request.state.authenticated_user = user
            request.state.user_id = user["id"]
            return user
    finally:
        conn.close()


def require_authenticated_user(request: Request) -> dict:
    user = authenticate_sso_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required")
    return user


def resolve_user_id(request: Request) -> str:
    """Resolve the authenticated CloudGuard user ID from the shared SSO session."""
    return require_authenticated_user(request)["id"]

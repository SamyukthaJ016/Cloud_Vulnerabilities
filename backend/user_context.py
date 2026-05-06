import os
import hashlib
import hmac
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
HTML_PAGE_PATHS = {
    "/",
    "/dashboard",
    "/frontend/history.html",
    "/schedules",
    "/system-status",
}

USER_ID_COOKIE = "cloudguard_user_id"
SSO_TOKEN_COOKIE = "cloudguard_sso_token"

SCANNER_REPORT_PATHS = {
    "/dashboard",
    "/posture/dashboard",
    "/api/severity-breakdown",
    "/api/provider-breakdown",
    "/api/scan-history",
    "/api/latest-findings",
    "/api/scans",
}


def _clean_user_id(value: str | None) -> str | None:
    if not value:
        return None

    cleaned = value.strip()
    return cleaned or None


def is_public_path(path: str) -> bool:
    return (
        path in PUBLIC_PATHS
        or (path.startswith("/api/scans/") and path.endswith("/view-token"))
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


def _scanner_shared_secret() -> str:
    return (
        os.getenv("CONTROL_PLANE_SCANNER_SHARED_SECRET")
        or os.getenv("SCANNER_SHARED_SECRET")
        or os.getenv("SHARED_SECRET")
        or ""
    ).strip()


def _scanner_view_secret(scan_id: str) -> str:
    return hmac.new(
        _scanner_shared_secret().encode("utf-8"),
        f"view:{scan_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _extract_report_scan_token_source(request: Request) -> str:
    return (
        (request.query_params.get("scanIds") or "").strip()
        or (request.query_params.get("scanId") or "").strip()
        or (request.query_params.get("scan_ids") or "").strip()
        or (request.query_params.get("scan_id") or "").strip()
    )


def _has_report_token_attempt(request: Request) -> bool:
    return bool((request.query_params.get("secret") or "").strip()) or bool(
        _extract_report_scan_token_source(request)
    )


def _parse_report_scan_ids(value: str) -> list[int]:
    ids: list[int] = []
    for item in value.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            ids.append(int(item))
        except ValueError:
            return []
    return ids


def _authenticate_scanner_report_user(request: Request) -> Optional[dict]:
    if request.url.path not in SCANNER_REPORT_PATHS:
        return None

    shared_secret = _scanner_shared_secret()
    provided_secret = (request.query_params.get("secret") or "").strip()
    token_source = _extract_report_scan_token_source(request)
    scan_ids = _parse_report_scan_ids(token_source)
    if not shared_secret or not provided_secret or not token_source or not scan_ids:
        return None

    if not hmac.compare_digest(provided_secret, _scanner_view_secret(token_source)):
        return None

    conn = psycopg2.connect(_get_database_url())
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id
                FROM scans
                WHERE id = ANY(%s)
                GROUP BY user_id
                HAVING COUNT(*) = %s
                LIMIT 1
                """,
                (scan_ids, len(scan_ids)),
            )
            row = cur.fetchone()
            if not row:
                return None

            user_id = row[0]
            return {
                "id": user_id,
                "email": f"{user_id}@scanner-report.cloudguard.local",
                "name": "CloudGuard scanner report",
                "role": "report_viewer",
            }
    finally:
        conn.close()


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

    report_user = _authenticate_scanner_report_user(request)
    if report_user:
        request.state.authenticated_user = report_user
        request.state.user_id = report_user["id"]
        return report_user
    if request.url.path in SCANNER_REPORT_PATHS and _has_report_token_attempt(request):
        raise HTTPException(status_code=401, detail="Invalid scanner report token")

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

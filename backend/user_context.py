import os
from typing import Optional
from urllib.parse import urlencode

import psycopg2
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
}
HTML_PAGE_PATHS = {
    "/",
    "/dashboard",
    "/frontend/history.html",
    "/schedules",
    "/system-status",
}

USER_ID_COOKIE = "cloudguard_user_id"


def _clean_user_id(value: str | None) -> str | None:
    if not value:
        return None

    cleaned = value.strip()
    return cleaned or None


def is_public_path(path: str) -> bool:
    return path in PUBLIC_PATHS


def is_html_navigation(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return request.url.path in HTML_PAGE_PATHS or "text/html" in accept


def get_sso_login_url() -> str:
    return os.getenv("SSO_LOGIN_URL", "http://localhost:3000/")


def build_sso_login_redirect(request: Request) -> str:
    return f"{get_sso_login_url()}?{urlencode({'callbackUrl': str(request.url)})}"


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


def authenticate_sso_user(request: Request) -> Optional[dict]:
    cached_user = getattr(request.state, "authenticated_user", None)
    if cached_user:
        return cached_user

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

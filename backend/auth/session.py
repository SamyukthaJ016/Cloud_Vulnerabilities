from typing import Any, Dict, Optional

from fastapi import HTTPException, Request


def get_current_user(request: Request) -> Optional[Dict[str, Any]]:
    try:
        session = request.session
    except Exception:
        return None

    user = session.get("user")
    return user if isinstance(user, dict) else None


def resolve_user_id(request: Request) -> str:
    """Resolve authenticated user identity, with legacy cookie fallback."""
    user = get_current_user(request)
    if user:
        google_sub = user.get("sub")
        if google_sub:
            return f"user_{google_sub}"

        explicit = user.get("user_id")
        if explicit:
            return str(explicit)

    legacy_session = request.cookies.get("session_id")
    if legacy_session:
        raw = legacy_session.replace("user_", "")
        return f"user_{raw}"

    return "anonymous"


def require_authenticated_user(request: Request) -> Dict[str, Any]:
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Authentication required. Sign in with Google.",
        )
    return user

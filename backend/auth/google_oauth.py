from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse

from backend.auth.settings import (
    GOOGLE_OAUTH_CLIENT_ID,
    GOOGLE_OAUTH_CLIENT_SECRET,
    OAUTH_REDIRECT_BASE_URL,
    oauth_configured,
)
from backend.auth.session import get_current_user

router = APIRouter(tags=["oauth"])

oauth = OAuth()
oauth.register(
    name="google",
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_id=GOOGLE_OAUTH_CLIENT_ID or None,
    client_secret=GOOGLE_OAUTH_CLIENT_SECRET or None,
    client_kwargs={"scope": "openid email profile"},
)


def _build_callback_url() -> str:
    base = OAUTH_REDIRECT_BASE_URL.rstrip("/")
    return f"{base}/auth/google/callback"


@router.get("/auth/google/login")
async def google_login(request: Request, next: str = "/"):
    if not oauth_configured():
        raise HTTPException(
            status_code=500,
            detail="Google OAuth is not configured. Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET.",
        )

    # keep only relative redirects to avoid open redirect issues
    next_target = next if next.startswith("/") else "/"
    request.session["post_login_redirect"] = next_target

    redirect_uri = _build_callback_url()
    return await oauth.google.authorize_redirect(request, redirect_uri)


@router.get("/auth/google/callback")
async def google_callback(request: Request):
    if not oauth_configured():
        raise HTTPException(
            status_code=500,
            detail="Google OAuth is not configured. Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET.",
        )

    try:
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as err:
        return JSONResponse(
            status_code=401,
            content={"detail": "OAuth authentication failed", "error": str(err)},
        )

    userinfo = token.get("userinfo")
    if not userinfo:
        userinfo = await oauth.google.parse_id_token(request, token)

    if not userinfo or not userinfo.get("sub"):
        return JSONResponse(
            status_code=401,
            content={"detail": "Google user info missing in OAuth response."},
        )

    user = {
        "sub": userinfo.get("sub"),
        "email": userinfo.get("email"),
        "name": userinfo.get("name"),
        "given_name": userinfo.get("given_name"),
        "family_name": userinfo.get("family_name"),
        "picture": userinfo.get("picture"),
        "user_id": f"user_{userinfo.get('sub')}",
    }
    request.session["user"] = user

    next_target = request.session.pop("post_login_redirect", "/")
    if not isinstance(next_target, str) or not next_target.startswith("/"):
        next_target = "/"

    response = RedirectResponse(url=next_target, status_code=302)
    return response


@router.get("/auth/me")
async def auth_me(request: Request):
    user = get_current_user(request)
    if not user:
        return JSONResponse(
            status_code=401,
            content={"authenticated": False, "detail": "Not authenticated"},
        )

    return {
        "authenticated": True,
        "user": user,
        "user_id": user.get("user_id") or f"user_{user.get('sub')}",
    }


@router.post("/auth/logout")
async def auth_logout(request: Request):
    request.session.pop("user", None)
    request.session.pop("post_login_redirect", None)

    response = JSONResponse({"success": True})
    response.delete_cookie("session_id", path="/")
    return response

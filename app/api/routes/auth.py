from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import RedirectResponse
from urllib.parse import urlencode
from urllib.request import Request, urlopen
from urllib.error import HTTPError, URLError
import json
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.api.deps import get_current_user
from app.db.mongo import get_mongo_db, to_object_id
from app.schemas.auth import (
    UserCreate,
    UserLogin,
    UserRead,
    Token,
    PasswordResetRequest,
    PasswordResetConfirm,
    PasswordResetValidate,
    PasswordResetValidation,
    Message,
)
from app.schemas.user import UserPublic, UserProfileUpdate
from app.services.auth_service import AuthService
from app.core.exceptions import ConflictException, AuthenticationException
from app.core.config import settings


router = APIRouter(prefix="/auth", tags=["auth"])
auth_service = AuthService()


@router.post("/register", response_model=UserRead, status_code=201)
async def register(payload: UserCreate, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Register a new user account.
    
    - email: Must be unique
    - password: Minimum 6 characters (will be hashed with bcrypt)
    - full_name: Optional
    
    New users are assigned 'normal' role by default.
    """
    try:
        user = await auth_service.register(db, payload.email, payload.password, payload.full_name)
        return auth_service.to_public(user)
    except ConflictException as e:
        raise HTTPException(status_code=409, detail=str(e))
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Registration failed: {str(e)}")


@router.post("/login", response_model=Token)
async def login(payload: UserLogin, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Authenticate user with email and password.
    
    Returns JWT access token valid for the configured expiration time.
    """
    try:
        user = await auth_service.authenticate(db, payload.email, payload.password)
        return auth_service.issue_token(user)
    except AuthenticationException as e:
        raise HTTPException(status_code=401, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")


@router.post("/logout")
async def logout(user=Depends(get_current_user)):
    """
    Logout user (client should discard token).
    Note: This is a stateless operation since we use JWT tokens.
    """
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserPublic)
async def me(user=Depends(get_current_user)):
    """
    Get current authenticated user profile.
    """
    return user


@router.patch("/me", response_model=UserPublic)
async def update_me(
    payload: UserProfileUpdate,
    user=Depends(get_current_user),
    db: AsyncIOMotorDatabase = Depends(get_mongo_db),
):
    updates = {}
    if payload.full_name is not None:
        updates["full_name"] = payload.full_name.strip() or None
    if payload.avatar_url is not None:
        updates["avatar_url"] = payload.avatar_url or None
    if not updates:
        return user

    updates["updated_at"] = datetime.utcnow()
    object_id = to_object_id(user.get("id", ""))
    if not object_id:
        raise HTTPException(status_code=400, detail="Invalid user id")
    await db.users.update_one({"_id": object_id}, {"$set": updates})
    updated = await db.users.find_one({"_id": object_id})
    return auth_service.to_public(updated)


@router.post("/refresh", response_model=Token)
async def refresh(user=Depends(get_current_user)):
    """
    Refresh access token for the current user.
    Returns a new access token with updated expiration.
    """
    return auth_service.issue_token(user)


@router.get("/oauth/github")
async def oauth_github():
    """OAuth2 GitHub login redirect."""
    if not settings.GITHUB_OAUTH_CLIENT_ID or not settings.GITHUB_OAUTH_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="GitHub OAuth is not configured")
    params = {
        "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
        "redirect_uri": settings.GITHUB_OAUTH_REDIRECT_URI,
        "scope": "read:user user:email",
    }
    url = "https://github.com/login/oauth/authorize?" + urlencode(params)
    return RedirectResponse(url)


@router.get("/oauth/google")
async def oauth_google():
    """OAuth2 Google login redirect."""
    if not settings.GOOGLE_OAUTH_CLIENT_ID or not settings.GOOGLE_OAUTH_REDIRECT_URI:
        raise HTTPException(status_code=500, detail="Google OAuth is not configured")
    params = {
        "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)
    return RedirectResponse(url)


@router.get("/oauth/google/callback")
async def oauth_google_callback(code: str, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """OAuth2 Google callback to exchange code and issue JWT."""
    if not settings.GOOGLE_OAUTH_CLIENT_ID or not settings.GOOGLE_OAUTH_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="Google OAuth is not configured")

    token_payload = urlencode(
        {
            "code": code,
            "client_id": settings.GOOGLE_OAUTH_CLIENT_ID,
            "client_secret": settings.GOOGLE_OAUTH_CLIENT_SECRET,
            "redirect_uri": settings.GOOGLE_OAUTH_REDIRECT_URI,
            "grant_type": "authorization_code",
        }
    ).encode("utf-8")
    token_req = Request(
        "https://oauth2.googleapis.com/token",
        data=token_payload,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    try:
        with urlopen(token_req, timeout=10) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=400, detail=f"Google token exchange failed: {detail}") from exc
    except URLError as exc:
        raise HTTPException(status_code=502, detail=f"Google token exchange error: {exc.reason}") from exc

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="Google token exchange missing access_token")

    userinfo_req = Request(
        "https://www.googleapis.com/oauth2/v2/userinfo",
        headers={"Authorization": f"Bearer {access_token}"},
        method="GET",
    )
    try:
        with urlopen(userinfo_req, timeout=10) as resp:
            userinfo = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=400, detail=f"Google userinfo failed: {detail}") from exc
    except URLError as exc:
        raise HTTPException(status_code=502, detail=f"Google userinfo error: {exc.reason}") from exc

    email = userinfo.get("email")
    if not email:
        raise HTTPException(status_code=400, detail="Google userinfo missing email")

    full_name = userinfo.get("name")
    google_sub = userinfo.get("id") or userinfo.get("sub", "")

    user = await auth_service.get_or_create_google_user(db, email, full_name, google_sub)
    token = auth_service.issue_token(user)

    redirect_params = urlencode({"token": token["access_token"]})
    redirect_url = f"{settings.FRONTEND_OAUTH_REDIRECT_URL}?{redirect_params}"
    return RedirectResponse(redirect_url)


@router.get("/oauth/github/callback")
async def oauth_github_callback(code: str, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """OAuth2 GitHub callback to exchange code and issue JWT."""
    if not settings.GITHUB_OAUTH_CLIENT_ID or not settings.GITHUB_OAUTH_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GitHub OAuth is not configured")

    token_payload = urlencode(
        {
            "client_id": settings.GITHUB_OAUTH_CLIENT_ID,
            "client_secret": settings.GITHUB_OAUTH_CLIENT_SECRET,
            "code": code,
            "redirect_uri": settings.GITHUB_OAUTH_REDIRECT_URI,
        }
    ).encode("utf-8")
    token_req = Request(
        "https://github.com/login/oauth/access_token",
        data=token_payload,
        headers={"Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(token_req, timeout=10) as resp:
            token_data = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=400, detail=f"GitHub token exchange failed: {detail}") from exc
    except URLError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub token exchange error: {exc.reason}") from exc

    access_token = token_data.get("access_token")
    if not access_token:
        raise HTTPException(status_code=400, detail="GitHub token exchange missing access_token")

    user_req = Request(
        "https://api.github.com/user",
        headers={"Authorization": f"Bearer {access_token}", "User-Agent": "vulcan-backend"},
        method="GET",
    )
    try:
        with urlopen(user_req, timeout=10) as resp:
            userinfo = json.loads(resp.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        raise HTTPException(status_code=400, detail=f"GitHub userinfo failed: {detail}") from exc
    except URLError as exc:
        raise HTTPException(status_code=502, detail=f"GitHub userinfo error: {exc.reason}") from exc

    email = userinfo.get("email")
    if not email:
        emails_req = Request(
            "https://api.github.com/user/emails",
            headers={"Authorization": f"Bearer {access_token}", "User-Agent": "vulcan-backend"},
            method="GET",
        )
        try:
            with urlopen(emails_req, timeout=10) as resp:
                emails = json.loads(resp.read().decode("utf-8"))
            primary = next((e for e in emails if e.get("primary") and e.get("verified")), None)
            email = primary.get("email") if primary else None
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="ignore")
            raise HTTPException(status_code=400, detail=f"GitHub emails lookup failed: {detail}") from exc
        except URLError as exc:
            raise HTTPException(status_code=502, detail=f"GitHub emails lookup error: {exc.reason}") from exc

    if not email:
        raise HTTPException(status_code=400, detail="GitHub user email not available")

    full_name = userinfo.get("name") or userinfo.get("login")
    github_id = str(userinfo.get("id"))

    user = await auth_service.get_or_create_github_user(db, email, full_name, github_id)
    token = auth_service.issue_token(user)

    redirect_params = urlencode({"token": token["access_token"]})
    redirect_url = f"{settings.FRONTEND_OAUTH_REDIRECT_URL}?{redirect_params}"
    return RedirectResponse(redirect_url)


@router.post("/forgot-password", response_model=Message)
async def forgot_password(payload: PasswordResetRequest, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Request a password reset email.
    Always returns success to avoid leaking account existence.
    """
    try:
        await auth_service.request_password_reset(db, payload.email)
        return Message(message="If the account exists, a reset email has been sent.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to request password reset: {str(e)}")


@router.post("/reset-password", response_model=Message)
async def reset_password(payload: PasswordResetConfirm, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Reset password using a valid reset token.
    """
    try:
        await auth_service.reset_password(db, payload.token, payload.new_password)
        return Message(message="Password reset successfully.")
    except AuthenticationException as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to reset password: {str(e)}")


@router.post("/validate-reset-token", response_model=PasswordResetValidation)
async def validate_reset_token(payload: PasswordResetValidate, db: AsyncIOMotorDatabase = Depends(get_mongo_db)):
    """
    Validate a password reset token before showing the reset form.
    """
    try:
        is_valid = await auth_service.validate_reset_token(db, payload.token)
        if not is_valid:
            return PasswordResetValidation(valid=False, message="Invalid or expired reset token.")
        return PasswordResetValidation(valid=True, message="Token is valid.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to validate reset token: {str(e)}")

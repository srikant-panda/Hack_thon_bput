"""Authenticated user endpoints."""

from fastapi import APIRouter, Depends, Response,status
from fastapi.responses import JSONResponse
from app.schemas.authScema import LoginScema
from app.core.security import CurrentUser, get_current_user
from app.core.supabase_client import get_supabase

router = APIRouter(tags=["auth"])


@router.get("/auth/me")
async def read_current_user(user: CurrentUser = Depends(get_current_user)) -> dict:
    """Return the identity of the caller verified via Supabase Auth."""
    return {
        "id": user.id,
        "email": user.email,
        "role": "analyst",
    }


@router.post("/auth/login")
async def login(payload: LoginScema, response: Response) -> dict:
    """authonticate the user and return tokens"""
    supabase = get_supabase()
    result = supabase.auth.sign_in_with_password(
        {"email": payload.email, "password": payload.password}
    )

    print(result.user)
    print(result.session.access_token, result.session.refresh_token)

    response.headers["Authorization"] = f"Bearer {result.session.access_token}"
    response.set_cookie(
        key="refresh_token",
        value=result.session.refresh_token,
        httponly=True,
        secure=False,  # True in production
        samesite="lax",
        max_age=60 * 60 * 24 * 7,
    )
    return {"message": "user login successfully."}



@router.post("/register")
async def register(data: LoginScema):
    supabase = get_supabase()
    result = supabase.auth.sign_up({
        "email": data.email,
        "password": data.password
    })

    if result.user is None:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={
                "success": False,
                "message": "Registration failed"
            }
        )

    # Email confirmation enabled
    if result.session is None:
        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content={
                "success": True,
                "message": "Registration successful. Please verify your email.",
                "user_id": str(result.user.id)
            }
        )

    # Session exists → user logged in immediately
    response = JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content={
            "success": True,
            "message": "Registration successful",
            "user_id": str(result.user.id)
        }
    )

    response.headers["Authorization"] = (
        f"Bearer {result.session.access_token}"
    )

    response.set_cookie(
        key="refresh_token",
        value=result.session.refresh_token,
        httponly=True,
        secure=False,  # True in production
        samesite="lax",
        max_age=60 * 60 * 24 * 7
    )

    return response
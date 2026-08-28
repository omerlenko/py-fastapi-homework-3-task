from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
from schemas import UserRegistrationRequestSchema, UserRegistrationResponseSchema, MessageResponseSchema, \
    UserActivationRequestSchema, PasswordResetCompleteRequestSchema, PasswordResetRequestSchema, \
    UserLoginResponseSchema, UserLoginRequestSchema, TokenRefreshResponseSchema, TokenRefreshRequestSchema
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from config import get_jwt_auth_manager, get_settings, BaseAppSettings
from database import (
    get_db,
    UserModel,
    UserGroupModel,
    UserGroupEnum,
    ActivationTokenModel,
    PasswordResetTokenModel,
    RefreshTokenModel
)
from exceptions import TokenExpiredError, InvalidTokenError
from security.interfaces import JWTAuthManagerInterface


router = APIRouter()
DbDep = Annotated[AsyncSession, Depends(get_db)]
JWTDep = Annotated[JWTAuthManagerInterface, Depends(get_jwt_auth_manager)]
Settings = Annotated[BaseAppSettings, Depends(get_settings)]


async def get_user_by_email(db: AsyncSession, email: str) -> UserModel | None:
    user = await db.scalar(select(UserModel).where(UserModel.email == email))
    return user


def as_utc(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


@router.post("/register/", response_model=UserRegistrationResponseSchema, status_code=201)
async def register_user(db: DbDep, data: UserRegistrationRequestSchema):
    if await get_user_by_email(db=db, email=data.email):
        raise HTTPException(status_code=409, detail=f"A user with this email {data.email} already exists.")

    user_group = await db.scalar(select(UserGroupModel).where(UserGroupModel.name == UserGroupEnum.USER))
    if user_group is None:
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    try:
        user = UserModel.create(email=data.email, raw_password=data.password, group_id=user_group.id)
        activation_token = ActivationTokenModel(user=user)
        db.add(user)
        db.add(activation_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred during user creation.")

    return user


@router.post("/activate/", response_model=MessageResponseSchema)
async def activate_user(db: DbDep, data: UserActivationRequestSchema):
    user = await get_user_by_email(db=db, email=data.email)
    if user is None:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")
    if user.is_active:
        raise HTTPException(status_code=400, detail="User account is already active.")

    now = datetime.now(timezone.utc)
    token: ActivationTokenModel | None = await db.scalar(
        select(ActivationTokenModel).where(
            ActivationTokenModel.token == data.token,
            ActivationTokenModel.user_id == user.id
        )
    )
    if token is None or as_utc(token.expires_at) <= now:
        raise HTTPException(status_code=400, detail="Invalid or expired activation token.")

    user.is_active = True
    await db.delete(token)
    await db.commit()

    return {
        "message": "User account activated successfully."
    }


@router.post("/password-reset/request/", response_model=MessageResponseSchema)
async def request_reset_password(db: DbDep, data: PasswordResetRequestSchema):
    response_message = {
        "message": "If you are registered, you will receive an email with instructions."
    }
    user = await get_user_by_email(db=db, email=data.email)
    if user is None or not user.is_active:
        return response_message

    existing_reset_token = await db.scalar(
        select(PasswordResetTokenModel).where(PasswordResetTokenModel.user_id == user.id)
    )
    if existing_reset_token is not None:
        await db.delete(existing_reset_token)
        await db.flush()

    new_token = PasswordResetTokenModel(user=user)
    db.add(new_token)
    await db.commit()

    return response_message


@router.post("/reset-password/complete/", response_model=MessageResponseSchema)
async def complete_reset_password(db: DbDep, data: PasswordResetCompleteRequestSchema):
    now = datetime.now(timezone.utc)
    user = await get_user_by_email(db=db, email=data.email)
    if user is None or not user.is_active:
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    reset_token: PasswordResetTokenModel | None = await db.scalar(
        select(PasswordResetTokenModel).where(
            PasswordResetTokenModel.user_id == user.id,
        )
    )
    if reset_token is None:
        raise HTTPException(status_code=400, detail="Invalid email or token.")
    if data.token != reset_token.token or as_utc(reset_token.expires_at) <= now:
        await db.delete(reset_token)
        await db.commit()
        raise HTTPException(status_code=400, detail="Invalid email or token.")

    try:
        user.password = data.password
        await db.delete(reset_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(
            status_code=500, detail="An error occurred while resetting the password."
        )

    return {
        "message": "Password reset successfully."
    }


@router.post("/login/", response_model=UserLoginResponseSchema, status_code=201)
async def login_user(db: DbDep, data: UserLoginRequestSchema, jwt_manager: JWTDep, settings: Settings):
    user = await get_user_by_email(db=db, email=data.email)
    if user is None or not user.verify_password(data.password):
        raise HTTPException(status_code=401, detail="Invalid email or password.")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="User account is not activated.")

    raw_access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    raw_refresh_token = jwt_manager.create_refresh_token(data={"user_id": user.id})
    refresh_token = RefreshTokenModel.create(
        token=raw_refresh_token,
        user_id=user.id,
        days_valid=settings.LOGIN_TIME_DAYS
    )
    try:
        db.add(refresh_token)
        await db.commit()
    except SQLAlchemyError:
        await db.rollback()
        raise HTTPException(status_code=500, detail="An error occurred while processing the request.")

    return UserLoginResponseSchema(
        access_token=raw_access_token, refresh_token=raw_refresh_token
    )


@router.post("/refresh/", response_model=TokenRefreshResponseSchema)
async def refresh(db: DbDep, data: TokenRefreshRequestSchema, jwt_manager: JWTDep):
    try:
        refresh_token_data = jwt_manager.decode_refresh_token(token=data.refresh_token)
    except TokenExpiredError:
        raise HTTPException(status_code=400, detail="Token has expired.")
    except InvalidTokenError:
        raise HTTPException(status_code=400, detail="Token is invalid.")

    refresh_token = await db.scalar(
        select(RefreshTokenModel).where(
            RefreshTokenModel.token == data.refresh_token,
            RefreshTokenModel.user_id == refresh_token_data["user_id"],
        )
    )
    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Refresh token not found.")

    user = await db.get(UserModel, refresh_token_data["user_id"])
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    access_token = jwt_manager.create_access_token(data={"user_id": user.id})
    return TokenRefreshResponseSchema(
        access_token=access_token
    )

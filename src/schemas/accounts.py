from typing import Annotated, Literal

from pydantic import BaseModel, EmailStr, ConfigDict, Field, AfterValidator


def validate_password(password: str) -> str:
    if len(password) < 8:
        raise ValueError("Password must contain at least 8 characters.")

    if not any(char.isupper() for char in password):
        raise ValueError("Password must contain at least one uppercase letter.")

    if not any(char.islower() for char in password):
        raise ValueError("Password must contain at least one lower letter.")

    if not any(char.isdigit() for char in password):
        raise ValueError("Password must contain at least one digit.")

    if not any(char in "@$!%*?#&" for char in password):
        raise ValueError("Password must contain at least one special character: @, $, !, %, *, ?, #, &.")

    return password


Password = Annotated[str, AfterValidator(validate_password)]
Token = Annotated[str, Field(max_length=64)]


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: Password


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: str

    model_config = ConfigDict(from_attributes=True)


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: Token


class MessageResponseSchema(BaseModel):
    message: str


class PasswordResetRequestSchema(BaseModel):
    email: EmailStr


class PasswordResetCompleteRequestSchema(BaseModel):
    email: EmailStr
    token: Token
    password: Password


class UserLoginRequestSchema(BaseModel):
    email: EmailStr
    password: str


class UserLoginResponseSchema(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"


class TokenRefreshRequestSchema(BaseModel):
    refresh_token: str


class TokenRefreshResponseSchema(BaseModel):
    access_token: str

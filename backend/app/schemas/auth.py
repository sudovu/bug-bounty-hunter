"""Pydantic schemas for Authentication and Authorization."""
import re
from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, field_validator
from backend.app.db.models import UserRole

EMAIL_REGEX = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def validate_email_format(v: str) -> str:
    clean = v.strip().lower()
    if not EMAIL_REGEX.match(clean):
        raise ValueError("Invalid email address format")
    return clean


class UserLogin(BaseModel):
    username: str
    password: str


class AdminSetup(BaseModel):
    username: str
    email: str
    password: str
    confirm_password: str

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 3:
            raise ValueError("Username must be at least 3 characters long")
        return clean

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return validate_email_format(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    role: UserRole = UserRole.REVIEWER

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        clean = v.strip()
        if len(clean) < 3:
            raise ValueError("Username must be at least 3 characters long")
        return clean

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        return validate_email_format(v)

    @field_validator("password")
    @classmethod
    def validate_password(cls, v: str) -> str:
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters long")
        return v


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class AuthStatusResponse(BaseModel):
    setup_required: bool
    authenticated: bool
    user: Optional[UserOut] = None

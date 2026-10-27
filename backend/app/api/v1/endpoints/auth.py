"""API Endpoints for Authentication and User Authorization."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.base import get_db
from backend.app.db.models import User, UserRole
from backend.app.schemas.auth import (
    UserLogin, AdminSetup, UserCreate, UserOut, TokenResponse, AuthStatusResponse
)
from backend.app.core.security import hash_password, verify_password, create_access_token
from backend.app.core.audit import record_audit_event
from backend.app.api.deps import get_current_user, require_admin, get_current_user_optional

router = APIRouter()


@router.get("/status", response_model=AuthStatusResponse)
def get_auth_status(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user_optional)
):
    """Check if initial setup is required or if current session is authenticated."""
    user_count = db.query(User).count()
    return AuthStatusResponse(
        setup_required=(user_count == 0),
        authenticated=(current_user is not None),
        user=current_user
    )


@router.post("/setup", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def initial_admin_setup(payload: AdminSetup, db: Session = Depends(get_db)):
    """First-time setup wizard: Create Master Administrator account.
    
    Permanently locked once the first user is created.
    """
    user_count = db.query(User).count()
    if user_count > 0:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="System is already initialized. Please login with existing credentials."
        )

    if payload.password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Passwords do not match."
        )

    admin_user = User(
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        hashed_password=hash_password(payload.password),
        role=UserRole.ADMIN,
        is_active=True
    )
    db.add(admin_user)
    db.commit()
    db.refresh(admin_user)

    record_audit_event(
        db,
        actor=admin_user.username,
        action="INITIAL_ADMIN_SETUP",
        decision="SUCCESS",
        target=admin_user.username,
        reason="Master administrator account created via setup wizard."
    )

    token = create_access_token(data={"sub": str(admin_user.id), "username": admin_user.username, "role": admin_user.role.value})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=admin_user
    )


@router.post("/login", response_model=TokenResponse)
def login(payload: UserLogin, db: Session = Depends(get_db)):
    """Authenticate with username or email and password."""
    identifier = payload.username.strip()
    user = db.query(User).filter(
        (User.username == identifier) | (User.email == identifier.lower())
    ).first()

    if not user or not verify_password(payload.password, user.hashed_password):
        record_audit_event(
            db,
            actor=identifier,
            action="LOGIN_FAILED",
            decision="DENY",
            target=identifier,
            reason="Invalid credentials supplied."
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"}
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact an administrator."
        )

    record_audit_event(
        db,
        actor=user.username,
        action="LOGIN_SUCCESS",
        decision="ALLOW",
        target=user.username,
        reason=f"Authenticated successfully with role '{user.role.value}'."
    )

    token = create_access_token(data={"sub": str(user.id), "username": user.username, "role": user.role.value})
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        user=user
    )


@router.get("/me", response_model=UserOut)
def get_current_user_profile(current_user: User = Depends(get_current_user)):
    """Get currently authenticated user's profile and permissions."""
    return current_user


@router.get("/users", response_model=List[UserOut])
def list_users(
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """List all accounts (Admin only)."""
    return db.query(User).order_by(User.id.asc()).all()


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def create_user(
    payload: UserCreate,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Create a new operator account (Admin only)."""
    existing_user = db.query(User).filter(
        (User.username == payload.username.strip()) | (User.email == payload.email.strip().lower())
    ).first()
    if existing_user:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A user with that username or email already exists."
        )

    new_user = User(
        username=payload.username.strip(),
        email=payload.email.strip().lower(),
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    record_audit_event(
        db,
        actor=admin.username,
        action="CREATE_USER",
        decision="SUCCESS",
        target=new_user.username,
        reason=f"Created user with role {new_user.role.value}."
    )
    return new_user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    admin: User = Depends(require_admin)
):
    """Delete an operator account (Admin only). Cannot delete oneself."""
    if user_id == admin.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own administrator account."
        )

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")

    db.delete(target_user)
    db.commit()

    record_audit_event(
        db,
        actor=admin.username,
        action="DELETE_USER",
        decision="SUCCESS",
        target=target_user.username,
        reason=f"User ID {user_id} removed by {admin.username}."
    )
    return None

"""API Endpoints for Bug Bounty Programs and Scope Management."""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from backend.app.db.base import get_db
from backend.app.db.models import Program, AuthorizedAsset, ExcludedAsset
from backend.app.schemas.program import (
    ProgramCreate, ProgramOut, ProgramUpdate,
    AuthorizedAssetCreate, AuthorizedAssetOut,
    ExcludedAssetCreate, ExcludedAssetOut
)
from backend.app.engine.scope_engine import verify_target_authorization, ScopeVerificationResult
from backend.app.core.audit import record_audit_event

router = APIRouter()


@router.get("", response_model=List[ProgramOut])
def list_programs(db: Session = Depends(get_db)):
    """List all configured bug bounty programs with their scopes."""
    return db.query(Program).order_by(Program.created_at.desc()).all()


@router.post("", response_model=ProgramOut, status_code=status.HTTP_201_CREATED)
def create_program(payload: ProgramCreate, db: Session = Depends(get_db)):
    """Register a new authorized bug bounty program with in-scope and excluded assets."""
    existing = db.query(Program).filter(Program.name == payload.name).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Program with name '{payload.name}' already exists."
        )

    program = Program(
        name=payload.name,
        platform=payload.platform,
        program_url=payload.program_url,
        policy_summary=payload.policy_summary,
        max_rate_limit=payload.max_rate_limit or 2.0,
        authorization_active=payload.authorization_active,
        authorization_expires_at=payload.authorization_expires_at
    )
    db.add(program)
    db.commit()
    db.refresh(program)

    # Add in-scope assets
    for asset in payload.in_scope_assets:
        db_asset = AuthorizedAsset(
            program_id=program.id,
            asset_type=asset.asset_type,
            pattern=asset.pattern,
            allowed_methods=asset.allowed_methods or "GET,HEAD",
            notes=asset.notes
        )
        db.add(db_asset)

    # Add excluded assets
    for excl in payload.excluded_assets:
        db_excl = ExcludedAsset(
            program_id=program.id,
            pattern=excl.pattern,
            reason=excl.reason
        )
        db.add(db_excl)

    db.commit()
    db.refresh(program)

    record_audit_event(
        db,
        actor="user",
        action="CREATE_PROGRAM",
        decision="SUCCESS",
        target=program.name,
        reason=f"Registered program with {len(payload.in_scope_assets)} scope rules and {len(payload.excluded_assets)} exclusions."
    )

    return program


@router.get("/{program_id}", response_model=ProgramOut)
def get_program(program_id: int, db: Session = Depends(get_db)):
    program = db.query(Program).filter(Program.id == program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    return program


@router.post("/{program_id}/verify-scope", response_model=ScopeVerificationResult)
def test_scope_verification(program_id: int, target: str, db: Session = Depends(get_db)):
    """Dry-run scope engine test to verify whether a given target is allowed or blocked."""
    result = verify_target_authorization(
        db=db,
        program_id=program_id,
        target=target,
        actor="manual_scope_test"
    )
    return result


@router.post("/{program_id}/assets", response_model=AuthorizedAssetOut)
def add_in_scope_asset(program_id: int, payload: AuthorizedAssetCreate, db: Session = Depends(get_db)):
    program = db.query(Program).filter(Program.id == program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    asset = AuthorizedAsset(
        program_id=program.id,
        asset_type=payload.asset_type,
        pattern=payload.pattern,
        allowed_methods=payload.allowed_methods or "GET,HEAD",
        notes=payload.notes
    )
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


@router.post("/{program_id}/exclusions", response_model=ExcludedAssetOut)
def add_excluded_asset(program_id: int, payload: ExcludedAssetCreate, db: Session = Depends(get_db)):
    program = db.query(Program).filter(Program.id == program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")

    excl = ExcludedAsset(
        program_id=program.id,
        pattern=payload.pattern,
        reason=payload.reason
    )
    db.add(excl)
    db.commit()
    db.refresh(excl)
    return excl


@router.delete("/{program_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_program(program_id: int, db: Session = Depends(get_db)):
    program = db.query(Program).filter(Program.id == program_id).first()
    if not program:
        raise HTTPException(status_code=404, detail="Program not found")
    db.delete(program)
    db.commit()
    return None

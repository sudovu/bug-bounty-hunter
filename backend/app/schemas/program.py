"""Pydantic models for Programs, Assets, and Exclusions."""
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict
from backend.app.db.models import AssetType


class AuthorizedAssetCreate(BaseModel):
    asset_type: AssetType
    pattern: str
    allowed_methods: Optional[str] = "GET,HEAD"
    notes: Optional[str] = None


class AuthorizedAssetOut(BaseModel):
    id: int
    program_id: int
    asset_type: AssetType
    pattern: str
    allowed_methods: str
    notes: Optional[str]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ExcludedAssetCreate(BaseModel):
    pattern: str
    reason: Optional[str] = None


class ExcludedAssetOut(BaseModel):
    id: int
    program_id: int
    pattern: str
    reason: Optional[str]
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)


class ProgramCreate(BaseModel):
    name: str
    platform: str
    program_url: str
    policy_summary: Optional[str] = None
    max_rate_limit: Optional[float] = 2.0
    authorization_active: bool = True
    authorization_expires_at: Optional[datetime] = None
    in_scope_assets: List[AuthorizedAssetCreate] = []
    excluded_assets: List[ExcludedAssetCreate] = []


class ProgramUpdate(BaseModel):
    name: Optional[str] = None
    platform: Optional[str] = None
    program_url: Optional[str] = None
    policy_summary: Optional[str] = None
    max_rate_limit: Optional[float] = None
    authorization_active: Optional[bool] = None
    authorization_expires_at: Optional[datetime] = None


class ProgramOut(BaseModel):
    id: int
    name: str
    platform: str
    program_url: str
    policy_summary: Optional[str]
    max_rate_limit: float
    authorization_active: bool
    authorization_expires_at: Optional[datetime]
    last_scope_verification: datetime
    created_at: datetime
    updated_at: datetime
    in_scope_assets: List[AuthorizedAssetOut] = []
    excluded_assets: List[ExcludedAssetOut] = []
    model_config = ConfigDict(from_attributes=True)

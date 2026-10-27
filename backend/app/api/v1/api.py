"""API Router Configuration."""
from fastapi import APIRouter
from backend.app.api.v1.endpoints import (
    auth,
    programs,
    scans,
    findings,
    approvals,
    system,
    reports
)

api_router = APIRouter()
api_router.include_router(auth.router, prefix="/auth", tags=["Authentication & Users"])
api_router.include_router(programs.router, prefix="/programs", tags=["Programs & Scope"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(findings.router, prefix="/findings", tags=["Findings"])
api_router.include_router(approvals.router, prefix="/approvals", tags=["Approvals"])
api_router.include_router(system.router, prefix="/system", tags=["System & Emergency Stop"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])

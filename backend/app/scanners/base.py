"""Base Scanner Interface and Execution Safety Wrappers."""
import abc
import asyncio
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.core.emergency import emergency_control
from backend.app.db.models import FindingSeverity, FindingConfidence, ScanMode
from backend.app.engine.scope_engine import verify_target_authorization, ScopeVerificationResult


class RawFindingCandidate(BaseModel):
    category: str
    title: str
    description: str
    evidence_summary: str
    raw_evidence: Optional[str] = None
    affected_component: Optional[str] = None
    potential_impact: Optional[str] = None
    safe_reproduction: Optional[str] = None
    policy_reference: Optional[str] = None
    recommended_remediation: Optional[str] = None
    detection_method: str
    severity: FindingSeverity
    confidence: FindingConfidence


class BaseScanner(abc.ABC):
    name: str = "base_scanner"
    description: str = "Base Security Scanner"
    allowed_mode: ScanMode = ScanMode.PASSIVE

    def __init__(self, timeout_seconds: int = 15):
        self.timeout_seconds = timeout_seconds

    @abc.abstractmethod
    async def execute_scan(
        self,
        target: str,
        scope_verification: ScopeVerificationResult
    ) -> List[RawFindingCandidate]:
        """Perform the actual security inspection."""
        pass

    async def run(
        self,
        db: Session,
        program_id: int,
        target: str,
        actor: str = "scanner_engine"
    ) -> List[RawFindingCandidate]:
        """Safety-gated scanner execution entry point.
        
        Enforces:
        - Emergency stop check
        - Scope verification (Default-DENY)
        - Scanner timeout
        """
        if emergency_control.is_global_stopped():
            return []

        # Scope verification MUST pass before executing any inspection
        verification = verify_target_authorization(
            db=db,
            program_id=program_id,
            target=target,
            requested_mode=self.allowed_mode,
            actor=actor
        )

        if not verification.allowed:
            return []

        try:
            return await asyncio.wait_for(
                self.execute_scan(target, verification),
                timeout=self.timeout_seconds
            )
        except asyncio.TimeoutError:
            return []
        except Exception:
            return []

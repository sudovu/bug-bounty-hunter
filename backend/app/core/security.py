"""Authentication, hashing, and token generation utilities."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Any
import jwt

from backend.app.core.config import settings

JWT_ALGORITHM = "HS256"
DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 24 * 7  # 7 days


def hash_password(password: str) -> str:
    """Create a secure SHA-256 salted hash for credentials."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(plain_password: str, hashed_value: str) -> bool:
    """Verify password against salt:hash format."""
    try:
        if not hashed_value or ":" not in hashed_value:
            return False
        salt, expected_hash = hashed_value.split(":")
        test_hash = hashlib.sha256((salt + plain_password).encode('utf-8')).hexdigest()
        return hmac.compare_digest(test_hash, expected_hash)
    except Exception:
        return False


def create_access_token(data: Dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=DEFAULT_ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=JWT_ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[Dict[str, Any]]:
    """Decode and validate a JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None


def generate_secure_token(prefix: str = "tok") -> str:
    """Generate a high-entropy cryptographically secure token."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def generate_deduplication_hash(*components: str) -> str:
    """Create a deterministic SHA-256 hash for deduplicating findings or alerts."""
    content = "|".join(str(c).strip().lower() for c in components)
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

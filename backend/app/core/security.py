"""Authentication, hashing, and token generation utilities."""
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta
from typing import Optional


def hash_password(password: str) -> str:
    """Create a secure SHA-256 salted hash for credentials."""
    salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(plain_password: str, hashed_value: str) -> bool:
    """Verify password against salt:hash format."""
    try:
        salt, expected_hash = hashed_value.split(":")
        test_hash = hashlib.sha256((salt + plain_password).encode('utf-8')).hexdigest()
        return hmac.compare_digest(test_hash, expected_hash)
    except Exception:
        return False


def generate_secure_token(prefix: str = "tok") -> str:
    """Generate a high-entropy cryptographically secure token."""
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def generate_deduplication_hash(*components: str) -> str:
    """Create a deterministic SHA-256 hash for deduplicating findings or alerts."""
    content = "|".join(str(c).strip().lower() for c in components)
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

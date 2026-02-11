"""Authentication: password hashing (Argon2) and TOTP."""

import hmac
import secrets

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
import pyotp


_ph = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
)


def hash_password(password: str) -> str:
    """Hash a password using Argon2id."""
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """Verify a password against an Argon2id hash."""
    try:
        return _ph.verify(password_hash, password)
    except VerifyMismatchError:
        return False


def generate_totp_secret() -> str:
    """Generate a new TOTP secret key."""
    return pyotp.random_base32()


def get_totp_provisioning_uri(secret: str, username: str = "owner") -> str:
    """Get the TOTP provisioning URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name="AgentShell")


def verify_totp(secret: str, code: str) -> bool:
    """Verify a TOTP code, allowing +-1 time window for clock drift."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


def generate_session_token() -> str:
    """Generate a cryptographically secure session token."""
    return secrets.token_urlsafe(48)


def constant_time_compare(a: str, b: str) -> bool:
    """Compare two strings in constant time to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())

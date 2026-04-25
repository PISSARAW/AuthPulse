"""AuthPulse — Time-based One-Time Password (TOTP) generator based on RFC 6238."""

from .totp import generate_totp
from .secret import generate_secret, validate_secret, decode_secret
from .verify import verify_totp

__all__ = [
    "generate_totp",
    "generate_secret",
    "validate_secret",
    "decode_secret",
    "verify_totp",
]

__version__ = "0.1.0"

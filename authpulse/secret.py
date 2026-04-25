"""Base32 secret key handling for TOTP.

Authenticator apps (Google Authenticator, Aegis, etc.) encode shared secrets
in base32 (RFC 4648) because it uses only uppercase letters A–Z and digits 2–7,
making it easy to type and avoiding visually ambiguous characters.
"""

import base64
import os
import re

# Valid base32 alphabet (RFC 4648)
_BASE32_RE = re.compile(r"^[A-Z2-7]+=*$")


def generate_secret(length: int = 20) -> str:
    """Generate a cryptographically secure random base32 secret.

    Args:
        length: Number of random bytes before encoding (default 20 → 160 bits,
                which is the standard key size for TOTP with HMAC-SHA1).

    Returns:
        Uppercase base32-encoded string **without** padding characters.

    Raises:
        ValueError: If *length* is less than 10.
    """
    if length < 10:
        raise ValueError("Secret length must be at least 10 bytes for security.")
    raw = os.urandom(length)
    return base64.b32encode(raw).decode("ascii").rstrip("=")


def validate_secret(secret: str) -> bool:
    """Return True if *secret* is a valid base32-encoded string.

    Accepts upper- and lowercase input and treats missing padding as valid.

    Args:
        secret: Candidate secret string.

    Returns:
        True if the string can be decoded as base32, False otherwise.
    """
    if not secret:
        return False
    normalised = secret.upper().strip()
    # Pad to a multiple of 8 for the regex check
    padded = normalised + "=" * ((8 - len(normalised) % 8) % 8)
    if not _BASE32_RE.match(padded):
        return False
    try:
        base64.b32decode(padded)
        return True
    except Exception:
        return False


def decode_secret(secret: str) -> bytes:
    """Decode a base32 secret to raw bytes.

    Handles mixed-case input and restores missing padding automatically.

    Args:
        secret: Base32-encoded secret key.

    Returns:
        Raw bytes of the secret.

    Raises:
        ValueError: If *secret* is not valid base32.
    """
    normalised = secret.upper().strip()
    # Restore padding
    padding = (8 - len(normalised) % 8) % 8
    padded = normalised + "=" * padding
    try:
        return base64.b32decode(padded)
    except Exception as exc:
        raise ValueError(f"Invalid base32 secret: {exc}") from exc

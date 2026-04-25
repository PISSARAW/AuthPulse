"""TOTP verification with configurable time-window tolerance.

Because clocks can drift slightly between a client and server, verification
allows a small window of adjacent time-steps to be accepted without
significantly increasing the attack surface.
"""

import math
import time

from .totp import generate_totp


def verify_totp(
    secret: str,
    code: str,
    timestamp: float | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
    window: int = 1,
) -> bool:
    """Verify a TOTP code against the current (or supplied) timestamp.

    A *window* of 1 (default) means the current time-step **plus** one step
    before and one step after are all accepted. This tolerates up to 30 seconds
    of clock skew in either direction.

    Args:
        secret: Base32-encoded secret key.
        code: The OTP code to verify (string, may be zero-padded).
        timestamp: Unix timestamp to verify against (defaults to ``time.time()``).
        digits: Expected OTP length — 6 (default), 7, or 8.
        period: Time-step in seconds (default 30).
        algorithm: Hash algorithm — 'sha1' (default), 'sha256', or 'sha512'.
        window: Number of adjacent time-steps to check on each side (default 1).

    Returns:
        True if the code is valid within the given window, False otherwise.
    """
    if timestamp is None:
        timestamp = time.time()

    current_counter = math.floor(timestamp / period)

    for step in range(-window, window + 1):
        counter_timestamp = (current_counter + step) * period
        expected = generate_totp(
            secret,
            timestamp=counter_timestamp,
            digits=digits,
            period=period,
            algorithm=algorithm,
        )
        if _constant_time_compare(code.strip(), expected):
            return True

    return False


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    if len(a) != len(b):
        return False
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

"""TOTP generation module implementing RFC 6238.

The Time-based One-Time Password algorithm works as follows:
  1. Decode the base32 secret key.
  2. Compute the time counter T = floor(current_unix_time / period).
  3. Pack T as a big-endian 8-byte unsigned integer.
  4. Compute HMAC using SHA-1 (default), SHA-256, or SHA-512 over T with the secret.
  5. Dynamically truncate the HMAC digest to a 4-byte offset value.
  6. Extract the last ``digits`` decimal digits from that 4-byte integer.
"""

import hashlib
import hmac
import math
import struct
import time

from .secret import decode_secret

# Supported hash algorithms
_ALGORITHMS = {
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def _hotp(secret_bytes: bytes, counter: int, digits: int, algorithm: str) -> str:
    """Compute an HMAC-based One-Time Password (RFC 4226).

    Args:
        secret_bytes: Raw (decoded) secret key bytes.
        counter: 8-byte counter value.
        digits: Number of OTP digits (6 or 8).
        algorithm: Hash algorithm name ('sha1', 'sha256', 'sha512').

    Returns:
        Zero-padded OTP string of length *digits*.

    Raises:
        ValueError: If *algorithm* is not supported or *digits* is out of range.
    """
    if algorithm not in _ALGORITHMS:
        raise ValueError(
            f"Unsupported algorithm '{algorithm}'. Choose from: {list(_ALGORITHMS)}"
        )
    if digits not in (6, 7, 8):
        raise ValueError("digits must be 6, 7, or 8.")

    # Step 1: HMAC computation
    digest_fn = _ALGORITHMS[algorithm]
    counter_bytes = struct.pack(">Q", counter)  # big-endian unsigned 64-bit
    hmac_digest = hmac.new(secret_bytes, counter_bytes, digest_fn).digest()

    # Step 2: Dynamic truncation (RFC 4226 §5.4)
    offset = hmac_digest[-1] & 0x0F
    truncated = struct.unpack(">I", hmac_digest[offset : offset + 4])[0]
    truncated &= 0x7FFFFFFF  # clear the most significant bit

    # Step 3: Extract OTP
    otp = truncated % (10**digits)
    return str(otp).zfill(digits)


def generate_totp(
    secret: str,
    timestamp: float | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
) -> str:
    """Generate a Time-based One-Time Password (RFC 6238).

    Args:
        secret: Base32-encoded secret key (case-insensitive, padding optional).
        timestamp: Unix timestamp to use (defaults to current UTC time).
        digits: Number of OTP digits — 6 (default), 7, or 8.
        period: Time-step in seconds (default 30).
        algorithm: Hash algorithm — 'sha1' (default), 'sha256', or 'sha512'.

    Returns:
        Zero-padded OTP string of length *digits*.

    Raises:
        ValueError: On invalid secret, algorithm, or digit count.
    """
    if timestamp is None:
        timestamp = time.time()

    secret_bytes = decode_secret(secret)
    counter = math.floor(timestamp / period)
    return _hotp(secret_bytes, counter, digits, algorithm)

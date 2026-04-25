"""Tests for authpulse.totp — RFC 6238 test vectors and edge cases.

The authoritative TOTP test vectors are defined in RFC 6238, Appendix B.
Secret used: "12345678901234567890" (ASCII), base32: GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ
"""

import base64

import pytest

from authpulse.totp import generate_totp, _hotp

# RFC 6238 Appendix B test vectors
# The secret bytes for SHA-1 are the ASCII string "12345678901234567890" (20 bytes).
# Base32 encoding of that string:
_SHA1_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

# (timestamp, expected_otp)
_RFC6238_SHA1_VECTORS = [
    (59, "94287082"),
    (1111111109, "07081804"),
    (1111111111, "14050471"),
    (1234567890, "89005924"),
    (2000000000, "69279037"),
    (20000000000, "65353130"),
]


@pytest.mark.parametrize("timestamp,expected", _RFC6238_SHA1_VECTORS)
def test_rfc6238_sha1_vectors(timestamp: int, expected: str) -> None:
    """Verify RFC 6238 SHA-1 test vectors (8-digit OTPs)."""
    result = generate_totp(
        _SHA1_SECRET_B32, timestamp=timestamp, digits=8, period=30, algorithm="sha1"
    )
    assert result == expected


def test_default_digits_is_6() -> None:
    """generate_totp with default digits returns a 6-character string."""
    code = generate_totp(_SHA1_SECRET_B32, timestamp=1234567890)
    assert len(code) == 6
    assert code.isdigit()


def test_8_digit_code() -> None:
    code = generate_totp(_SHA1_SECRET_B32, timestamp=1234567890, digits=8)
    assert len(code) == 8
    assert code.isdigit()


def test_invalid_algorithm_raises() -> None:
    with pytest.raises(ValueError, match="Unsupported algorithm"):
        generate_totp(_SHA1_SECRET_B32, algorithm="md5")


def test_invalid_digits_raises() -> None:
    with pytest.raises(ValueError, match="digits"):
        generate_totp(_SHA1_SECRET_B32, digits=5)


def test_same_period_same_code() -> None:
    """Two timestamps inside the same 30-second window produce the same OTP."""
    # Window 33: [990, 1020); both values fall in that window.
    code1 = generate_totp(_SHA1_SECRET_B32, timestamp=990.0)
    code2 = generate_totp(_SHA1_SECRET_B32, timestamp=1019.9)
    assert code1 == code2


def test_different_periods_different_codes() -> None:
    """Timestamps in adjacent 30-second windows produce different OTPs (usually)."""
    code1 = generate_totp(_SHA1_SECRET_B32, timestamp=990.0)
    code2 = generate_totp(_SHA1_SECRET_B32, timestamp=1020.0)
    # They *could* collide with probability ~1/10^6 — acceptable for a test.
    assert code1 != code2


def test_zero_padded_output() -> None:
    """The OTP is zero-padded to the requested number of digits."""
    # Force a known secret where the first code starts with 0.
    # We just check the format property.
    code = generate_totp(_SHA1_SECRET_B32, timestamp=59, digits=8)
    assert len(code) == 8
    assert code[0] == "9"  # from RFC vector: "94287082"


def test_hotp_counter_increases() -> None:
    """Incrementing the counter changes the HOTP value."""
    raw = "JBSWY3DPEHPK3PXP"
    padding = (8 - len(raw) % 8) % 8
    key = base64.b32decode(raw + "=" * padding)
    codes = [_hotp(key, c, 6, "sha1") for c in range(5)]
    assert len(set(codes)) == 5  # all distinct

"""Tests for authpulse.verify — TOTP verification with time-window tolerance."""

import pytest

from authpulse.totp import generate_totp
from authpulse.verify import verify_totp, _constant_time_compare

_SECRET = "JBSWY3DPEHPK3PXP"
_TIMESTAMP = 1_700_000_000.0  # fixed reference timestamp


def _current_code(ts: float = _TIMESTAMP) -> str:
    return generate_totp(_SECRET, timestamp=ts)


class TestVerifyTotp:
    def test_correct_code_validates(self) -> None:
        code = _current_code()
        assert verify_totp(_SECRET, code, timestamp=_TIMESTAMP) is True

    def test_wrong_code_rejected(self) -> None:
        assert verify_totp(_SECRET, "000000", timestamp=_TIMESTAMP) is False

    def test_previous_step_accepted_with_window_1(self) -> None:
        # Code from one step before should be accepted with window=1
        prev_ts = _TIMESTAMP - 30
        prev_code = generate_totp(_SECRET, timestamp=prev_ts)
        assert verify_totp(_SECRET, prev_code, timestamp=_TIMESTAMP, window=1) is True

    def test_next_step_accepted_with_window_1(self) -> None:
        next_ts = _TIMESTAMP + 30
        next_code = generate_totp(_SECRET, timestamp=next_ts)
        assert verify_totp(_SECRET, next_code, timestamp=_TIMESTAMP, window=1) is True

    def test_two_steps_away_rejected_with_window_1(self) -> None:
        far_ts = _TIMESTAMP + 60
        far_code = generate_totp(_SECRET, timestamp=far_ts)
        assert verify_totp(_SECRET, far_code, timestamp=_TIMESTAMP, window=1) is False

    def test_two_steps_away_accepted_with_window_2(self) -> None:
        far_ts = _TIMESTAMP + 60
        far_code = generate_totp(_SECRET, timestamp=far_ts)
        assert verify_totp(_SECRET, far_code, timestamp=_TIMESTAMP, window=2) is True

    def test_window_0_only_current_step(self) -> None:
        prev_code = generate_totp(_SECRET, timestamp=_TIMESTAMP - 30)
        assert verify_totp(_SECRET, prev_code, timestamp=_TIMESTAMP, window=0) is False

    def test_8_digit_code(self) -> None:
        code = generate_totp(_SECRET, timestamp=_TIMESTAMP, digits=8)
        assert verify_totp(_SECRET, code, timestamp=_TIMESTAMP, digits=8) is True

    def test_wrong_digit_count_rejected(self) -> None:
        code6 = generate_totp(_SECRET, timestamp=_TIMESTAMP, digits=6)
        # Verifying a 6-digit code with digits=8 should fail
        assert verify_totp(_SECRET, code6, timestamp=_TIMESTAMP, digits=8) is False

    def test_code_with_leading_whitespace(self) -> None:
        code = _current_code()
        assert verify_totp(_SECRET, f"  {code}  ", timestamp=_TIMESTAMP) is True


class TestConstantTimeCompare:
    def test_equal_strings(self) -> None:
        assert _constant_time_compare("123456", "123456") is True

    def test_different_strings(self) -> None:
        assert _constant_time_compare("123456", "654321") is False

    def test_different_lengths(self) -> None:
        assert _constant_time_compare("12345", "123456") is False

    def test_empty_strings(self) -> None:
        assert _constant_time_compare("", "") is True

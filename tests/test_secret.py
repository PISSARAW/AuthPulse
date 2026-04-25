"""Tests for authpulse.secret — base32 secret handling."""

import base64

import pytest

from authpulse.secret import generate_secret, validate_secret, decode_secret


class TestGenerateSecret:
    def test_returns_string(self) -> None:
        assert isinstance(generate_secret(), str)

    def test_default_length_is_valid_base32(self) -> None:
        secret = generate_secret()
        assert validate_secret(secret)

    def test_custom_length(self) -> None:
        secret = generate_secret(length=32)
        assert validate_secret(secret)

    def test_minimum_length(self) -> None:
        secret = generate_secret(length=10)
        assert validate_secret(secret)

    def test_too_short_raises(self) -> None:
        with pytest.raises(ValueError, match="at least 10 bytes"):
            generate_secret(length=5)

    def test_two_secrets_are_different(self) -> None:
        s1 = generate_secret()
        s2 = generate_secret()
        assert s1 != s2

    def test_no_padding_characters(self) -> None:
        secret = generate_secret()
        assert "=" not in secret

    def test_uppercase_only(self) -> None:
        secret = generate_secret()
        assert secret == secret.upper()


class TestValidateSecret:
    def test_valid_known_secret(self) -> None:
        assert validate_secret("JBSWY3DPEHPK3PXP") is True

    def test_lowercase_accepted(self) -> None:
        assert validate_secret("jbswy3dpehpk3pxp") is True

    def test_empty_string_invalid(self) -> None:
        assert validate_secret("") is False

    def test_invalid_chars_invalid(self) -> None:
        assert validate_secret("!!!!!!") is False

    def test_with_padding(self) -> None:
        # base32 with explicit padding should also be valid
        padded = base64.b32encode(b"hello world").decode()
        assert validate_secret(padded) is True

    def test_numeric_only_invalid(self) -> None:
        # "1" and "9" are not in the base32 alphabet
        assert validate_secret("19191919") is False


class TestDecodeSecret:
    def test_round_trip(self) -> None:
        raw = b"hello world"
        encoded = base64.b32encode(raw).decode().rstrip("=")
        assert decode_secret(encoded) == raw

    def test_case_insensitive(self) -> None:
        raw = b"test"
        encoded = base64.b32encode(raw).decode()
        assert decode_secret(encoded.lower()) == raw

    def test_invalid_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="Invalid base32"):
            decode_secret("!!!INVALID!!!")

    def test_known_secret_decodes_correctly(self) -> None:
        # "JBSWY3DPEHPK3PXP" decodes to b"Hello!\xde\xad\xbe\xef"
        result = decode_secret("JBSWY3DPEHPK3PXP")
        assert isinstance(result, bytes)
        assert len(result) == 10

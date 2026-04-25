"""Tests for authpulse.qr — OTP URI building and QR code generation."""

import pytest

from authpulse.qr import build_otpauth_uri


class TestBuildOtpauthUri:
    def test_basic_uri_structure(self) -> None:
        uri = build_otpauth_uri(
            secret="JBSWY3DPEHPK3PXP",
            account_name="user@example.com",
            issuer="MyApp",
        )
        assert uri.startswith("otpauth://totp/")
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "issuer=MyApp" in uri

    def test_label_contains_issuer_and_account(self) -> None:
        uri = build_otpauth_uri(
            secret="JBSWY3DPEHPK3PXP",
            account_name="alice",
            issuer="Acme",
        )
        # Label is URL-encoded "Acme:alice"
        assert "Acme%3Aalice" in uri

    def test_no_issuer(self) -> None:
        uri = build_otpauth_uri(
            secret="JBSWY3DPEHPK3PXP",
            account_name="user@example.com",
        )
        assert "issuer=" not in uri
        assert "user%40example.com" in uri

    def test_custom_digits(self) -> None:
        uri = build_otpauth_uri(
            secret="JBSWY3DPEHPK3PXP",
            account_name="user",
            digits=8,
        )
        assert "digits=8" in uri

    def test_custom_period(self) -> None:
        uri = build_otpauth_uri(
            secret="JBSWY3DPEHPK3PXP",
            account_name="user",
            period=60,
        )
        assert "period=60" in uri

    def test_algorithm_is_uppercase(self) -> None:
        uri = build_otpauth_uri(
            secret="JBSWY3DPEHPK3PXP",
            account_name="user",
            algorithm="sha256",
        )
        assert "algorithm=SHA256" in uri

    def test_secret_is_uppercase_no_padding(self) -> None:
        uri = build_otpauth_uri(
            secret="jbswy3dpehpk3pxp",  # lowercase input
            account_name="user",
        )
        assert "secret=JBSWY3DPEHPK3PXP" in uri
        assert "=" not in uri.split("secret=")[1].split("&")[0]


class TestGenerateQrCode:
    def test_raises_import_error_without_qrcode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """If qrcode is not installed, a helpful ImportError should be raised."""
        import builtins
        real_import = builtins.__import__

        def mock_import(name: str, *args, **kwargs):
            if name == "qrcode":
                raise ImportError("No module named 'qrcode'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        from authpulse.qr import generate_qr_code
        with pytest.raises(ImportError, match="qrcode"):
            generate_qr_code("JBSWY3DPEHPK3PXP", "user@example.com")

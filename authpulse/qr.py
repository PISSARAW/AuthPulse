"""QR code generation for TOTP provisioning URIs.

Authenticator apps scan a QR code that encodes a ``otpauth://`` URI defined by
the Key Uri Format specification:
  https://github.com/google/google-authenticator/wiki/Key-Uri-Format

Example URI::

    otpauth://totp/Example%3Auser%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example

The QR code can be exported as:
  * A PNG image file.
  * A terminal-friendly ASCII art string (no external dependencies required).
"""

from __future__ import annotations

import urllib.parse


def build_otpauth_uri(
    secret: str,
    account_name: str,
    issuer: str = "",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
) -> str:
    """Build an ``otpauth://totp/`` provisioning URI.

    Args:
        secret: Base32-encoded secret key (without padding).
        account_name: User's account identifier (e.g. ``user@example.com``).
        issuer: Service or application name shown in the authenticator.
        digits: OTP length (6 or 8).
        period: Time-step in seconds (default 30).
        algorithm: Hash algorithm — 'SHA1', 'SHA256', or 'SHA512'.

    Returns:
        Fully-formed ``otpauth://totp/`` URI string.
    """
    label = f"{issuer}:{account_name}" if issuer else account_name
    encoded_label = urllib.parse.quote(label, safe="")

    params: dict[str, str] = {
        "secret": secret.upper().rstrip("="),
        "algorithm": algorithm.upper(),
        "digits": str(digits),
        "period": str(period),
    }
    if issuer:
        params["issuer"] = issuer

    query = urllib.parse.urlencode(params)
    return f"otpauth://totp/{encoded_label}?{query}"


def generate_qr_code(
    secret: str,
    account_name: str,
    issuer: str = "",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
    output_path: str | None = None,
) -> str:
    """Generate a QR code for the given TOTP secret.

    Requires the ``qrcode`` package (``pip install qrcode[pil]``).
    If *output_path* is provided the QR code is saved as a PNG image there;
    otherwise it is printed as ASCII art to stdout.

    Args:
        secret: Base32-encoded secret key.
        account_name: User account identifier.
        issuer: Service name shown in the authenticator.
        digits: OTP digit count (6 or 8).
        period: Time-step seconds.
        algorithm: Hash algorithm name.
        output_path: Optional filesystem path to save a PNG file.

    Returns:
        The ``otpauth://`` URI that was encoded into the QR code.

    Raises:
        ImportError: If the ``qrcode`` package is not installed.
    """
    try:
        import qrcode  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "The 'qrcode' package is required for QR code generation. "
            "Install it with: pip install qrcode[pil]"
        ) from exc

    uri = build_otpauth_uri(
        secret=secret,
        account_name=account_name,
        issuer=issuer,
        digits=digits,
        period=period,
        algorithm=algorithm,
    )

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(uri)
    qr.make(fit=True)

    if output_path:
        img = qr.make_image(fill_color="black", back_color="white")
        img.save(output_path)
    else:
        qr.print_ascii(invert=True)

    return uri

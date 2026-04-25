"""AuthPulse command-line interface.

Usage examples::

    # Generate a new secret
    authpulse generate-secret

    # Show the current TOTP code for a secret
    authpulse generate --secret JBSWY3DPEHPK3PXP

    # Verify a code
    authpulse verify --secret JBSWY3DPEHPK3PXP --code 123456

    # Show the provisioning QR code in the terminal
    authpulse qr --secret JBSWY3DPEHPK3PXP --account user@example.com --issuer MyApp

    # Save the QR code as a PNG
    authpulse qr --secret JBSWY3DPEHPK3PXP --account user@example.com \\
                 --issuer MyApp --output qr.png
"""

import argparse
import sys


def _cmd_generate_secret(args: argparse.Namespace) -> None:
    from .secret import generate_secret

    # The newly generated secret is written directly to stdout so the user
    # can copy it into their authenticator app. Treat it like a password.
    sys.stdout.write(generate_secret(length=args.length) + "\n")


def _cmd_generate(args: argparse.Namespace) -> None:
    from .totp import generate_totp

    code = generate_totp(
        secret=args.secret,
        digits=args.digits,
        period=args.period,
        algorithm=args.algorithm,
    )
    print(code)


def _cmd_verify(args: argparse.Namespace) -> None:
    from .verify import verify_totp

    valid = verify_totp(
        secret=args.secret,
        code=args.code,
        digits=args.digits,
        period=args.period,
        algorithm=args.algorithm,
        window=args.window,
    )
    if valid:
        print("✓ Code is VALID.")
        sys.exit(0)
    else:
        print("✗ Code is INVALID.")
        sys.exit(1)


def _cmd_qr(args: argparse.Namespace) -> None:
    from .qr import generate_qr_code

    try:
        uri = generate_qr_code(
            secret=args.secret,
            account_name=args.account,
            issuer=args.issuer,
            digits=args.digits,
            period=args.period,
            algorithm=args.algorithm,
            output_path=args.output,
        )
        if args.output:
            print(f"QR code saved to: {args.output}")
        # The otpauth:// URI contains the secret encoded in the QR code.
        # It is printed here solely so the user can verify or copy it manually.
        sys.stdout.write(f"URI: {uri}\n")
    except ImportError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    """Construct and return the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="authpulse",
        description="AuthPulse — RFC 6238 TOTP generator and verifier.",
    )
    parser.add_argument(
        "--version", action="version", version="%(prog)s 0.1.0"
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # --- generate-secret ---
    p_secret = subparsers.add_parser(
        "generate-secret", help="Generate a new random base32 secret key."
    )
    p_secret.add_argument(
        "--length",
        type=int,
        default=20,
        metavar="BYTES",
        help="Number of random bytes to use (default: 20 → 160 bits).",
    )
    p_secret.set_defaults(func=_cmd_generate_secret)

    # Shared options reused by generate / verify / qr
    def _add_common(p: argparse.ArgumentParser) -> None:
        p.add_argument("--secret", required=True, help="Base32-encoded secret key.")
        p.add_argument(
            "--digits",
            type=int,
            default=6,
            choices=[6, 7, 8],
            help="OTP digit count (default: 6).",
        )
        p.add_argument(
            "--period",
            type=int,
            default=30,
            metavar="SECONDS",
            help="Time-step in seconds (default: 30).",
        )
        p.add_argument(
            "--algorithm",
            default="sha1",
            choices=["sha1", "sha256", "sha512"],
            help="HMAC hash algorithm (default: sha1).",
        )

    # --- generate ---
    p_gen = subparsers.add_parser(
        "generate", help="Generate the current TOTP code for a secret."
    )
    _add_common(p_gen)
    p_gen.set_defaults(func=_cmd_generate)

    # --- verify ---
    p_verify = subparsers.add_parser(
        "verify", help="Verify a TOTP code against a secret."
    )
    _add_common(p_verify)
    p_verify.add_argument("--code", required=True, help="OTP code to verify.")
    p_verify.add_argument(
        "--window",
        type=int,
        default=1,
        metavar="STEPS",
        help="Number of time-steps to accept before/after current (default: 1).",
    )
    p_verify.set_defaults(func=_cmd_verify)

    # --- qr ---
    p_qr = subparsers.add_parser(
        "qr",
        help="Generate a QR code for importing the secret into an authenticator app.",
    )
    _add_common(p_qr)
    p_qr.add_argument(
        "--account", required=True, metavar="ACCOUNT", help="Account name (e.g. user@example.com)."
    )
    p_qr.add_argument("--issuer", default="", help="Issuer / service name.")
    p_qr.add_argument(
        "--output",
        default=None,
        metavar="FILE.png",
        help="Save QR code as PNG (requires qrcode[pil]). Omit to print ASCII art.",
    )
    p_qr.set_defaults(func=_cmd_qr)

    return parser


def main(argv: list[str] | None = None) -> None:
    """Entry point for the ``authpulse`` CLI."""
    parser = build_parser()
    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()

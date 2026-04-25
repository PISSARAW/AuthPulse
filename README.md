# AuthPulse

**AuthPulse** is a pure-Python implementation of the **Time-based One-Time Password (TOTP)** algorithm defined in [RFC 6238](https://datatracker.ietf.org/doc/html/rfc6238). It is compatible with popular authenticator apps such as Google Authenticator, Aegis, and Authy.

---

## Table of Contents

1. [How TOTP Works](#how-totp-works)
2. [Project Structure](#project-structure)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [CLI Reference](#cli-reference)
6. [Python API](#python-api)
7. [Security Considerations](#security-considerations)
8. [Running Tests](#running-tests)

---

## How TOTP Works

TOTP is a two-factor authentication mechanism that generates short, time-limited codes shared between a **client** (e.g. an authenticator app) and a **server** (your application). No network communication is needed once the secret is provisioned.

### The Algorithm (RFC 6238 § 4)

```
T  = floor(unix_timestamp / time_step)    # default step = 30 s
OTP = HOTP(secret, T)
```

Where **HOTP** (RFC 4226) is:

```
1. HMAC = HMAC-SHA1(secret_key, T_bytes)      # T as 8-byte big-endian integer
2. offset = last_byte(HMAC) & 0x0F
3. P = HMAC[offset : offset+4] & 0x7FFFFFFF  # 31-bit integer
4. OTP = P mod 10^digits                      # default digits = 6
5. Zero-pad OTP to `digits` characters
```

### Why This Is Secure

| Property | Explanation |
|---|---|
| **Short-lived** | Each code is only valid for 30 seconds (configurable). |
| **Shared secret** | The secret never travels over the wire after initial provisioning. |
| **HMAC** | Even if you know consecutive OTP values you cannot derive the secret. |
| **No reuse** | The same code cannot be used twice within the same time window. |

---

## Project Structure

```
AuthPulse/
├── authpulse/
│   ├── __init__.py    # Package exports
│   ├── totp.py        # Core TOTP / HOTP generation (RFC 6238 / RFC 4226)
│   ├── secret.py      # Base32 secret generation & validation
│   ├── verify.py      # TOTP verification with time-window tolerance
│   ├── qr.py          # QR code generation (otpauth:// URI)
│   └── cli.py         # Command-line interface
├── tests/
│   ├── test_totp.py   # RFC 6238 test vectors + edge cases
│   ├── test_secret.py # Secret generation & validation tests
│   ├── test_verify.py # Verification & time-window tests
│   └── test_qr.py     # URI building & QR code tests
├── pyproject.toml
├── requirements.txt
└── README.md
```

---

## Installation

```bash
# Clone the repository
git clone https://github.com/PISSARAW/AuthPulse.git
cd AuthPulse

# Install in editable mode (no QR code support)
pip install -e .

# With QR code support
pip install -e ".[qr]"

# With development dependencies (tests, coverage)
pip install -e ".[dev]"
```

---

## Quick Start

### Generate a secret and a TOTP code

```python
from authpulse import generate_secret, generate_totp, verify_totp

# 1. Generate a new shared secret (store this securely on your server)
secret = generate_secret()
print(secret)   # e.g. "JBSWY3DPEHPK3PXP..."

# 2. Generate the current OTP (what the user's app would show)
code = generate_totp(secret)
print(code)     # e.g. "482 714"

# 3. Verify a code submitted by the user
is_valid = verify_totp(secret, code)
print(is_valid) # True
```

### Generate a QR code for authenticator apps

```python
from authpulse.qr import generate_qr_code

# Print ASCII QR code in terminal
uri = generate_qr_code(
    secret="JBSWY3DPEHPK3PXP",
    account_name="user@example.com",
    issuer="MyApp",
)

# Or save as PNG (requires qrcode[pil])
generate_qr_code(
    secret="JBSWY3DPEHPK3PXP",
    account_name="user@example.com",
    issuer="MyApp",
    output_path="totp_qr.png",
)
```

---

## CLI Reference

```
authpulse [--version] <command> [options]
```

### `generate-secret` — Create a new secret

```bash
authpulse generate-secret
# JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP

authpulse generate-secret --length 32   # 32 random bytes
```

### `generate` — Show the current TOTP code

```bash
authpulse generate --secret JBSWY3DPEHPK3PXP
# 482714

authpulse generate --secret JBSWY3DPEHPK3PXP --digits 8 --algorithm sha256
```

### `verify` — Check a code

```bash
authpulse verify --secret JBSWY3DPEHPK3PXP --code 482714
# ✓ Code is VALID.

authpulse verify --secret JBSWY3DPEHPK3PXP --code 000000 --window 2
# ✗ Code is INVALID.
```

Exit code is **0** on success and **1** on failure — suitable for scripting.

### `qr` — Generate a QR code

```bash
# ASCII art in terminal
authpulse qr --secret JBSWY3DPEHPK3PXP \
             --account user@example.com \
             --issuer MyApp

# Save as PNG
authpulse qr --secret JBSWY3DPEHPK3PXP \
             --account user@example.com \
             --issuer MyApp \
             --output totp_qr.png
```

---

## Python API

### `authpulse.totp.generate_totp`

```python
generate_totp(
    secret: str,
    timestamp: float | None = None,   # defaults to time.time()
    digits: int = 6,                  # 6, 7, or 8
    period: int = 30,                 # time-step in seconds
    algorithm: str = "sha1",          # "sha1" | "sha256" | "sha512"
) -> str
```

### `authpulse.secret.generate_secret`

```python
generate_secret(length: int = 20) -> str   # 20 bytes → 160-bit key
```

### `authpulse.verify.verify_totp`

```python
verify_totp(
    secret: str,
    code: str,
    timestamp: float | None = None,
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
    window: int = 1,   # accept ±window time-steps to handle clock skew
) -> bool
```

### `authpulse.qr.generate_qr_code`

```python
generate_qr_code(
    secret: str,
    account_name: str,
    issuer: str = "",
    digits: int = 6,
    period: int = 30,
    algorithm: str = "sha1",
    output_path: str | None = None,  # None → print ASCII to stdout
) -> str  # returns the otpauth:// URI
```

---

## Security Considerations

### Secret storage
- Store secrets **encrypted at rest** (e.g. using a KMS or encrypted database column).
- Treat secrets with the same care as passwords — never log them.
- Use at least **160 bits** of entropy (the default `generate_secret()` provides this).

### Transport security
- Always transmit the QR code / provisioning URI **over HTTPS** during enrollment.
- The `otpauth://` URI contains the plaintext secret — treat it like a password.

### Clock synchronisation
- The server clock must be reasonably accurate (NTP is recommended).
- AuthPulse accepts codes from adjacent time windows (`window=1` by default) to tolerate up to **±30 seconds** of clock skew without significantly increasing the attack surface.

### Brute-force protection
- A 6-digit code has only 1,000,000 possible values. **Always rate-limit** OTP verification endpoints (e.g. lock after 5 failed attempts).

### Code reuse
- To prevent replay attacks, track and **reject already-used OTP codes** within the current (and adjacent accepted) time window. AuthPulse's `verify_totp` does not implement this — you must do it in your application layer.

### Algorithm choice
- SHA-1 is the default for maximum compatibility with authenticator apps.
- For new, internal deployments consider **SHA-256** or **SHA-512**, but verify your authenticator app supports them.

---

## Running Tests

```bash
# Install dev dependencies
pip install -e ".[dev]"

# Run all tests
pytest

# With coverage report
pytest --cov=authpulse --cov-report=term-missing
```

---

## License

MIT — see [LICENSE](LICENSE) for details.

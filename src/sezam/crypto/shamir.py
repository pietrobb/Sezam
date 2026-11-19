"""Shamir's Secret Sharing over GF(256) (spec 9.4).

Used for organizational recovery: the root KEK is wrapped with a recovery
key. The recovery key is split via Shamir into N shares requiring a threshold
of K shares to reconstruct.

Implementation uses GF(2^8) arithmetic with the AES irreducible polynomial
x^8 + x^4 + x^3 + x + 1 (0x11B) for field operations. Each byte of the
secret is independently split using a random polynomial of degree
(threshold - 1).

Security properties:
- Any (threshold - 1) shares reveal ZERO information about the secret.
- Shares are cryptographically independent (random coefficients from os.urandom).
- Share indices are 1-based (index 0 would leak the secret as f(0) = secret).
"""

from __future__ import annotations

import os
from typing import List, Tuple


# ── GF(256) arithmetic with AES irreducible polynomial ──

# Precomputed exp and log tables for GF(2^8) with generator 0x03
# Irreducible polynomial: x^8 + x^4 + x^3 + x + 1 = 0x11B
_EXP_TABLE = [0] * 512  # exp[i] = g^i mod p
_LOG_TABLE = [0] * 256   # log[exp[i]] = i

def _init_tables() -> None:
    """Initialize GF(256) exp/log lookup tables."""
    x = 1
    for i in range(255):
        _EXP_TABLE[i] = x
        _LOG_TABLE[x] = i
        # Multiply by generator (0x03 = x + 1 in GF(2^8))
        x = x ^ (x << 1)  # x * 0x03 = x * (x + 1) = x^2 + x = (x << 1) ^ x
        if x & 0x100:
            x ^= 0x11B  # Reduce modulo irreducible polynomial
    # Fill the second half for easy modular reduction
    for i in range(255, 512):
        _EXP_TABLE[i] = _EXP_TABLE[i - 255]

_init_tables()


def _gf_mul(a: int, b: int) -> int:
    """Multiply two elements in GF(256)."""
    if a == 0 or b == 0:
        return 0
    return _EXP_TABLE[_LOG_TABLE[a] + _LOG_TABLE[b]]


def _gf_inv(a: int) -> int:
    """Multiplicative inverse in GF(256). Raises for a=0."""
    if a == 0:
        raise ZeroDivisionError("No inverse for 0 in GF(256)")
    return _EXP_TABLE[255 - _LOG_TABLE[a]]


def _gf_div(a: int, b: int) -> int:
    """Divide a by b in GF(256)."""
    if b == 0:
        raise ZeroDivisionError("Division by zero in GF(256)")
    if a == 0:
        return 0
    return _EXP_TABLE[(_LOG_TABLE[a] - _LOG_TABLE[b]) % 255]


# ── Polynomial evaluation and interpolation ──

def _eval_poly(coeffs: list[int], x: int) -> int:
    """Evaluate polynomial at point x in GF(256).

    coeffs[0] is the constant term (the secret byte).
    f(x) = coeffs[0] + coeffs[1]*x + coeffs[2]*x^2 + ...

    Uses Horner's method for efficiency.
    """
    # Horner's method: ((c_n * x + c_{n-1}) * x + ...) * x + c_0
    result = 0
    for i in range(len(coeffs) - 1, -1, -1):
        result = _gf_mul(result, x) ^ coeffs[i]
    return result


def _lagrange_interpolate(points: list[tuple[int, int]], x: int = 0) -> int:
    """Lagrange interpolation at point x in GF(256).

    points: list of (x_i, y_i) pairs.
    Returns f(x) where f is the unique polynomial of degree < len(points)
    passing through all points.

    Default x=0 recovers the secret (constant term).
    """
    k = len(points)
    result = 0

    for i in range(k):
        xi, yi = points[i]
        if yi == 0:
            continue

        # Compute Lagrange basis polynomial L_i(x) = prod_{j!=i} (x - x_j) / (x_i - x_j)
        numerator = 1
        denominator = 1
        for j in range(k):
            if i == j:
                continue
            xj = points[j][0]
            numerator = _gf_mul(numerator, x ^ xj)       # (x - x_j) in GF(2^8): subtraction = XOR
            denominator = _gf_mul(denominator, xi ^ xj)   # (x_i - x_j)

        # L_i(x) = numerator / denominator
        basis = _gf_div(numerator, denominator)
        result ^= _gf_mul(yi, basis)  # Addition in GF(2^8) = XOR

    return result


# ── Public API ──

def split_secret(
    secret: bytes,
    threshold: int,
    shares: int,
) -> List[Tuple[int, bytes]]:
    """Split a secret into shares using Shamir's Secret Sharing over GF(256).

    Args:
        secret: The secret bytes to split (any length).
        threshold: Minimum number of shares required to reconstruct (k).
        shares: Total number of shares to generate (n).

    Returns:
        List of (index, share_bytes) tuples where index is 1-based.
        Each share_bytes has the same length as the secret.

    Raises:
        ValueError: If parameters are invalid.

    Security: Each byte of the secret is independently split using a random
    polynomial of degree (threshold - 1). The random coefficients are
    generated using os.urandom (CSPRNG).
    """
    if threshold < 2:
        raise ValueError("Threshold must be at least 2")
    if shares < threshold:
        raise ValueError("Number of shares must be >= threshold")
    if shares > 255:
        raise ValueError("Maximum 255 shares (GF(256) constraint: indices 1-255)")
    if not secret:
        raise ValueError("Secret must not be empty")

    secret_len = len(secret)
    result: List[Tuple[int, bytes]] = []

    # For each share index (1-based), compute the share byte-by-byte
    # We process per-byte to avoid keeping all polynomials in memory
    share_arrays = [bytearray(secret_len) for _ in range(shares)]

    for byte_idx in range(secret_len):
        # Build random polynomial: coeffs[0] = secret_byte, coeffs[1..k-1] = random
        coeffs = [secret[byte_idx]] + list(os.urandom(threshold - 1))

        # Evaluate polynomial at each share index
        for share_idx in range(shares):
            x = share_idx + 1  # 1-based index
            share_arrays[share_idx][byte_idx] = _eval_poly(coeffs, x)

    for share_idx in range(shares):
        result.append((share_idx + 1, bytes(share_arrays[share_idx])))

    return result


def reconstruct_secret(
    shares: List[Tuple[int, bytes]],
) -> bytes:
    """Reconstruct a secret from Shamir shares using Lagrange interpolation.

    Args:
        shares: List of (index, share_bytes) tuples. Must contain at least
                `threshold` shares (the threshold used during splitting).

    Returns:
        The reconstructed secret bytes.

    Raises:
        ValueError: If shares are invalid or inconsistent.
    """
    if not shares:
        raise ValueError("No shares provided")
    if len(shares) < 2:
        raise ValueError("At least 2 shares required for reconstruction")

    # Validate consistent share lengths
    share_len = len(shares[0][1])
    for idx, share_bytes in shares:
        if len(share_bytes) != share_len:
            raise ValueError(
                f"Share {idx} has length {len(share_bytes)}, "
                f"expected {share_len}"
            )
        if idx < 1 or idx > 255:
            raise ValueError(f"Share index must be 1-255, got {idx}")

    # Check for duplicate indices
    indices = [s[0] for s in shares]
    if len(set(indices)) != len(indices):
        raise ValueError("Duplicate share indices detected")

    # Reconstruct byte-by-byte using Lagrange interpolation at x=0
    result = bytearray(share_len)
    for byte_idx in range(share_len):
        points = [(s[0], s[1][byte_idx]) for s in shares]
        result[byte_idx] = _lagrange_interpolate(points, x=0)

    return bytes(result)

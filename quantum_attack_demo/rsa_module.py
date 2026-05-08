"""
Small-key RSA for classroom demos only (NOT secure).

Supported modulus sizes in this project: n ∈ {15, 21, 35}
Corresponds to prime pairs (3,5), (3,7), (5,7).
"""

from __future__ import annotations

import math
import random
from typing import Tuple


PublicKey = Tuple[int, int]  # (e, n)
PrivateKey = Tuple[int, int]  # (d, n)


def _extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean algorithm: returns (gcd, x, y) with ax + by = gcd."""
    if a == 0:
        return (b, 0, 1)
    g, x1, y1 = _extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return (g, x, y)


def mod_inverse(a: int, m: int) -> int:
    """Return x such that (a * x) % m == 1."""
    g, x, _ = _extended_gcd(a % m, m)
    if g != 1:
        raise ValueError("No modular inverse")
    return x % m


def choose_demo_primes() -> Tuple[int, int]:
    """Pick one of the assignment-friendly semiprime constructions."""
    pairs = [(3, 5), (3, 7), (5, 7)]  # n = 15, 21, 35
    return random.choice(pairs)


def generate_rsa_keys(p: int | None = None, q: int | None = None) -> Tuple[PublicKey, PrivateKey]:
    """
    Generate RSA keys with tiny primes suitable for Shor demos.

    Default e = 3 when gcd(3, phi)==1; otherwise e = 5.
    """
    if p is None or q is None:
        p, q = choose_demo_primes()
    if p == q:
        raise ValueError("p and q must be distinct primes")

    n = p * q
    phi = (p - 1) * (q - 1)

    # Pick small odd public exponent typical for demos
    for e in (3, 5, 17):
        if math.gcd(e, phi) == 1:
            break
    else:
        raise ValueError("Could not find suitable e")

    d = mod_inverse(e, phi)
    return (e, n), (d, n)


def encrypt(message: str, public_key: PublicKey) -> list[int]:
    e, n = public_key
    out: list[int] = []
    for ch in message:
        m = ord(ch) % n
        if m == 0:
            raise ValueError("Character not representable in this tiny RSA demo")
        out.append(pow(m, e, n))
    return out


def decrypt(ciphertext: list[int], private_key: PrivateKey) -> str:
    d, n = private_key
    chars: list[str] = []
    for c in ciphertext:
        m = pow(c, d, n)
        if m > 0x10FFFF:
            raise ValueError("Decryption produced invalid code point")
        chars.append(chr(m))
    return "".join(chars)

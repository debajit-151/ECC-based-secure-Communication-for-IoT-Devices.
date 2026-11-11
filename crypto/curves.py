"""
Elliptic Curve Parameters and Mathematical Models.
Provides standard parameters for NIST P-256 (secp256r1) and mathematical utilities.
"""

from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import ec

@dataclass(frozen=True)
class CurveParameters:
    """NIST P-256 (secp256r1) Weierstrass Curve Parameters: y^2 = x^3 + ax + b (mod p)"""
    name: str = "secp256r1"
    # Prime modulus p (2^256 - 2^224 + 2^192 + 2^96 - 1)
    p: int = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
    # Curve coefficient a = -3 mod p
    a: int = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
    # Curve coefficient b
    b: int = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
    # Base generator point G = (Gx, Gy)
    Gx: int = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
    Gy: int = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
    # Order of G (number of points in the subgroup)
    n: int = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    # Cofactor h
    h: int = 1

NIST_P256 = CurveParameters()

def get_cryptography_curve():
    """Returns the cryptography library EllipticCurve object."""
    return ec.SECP256R1()

def is_point_on_curve(x: int, y: int, params: CurveParameters = NIST_P256) -> bool:
    """Verifies that point (x, y) satisfies the Weierstrass equation: y^2 = x^3 + ax + b (mod p)."""
    lhs = (y * y) % params.p
    rhs = (pow(x, 3, params.p) + params.a * x + params.b) % params.p
    return lhs == rhs

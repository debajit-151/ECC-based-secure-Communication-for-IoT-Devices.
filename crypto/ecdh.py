"""
Elliptic Curve Diffie-Hellman (ECDH) Key Exchange.
Enables two parties (e.g. IoT Sensor and Gateway) to establish a shared secret over an insecure channel.
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from .curves import get_cryptography_curve

class ECDHManager:
    """Manages Ephemeral Elliptic Curve Diffie-Hellman (ECDHE) key exchange."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey = None):
        if private_key is None:
            self.private_key = ec.generate_private_key(get_cryptography_curve())
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()

    @classmethod
    def generate(cls) -> "ECDHManager":
        """Factory method to generate a fresh ephemeral ECDH keypair."""
        return cls()

    def get_public_bytes(self) -> bytes:
        """Serializes the public key to DER SubjectPublicKeyInfo format."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_pem(self) -> str:
        """Serializes public key into PEM format for logging and inspection."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def get_public_coordinates(self) -> Tuple[int, int]:
        """Returns the affine (x, y) coordinates on the elliptic curve."""
        numbers = self.public_key.public_numbers()
        return numbers.x, numbers.y

    def compute_shared_secret(self, peer_public_bytes: bytes) -> bytes:
        """
        Computes the shared secret point scalar Z = d_A * Q_B.
        Returns the x-coordinate of the resulting elliptic curve point.
        """
        peer_public_key = serialization.load_der_public_key(peer_public_bytes)
        if not isinstance(peer_public_key, ec.EllipticCurvePublicKey):
            raise ValueError("Peer public key must be an Elliptic Curve public key.")
        
        shared_secret = self.private_key.exchange(ec.ECDH(), peer_public_key)
        return shared_secret


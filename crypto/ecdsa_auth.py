"""
Elliptic Curve Digital Signature Algorithm (ECDSA) and Certificate Management.
Provides authentication, message integrity, and non-repudiation for IoT devices.
"""

import json
import time
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from .curves import get_cryptography_curve

class ECDSASigner:
    """Handles ECDSA key generation, digital signing, and signature verification."""

    def __init__(self, private_key: ec.EllipticCurvePrivateKey = None):
        if private_key is None:
            self.private_key = ec.generate_private_key(get_cryptography_curve())
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()

    @classmethod
    def generate(cls) -> "ECDSASigner":
        """Generates a fresh long-term ECDSA identity keypair."""
        return cls()

    def get_public_bytes(self) -> bytes:
        """Returns DER-encoded SubjectPublicKeyInfo."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def get_public_pem(self) -> str:
        """Returns PEM-formatted public key string."""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode("utf-8")

    def sign(self, message: bytes) -> bytes:
        """Signs arbitrary byte data using ECDSA-SHA256."""
        signature = self.private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        return signature

    @staticmethod
    def verify(signature: bytes, message: bytes, public_key_bytes: bytes) -> bool:
        """Verifies an ECDSA-SHA256 signature against peer public key bytes."""
        try:
            peer_pubkey = serialization.load_der_public_key(public_key_bytes)
            if not isinstance(peer_pubkey, ec.EllipticCurvePublicKey):
                return False
            peer_pubkey.verify(
                signature,
                message,
                ec.ECDSA(hashes.SHA256())
            )
            return True
        except (InvalidSignature, Exception):
            return False


class CertificateAuthority:
    """
    Lightweight IoT Certificate Authority (Trust Anchor).
    Issues and verifies identity certificates for IoT Nodes and Gateway to defeat MITM.
    """

    def __init__(self, name: str = "Root-IoT-CA"):
        self.name = name
        self.ca_signer = ECDSASigner.generate()

    def get_ca_public_bytes(self) -> bytes:
        return self.ca_signer.get_public_bytes()

    def issue_certificate(self, device_id: str, public_key_bytes: bytes, validity_seconds: int = 86400) -> Dict[str, Any]:
        """
        Issues a signed JSON-formatted identity certificate.
        Cert = {
           'device_id': ...,
           'pubkey_hex': ...,
           'issued_at': ...,
           'expires_at': ...,
           'ca_name': ...,
           'signature_hex': ...
        }
        """
        now = time.time()
        payload = {
            "device_id": device_id,
            "pubkey_hex": public_key_bytes.hex(),
            "issued_at": now,
            "expires_at": now + validity_seconds,
            "ca_name": self.name
        }
        canonical_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        sig = self.ca_signer.sign(canonical_bytes)
        
        cert = dict(payload)
        cert["signature_hex"] = sig.hex()
        return cert

    def verify_certificate(self, cert: Dict[str, Any]) -> Tuple[bool, str]:
        """Verifies certificate validity and CA signature."""
        try:
            cert_copy = dict(cert)
            sig_hex = cert_copy.pop("signature_hex", None)
            if not sig_hex:
                return False, "Certificate is missing signature"
            
            sig = bytes.fromhex(sig_hex)
            canonical_bytes = json.dumps(cert_copy, sort_keys=True).encode("utf-8")
            
            if not ECDSASigner.verify(sig, canonical_bytes, self.get_ca_public_bytes()):
                return False, "Invalid CA signature on certificate"
            
            if time.time() > cert_copy["expires_at"]:
                return False, "Certificate has expired"
            
            return True, "Valid"
        except Exception as e:
            return False, f"Verification error: {str(e)}"

